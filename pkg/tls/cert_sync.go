package tls

import (
	"context"
	"log/slog"
	"time"

	"migadu/mizu/pkg/concurrency"
)

// CertSyncWorker manages periodic synchronization of certificates from local cache to S3.
type CertSyncWorker struct {
	fallbackCache    *FallbackCache
	syncInterval     time.Duration
	logger           *slog.Logger
	stopCh           chan struct{}
	doneCh           chan struct{}
	consecutiveFails int
}

func NewCertSyncWorker(fallbackCache *FallbackCache, syncInterval time.Duration, logger *slog.Logger) *CertSyncWorker {
	return &CertSyncWorker{
		fallbackCache: fallbackCache,
		syncInterval:  syncInterval,
		logger:        logger,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

func (w *CertSyncWorker) Start() {
	w.logger.Info("starting certificate sync worker", "interval", w.syncInterval)

	concurrency.SafeGo(w.logger, "cert-sync-worker", func() {
		defer close(w.doneCh)

		// One-time startup sync: push local certs to S3 if they're missing there.
		w.logger.Info("certificate sync worker: running startup sync from local cache to S3")
		w.runStartupSync()

		ticker := time.NewTicker(w.syncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				w.runSync()
			case <-w.stopCh:
				w.logger.Info("certificate sync worker stopped")
				return
			}
		}
	})
}

func (w *CertSyncWorker) runStartupSync() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := w.fallbackCache.SyncAllToS3(ctx); err != nil {
		w.logger.Warn("certificate sync worker: startup sync had errors", "error", err)
	} else {
		w.logger.Info("certificate sync worker: startup sync complete")
	}
}

func (w *CertSyncWorker) Stop(timeout time.Duration) {
	w.logger.Info("stopping certificate sync worker")
	close(w.stopCh)

	select {
	case <-w.doneCh:
		w.logger.Info("certificate sync worker stopped gracefully")
	case <-time.After(timeout):
		w.logger.Warn("certificate sync worker stop timed out")
	}
}

// runSync performs a single sync operation with escalating severity on
// consecutive failures so persistent S3 issues are impossible to miss.
// Only syncs when there are local-only certs to avoid downloading all certs
// from S3 on every tick.
func (w *CertSyncWorker) runSync() {
	if !w.fallbackCache.NeedsSync() {
		w.logger.Debug("certificate sync: no sync needed, skipping")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	w.logger.Debug("running certificate sync")
	if err := w.fallbackCache.SyncAllToS3(ctx); err != nil {
		w.consecutiveFails++

		switch {
		case w.consecutiveFails <= 3:
			w.logger.Error("certificate sync failed", "error", err,
				"consecutive_failures", w.consecutiveFails)
		default:
			w.logger.Error("PERSISTENT SYNC FAILURE: certificates are NOT being replicated to S3 — investigate S3 connectivity/credentials",
				"error", err,
				"consecutive_failures", w.consecutiveFails,
				"sync_interval", w.syncInterval)
		}
	} else {
		if w.consecutiveFails > 0 {
			w.logger.Info("certificate sync recovered after failures",
				"previous_consecutive_failures", w.consecutiveFails)
		}
		w.consecutiveFails = 0
	}
}

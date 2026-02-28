package tls

import (
	"context"
	"time"

	"migadu/mizu/pkg/concurrency"
)

// startCertificateSyncWorker starts a background worker that periodically syncs certificates
// from local fallback cache to S3. This ensures consistency after S3 outages.
// On startup, it performs a one-time sync to push any local-only certs to S3
// (e.g., after S3 was cleared or on first boot with existing local certs).
func (m *Manager) startCertificateSyncWorker(syncInterval time.Duration) {
	m.logger.Info("Starting certificate sync worker", "interval", syncInterval)

	concurrency.SafeGo(m.logger, "tls-cert-sync-worker", func() {
		// One-time startup sync: push local certs to S3 if they're missing there.
		// This covers the case where S3 was wiped or certs exist only locally.
		if fallbackCache, ok := m.autocertManager.Cache.(*FallbackCache); ok {
			m.logger.Info("Certificate sync worker: running startup sync from local cache to S3")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			if err := fallbackCache.SyncAllToS3(ctx); err != nil {
				m.logger.Warn("Certificate sync worker: startup sync had errors", "error", err)
			} else {
				m.logger.Info("Certificate sync worker: startup sync complete")
			}
			cancel()
		}

		ticker := time.NewTicker(syncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if fallbackCache, ok := m.autocertManager.Cache.(*FallbackCache); ok {
					// Only sync when there are local-only certs that need to be pushed to S3.
					// This avoids downloading all certs from S3 on every tick just to compare them.
					if !fallbackCache.NeedsSync() {
						m.logger.Debug("Certificate sync worker: no sync needed, skipping")
						continue
					}
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					if err := fallbackCache.SyncAllToS3(ctx); err != nil {
						m.logger.Debug("Certificate sync worker: some certificates failed to sync", "error", err)
					}
					cancel()
				}
			case <-m.stopCertSync:
				m.logger.Info("Certificate sync worker stopped")
				return
			}
		}
	})
}

// Shutdown gracefully stops the TLS manager and its background workers
func (m *Manager) Shutdown() {
	if m.stopCertSync != nil {
		close(m.stopCertSync)
	}
	m.logger.Info("TLS manager shutdown complete")
}

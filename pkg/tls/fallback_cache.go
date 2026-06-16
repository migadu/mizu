package tls

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"migadu/mizu/pkg/concurrency"

	"golang.org/x/crypto/acme/autocert"
)

// FallbackCache implements a two-tier cache system:
// - Primary: S3 (source of truth, shared across cluster)
// - Fallback: Local filesystem (fast cache, used when S3 unavailable)
//
// - Get(): Try local first (fast), fallback to S3, sync S3→local
// - Put(): Try S3 first (source of truth), fallback to local, schedule background sync
// - Periodic sync: Ensures S3 has all certificates from fallback cache
//
// S3 Circuit Breaker: If S3 operations fail, the cache stops trying S3 for
// a configurable interval (default 30s) to avoid repeated timeouts.
type FallbackCache struct {
	primary          autocert.Cache
	fallback         autocert.Cache
	fallbackDir      string
	logger           *slog.Logger
	mu               sync.RWMutex
	s3Mu             sync.RWMutex
	s3Available      bool
	needsSync        bool
	lastS3Check      time.Time
	checkInterval    time.Duration
	consecutiveFails int
}

// NewFallbackCache creates a new two-tier cache with S3 as primary.
// Returns S3-only behavior with a warning if fallback directory cannot be created.
func NewFallbackCache(localDir string, s3Cache *S3Cache, logger *slog.Logger) *FallbackCache {
	if err := os.MkdirAll(localDir, 0700); err != nil {
		logger.Warn("cannot create fallback directory - fallback cache disabled, using S3-only",
			"dir", localDir,
			"error", err)
		logger.Warn("certificates will only be stored in S3 - if S3 becomes unavailable, certificate operations will fail")
	}

	return &FallbackCache{
		primary:       s3Cache,
		fallback:      autocert.DirCache(localDir),
		fallbackDir:   localDir,
		logger:        logger,
		s3Available:   true,
		checkInterval: 30 * time.Second,
	}
}

func (f *FallbackCache) isS3Available() bool {
	f.s3Mu.RLock()
	defer f.s3Mu.RUnlock()

	if !f.s3Available {
		if time.Since(f.lastS3Check) < f.checkInterval {
			return false
		}
	}
	return true
}

// markS3Unavailable marks S3 as unavailable, records the time, and tracks
// consecutive failures. Escalates log severity when failures persist.
func (f *FallbackCache) markS3Unavailable() {
	f.s3Mu.Lock()
	defer f.s3Mu.Unlock()

	f.consecutiveFails++
	f.s3Available = false
	f.lastS3Check = time.Now()

	switch {
	case f.consecutiveFails == 1:
		f.logger.Warn("S3 certificate cache unavailable - operations will use local cache only",
			"retry_after", f.checkInterval,
			"consecutive_failures", f.consecutiveFails)
	case f.consecutiveFails <= 5:
		f.logger.Warn("S3 certificate cache still unavailable",
			"consecutive_failures", f.consecutiveFails,
			"retry_after", f.checkInterval)
	default:
		f.logger.Error("PERSISTENT S3 FAILURE: certificate cache has been unavailable for an extended period — certificates are only stored locally and NOT replicated",
			"consecutive_failures", f.consecutiveFails,
			"retry_after", f.checkInterval)
	}
}

func (f *FallbackCache) markS3Available() {
	f.s3Mu.Lock()
	defer f.s3Mu.Unlock()

	if !f.s3Available {
		f.logger.Info("S3 certificate cache restored - resuming S3 operations",
			"was_unavailable_for_failures", f.consecutiveFails)
	}
	f.s3Available = true
	f.consecutiveFails = 0
}

// Get retrieves a certificate, trying local cache first (fast), then S3 (slow).
// S3 operations have a 5-second timeout to prevent blocking TLS handshakes.
func (f *FallbackCache) Get(ctx context.Context, key string) ([]byte, error) {
	f.logger.Debug("FallbackCache: Get certificate (checking local cache first)", "name", key)

	data, err := f.fallback.Get(ctx, key)
	if err == nil {
		f.logger.Debug("FallbackCache: certificate found in local cache", "name", key)
		return data, nil
	}

	if err != autocert.ErrCacheMiss {
		f.logger.Warn("FallbackCache: error reading local cache (will try S3)", "name", key, "error", err)
	} else {
		f.logger.Debug("FallbackCache: certificate not in local cache (checking S3)", "name", key)
	}

	if !f.isS3Available() {
		f.logger.Debug("FallbackCache: S3 unavailable (circuit breaker), certificate not found", "name", key)
		return nil, autocert.ErrCacheMiss
	}

	f.logger.Debug("FallbackCache: fetching certificate from S3", "name", key)

	s3Ctx, s3Cancel := context.WithTimeout(ctx, 5*time.Second)
	defer s3Cancel()

	data, err = f.primary.Get(s3Ctx, key)
	if err == nil {
		f.logger.Info("FallbackCache: certificate found in S3 - syncing to local cache", "name", key)
		f.markS3Available()

		concurrency.SafeGo(f.logger, "tls-cert-sync-to-local", func() {
			if putErr := f.fallback.Put(context.Background(), key, data); putErr != nil {
				f.logger.Warn("FallbackCache: failed to sync certificate to local cache", "name", key, "error", putErr)
			} else {
				f.logger.Debug("FallbackCache: certificate synced to local cache", "name", key)
			}
		})

		return data, nil
	}

	if err == autocert.ErrCacheMiss {
		f.logger.Debug("FallbackCache: certificate not found in S3 (cache miss)", "name", key)
		return nil, autocert.ErrCacheMiss
	}

	f.logger.Warn("FallbackCache: S3 Get failed (marking S3 unavailable)", "name", key, "error", err)
	f.markS3Unavailable()
	return nil, err
}

// Put stores a certificate, trying S3 first (source of truth), then falling back to local cache.
func (f *FallbackCache) Put(ctx context.Context, key string, data []byte) error {
	var s3Err error

	if f.isS3Available() {
		s3Err = f.primary.Put(ctx, key, data)
		if s3Err == nil {
			f.markS3Available()
			if fallbackErr := f.fallback.Put(ctx, key, data); fallbackErr != nil {
				f.logger.Warn("failed to sync certificate to fallback cache", "name", key, "error", fallbackErr)
			}
			return nil
		}

		f.logger.Warn("S3 Put failed - using fallback cache", "name", key, "error", s3Err)
		f.markS3Unavailable()
	}

	f.mu.Lock()
	f.needsSync = true
	f.mu.Unlock()

	f.logger.Info("storing certificate in fallback cache (needs S3 sync)", "name", key)
	if err := f.fallback.Put(ctx, key, data); err != nil {
		if s3Err != nil {
			return fmt.Errorf("both S3 and fallback cache failed - S3 error: %w, fallback error: %v", s3Err, err)
		}
		return err
	}

	concurrency.SafeGo(f.logger, "tls-cert-sync-to-s3", func() {
		f.syncToS3(key, data)
	})

	return nil
}

func (f *FallbackCache) syncToS3(key string, data []byte) {
	time.Sleep(f.checkInterval)

	if !f.isS3Available() {
		f.logger.Debug("background S3 sync skipped (circuit breaker)", "name", key)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := f.primary.Put(ctx, key, data); err != nil {
		f.logger.Warn("background S3 sync failed - certificate only stored locally (will retry on periodic sync)", "name", key, "error", err)
		f.markS3Unavailable()
	} else {
		f.logger.Info("certificate synced from fallback cache to S3 (background)", "name", key)
		f.markS3Available()
	}
}

func (f *FallbackCache) Delete(ctx context.Context, key string) error {
	var s3Err error

	if f.isS3Available() {
		s3Err = f.primary.Delete(ctx, key)
		if s3Err == nil {
			f.markS3Available()
		} else {
			f.logger.Warn("S3 Delete failed", "name", key, "error", s3Err)
			f.markS3Unavailable()
		}
	}

	fallbackErr := f.fallback.Delete(ctx, key)

	if s3Err != nil && fallbackErr != nil {
		return fmt.Errorf("both S3 and fallback cache delete failed - S3 error: %w, fallback error: %v", s3Err, fallbackErr)
	}

	if s3Err != nil {
		f.logger.Warn("certificate deleted from local cache but S3 delete failed — S3 may retain stale certificate",
			"name", key, "s3_error", s3Err)
	}

	return nil
}

// NeedsSync returns true if there are certificates in the local fallback cache
// that haven't been synced to S3 yet (due to a previous S3 outage).
func (f *FallbackCache) NeedsSync() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.needsSync
}

// SyncAllToS3 attempts to sync all certificates from fallback cache to S3.
// Only syncs certificates that are missing or different in S3.
func (f *FallbackCache) SyncAllToS3(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	entries, err := os.ReadDir(f.fallbackDir)
	if err != nil {
		if os.IsNotExist(err) {
			f.logger.Debug("fallback cache directory does not exist yet", "dir", f.fallbackDir)
			return nil
		}
		return fmt.Errorf("failed to read fallback directory: %w", err)
	}

	synced := 0
	failed := 0
	skipped := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		path := filepath.Join(f.fallbackDir, name)

		data, err := os.ReadFile(path)
		if err != nil {
			f.logger.Warn("failed to read fallback certificate", "name", name, "error", err)
			failed++
			continue
		}

		s3Data, err := f.primary.Get(ctx, name)
		if err == nil {
			if len(s3Data) == len(data) && bytes.Equal(s3Data, data) {
				skipped++
				continue
			}
			f.logger.Debug("certificate differs in S3, syncing", "name", name)
		} else if err != autocert.ErrCacheMiss {
			// Transient S3 error - skip. Do NOT re-upload: we can't confirm cert
			// is missing vs S3 being unreachable. Re-uploading on transient errors
			// causes massive S3 object accumulation.
			f.logger.Warn("transient S3 error checking certificate - skipping sync", "name", name, "error", err)
			skipped++
			continue
		}

		if err := f.primary.Put(ctx, name, data); err != nil {
			f.logger.Warn("failed to sync certificate to S3", "name", name, "error", err)
			failed++
			continue
		}

		synced++
		f.logger.Debug("synced certificate to S3", "name", name)
	}

	if synced > 0 {
		f.logger.Info("synced certificates from fallback cache to S3", "synced", synced, "skipped", skipped, "failed", failed)
	}

	if failed > 0 {
		return fmt.Errorf("failed to sync %d certificates to S3", failed)
	}

	f.needsSync = false

	return nil
}

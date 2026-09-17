package tls

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// FallbackCache implements a two-tier cache system:
// - Primary: S3 (source of truth, shared across cluster)
// - Fallback: Local filesystem (used only while S3 is unreachable)
//
// - Get(): S3 first, written through to local; local only if S3 cannot be reached
// - Put(): S3 first; if S3 is down, store locally and remember the key as pending
// - Periodic sync: pushes pending keys to S3 once it is reachable again
//
// S3 must be read first. Every node keeps a local copy of every certificate it
// has served, so a local-first read never notices a certificate the leader has
// since renewed into S3: the node keeps serving its stale copy until it expires
// and concludes it has to renew the certificate itself.
//
// S3 Circuit Breaker: If S3 operations fail, the cache stops trying S3 for
// a configurable interval (default 30s) to avoid repeated timeouts.
type FallbackCache struct {
	primary          autocert.Cache
	fallback         autocert.Cache
	logger           *slog.Logger
	putMu            sync.Mutex          // serializes writers so a pending sync cannot overwrite a newer Put
	mu               sync.Mutex          // guards pending
	pending          map[string]struct{} // keys stored locally that S3 has not received yet
	s3Mu             sync.RWMutex
	s3Available      bool
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
		logger:        logger,
		pending:       make(map[string]struct{}),
		s3Available:   true,
		checkInterval: 30 * time.Second,
	}
}

// isChallengeKey reports whether key holds an ACME challenge response (autocert's
// "<domain>+token" and "<token>+http-01" entries) rather than a certificate or
// the account key. A challenge response exists to be fetched by the other nodes
// while the CA validates, which only S3 can do, so it never touches the local
// directory — where a leftover from an earlier order would outlive its 24h
// validity and be served in place of the current one.
func isChallengeKey(key string) bool {
	return strings.HasSuffix(key, "+token") || strings.HasSuffix(key, "+http-01")
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

// Get retrieves a certificate from S3, falling back to the local cache only when
// S3 cannot be reached. S3 operations have a 5-second timeout to prevent blocking
// TLS handshakes.
func (f *FallbackCache) Get(ctx context.Context, key string) ([]byte, error) {
	// A pending key was written while S3 was down: the local copy is the newer one.
	if f.isPending(key) {
		f.logger.Debug("FallbackCache: certificate awaiting S3 sync - using local cache", "name", key)
		return f.fallback.Get(ctx, key)
	}

	if !f.isS3Available() {
		f.logger.Debug("FallbackCache: S3 unavailable (circuit breaker) - using local cache", "name", key)
		return f.fallback.Get(ctx, key)
	}

	s3Ctx, s3Cancel := context.WithTimeout(ctx, 5*time.Second)
	defer s3Cancel()

	data, err := f.primary.Get(s3Ctx, key)
	if err == nil {
		f.markS3Available()
		if !isChallengeKey(key) {
			if putErr := f.fallback.Put(ctx, key, data); putErr != nil {
				f.logger.Warn("FallbackCache: failed to sync certificate to local cache", "name", key, "error", putErr)
			}
		}
		return data, nil
	}

	// S3 answered and the key is not there. A local copy is a leftover (deleted
	// by an admin, or a spent challenge response) and must not be served.
	if err == autocert.ErrCacheMiss {
		f.markS3Available()
		f.logger.Debug("FallbackCache: certificate not found in S3 (cache miss)", "name", key)
		return nil, autocert.ErrCacheMiss
	}

	f.logger.Warn("FallbackCache: S3 Get failed (marking S3 unavailable) - using local cache", "name", key, "error", err)
	f.markS3Unavailable()
	return f.fallback.Get(ctx, key)
}

// Put stores a certificate, trying S3 first (source of truth), then falling back to local cache.
func (f *FallbackCache) Put(ctx context.Context, key string, data []byte) error {
	f.putMu.Lock()
	defer f.putMu.Unlock()

	var s3Err error

	if f.isS3Available() {
		s3Err = f.primary.Put(ctx, key, data)
		if s3Err == nil {
			f.markS3Available()
			f.setPending(key, false)
			if !isChallengeKey(key) {
				if fallbackErr := f.fallback.Put(ctx, key, data); fallbackErr != nil {
					f.logger.Warn("failed to sync certificate to fallback cache", "name", key, "error", fallbackErr)
				}
			}
			return nil
		}

		f.logger.Warn("S3 Put failed - using fallback cache", "name", key, "error", s3Err)
		f.markS3Unavailable()
	}

	if isChallengeKey(key) {
		return fmt.Errorf("S3 unavailable - challenge response %s not shared with the cluster (S3 error: %v)", key, s3Err)
	}

	f.logger.Info("storing certificate in fallback cache (needs S3 sync)", "name", key)
	if err := f.fallback.Put(ctx, key, data); err != nil {
		if s3Err != nil {
			return fmt.Errorf("both S3 and fallback cache failed - S3 error: %w, fallback error: %v", s3Err, err)
		}
		return err
	}
	f.setPending(key, true)

	return nil
}

func (f *FallbackCache) Delete(ctx context.Context, key string) error {
	f.putMu.Lock()
	defer f.putMu.Unlock()

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

	f.setPending(key, false)
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

func (f *FallbackCache) isPending(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.pending[key]
	return ok
}

func (f *FallbackCache) setPending(key string, pending bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if pending {
		f.pending[key] = struct{}{}
	} else {
		delete(f.pending, key)
	}
}

// NeedsSync returns true if there are certificates in the local fallback cache
// that haven't been synced to S3 yet (due to a previous S3 outage).
func (f *FallbackCache) NeedsSync() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pending) > 0
}

// SyncPendingToS3 pushes the certificates this process stored locally during an
// S3 outage. It deliberately does not sweep the local directory: a local file
// says nothing about being newer than S3, and uploading whatever differs lets a
// restarted node overwrite a renewed certificate with its stale copy.
func (f *FallbackCache) SyncPendingToS3(ctx context.Context) error {
	f.mu.Lock()
	keys := make([]string, 0, len(f.pending))
	for key := range f.pending {
		keys = append(keys, key)
	}
	f.mu.Unlock()

	synced := 0
	failed := 0

	for _, key := range keys {
		if err := f.syncKeyToS3(ctx, key); err != nil {
			f.logger.Warn("failed to sync certificate to S3", "name", key, "error", err)
			failed++
			continue
		}
		synced++
	}

	if synced > 0 {
		f.logger.Info("synced certificates from fallback cache to S3", "synced", synced, "failed", failed)
	}

	if failed > 0 {
		return fmt.Errorf("failed to sync %d certificates to S3", failed)
	}

	return nil
}

func (f *FallbackCache) syncKeyToS3(ctx context.Context, key string) error {
	f.putMu.Lock()
	defer f.putMu.Unlock()

	// A Put or Delete that ran since the snapshot already settled this key.
	if !f.isPending(key) {
		return nil
	}

	data, err := f.fallback.Get(ctx, key)
	if err == autocert.ErrCacheMiss {
		f.setPending(key, false)
		return nil
	}
	if err != nil {
		return err
	}

	if err := f.primary.Put(ctx, key, data); err != nil {
		f.markS3Unavailable()
		return err
	}

	f.markS3Available()
	f.setPending(key, false)
	return nil
}

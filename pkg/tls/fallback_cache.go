package tls

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
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
	pendingDir       string              // holds one marker file per pending key
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

	pendingDir := filepath.Join(localDir, pendingSubdir)
	if err := os.MkdirAll(pendingDir, 0700); err != nil {
		logger.Warn("cannot create the pending-sync directory - a certificate stored during an S3 outage will be overwritten from S3 on restart",
			"dir", pendingDir, "error", err)
	}

	f := &FallbackCache{
		primary:       s3Cache,
		fallback:      autocert.DirCache(localDir),
		logger:        logger,
		pending:       make(map[string]struct{}),
		pendingDir:    pendingDir,
		s3Available:   true,
		checkInterval: 30 * time.Second,
	}
	f.loadPending()
	return f
}

// pendingSubdir holds the markers naming keys this node stored locally but has
// not got into S3 yet. It lives inside the cache directory so it survives a
// restart: without it the node forgets that its local copy is the newer one and
// the next read puts S3's older certificate back over it — and over the private
// key that goes with it, which nothing can then recover.
const pendingSubdir = ".pending"

func (f *FallbackCache) markerPath(key string) string {
	// Escaped so a key can never reach outside the directory.
	return filepath.Join(f.pendingDir, url.PathEscape(key))
}

func (f *FallbackCache) loadPending() {
	entries, err := os.ReadDir(f.pendingDir)
	if err != nil {
		if !os.IsNotExist(err) {
			f.logger.Warn("cannot read the pending-sync directory", "dir", f.pendingDir, "error", err)
		}
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, entry := range entries {
		key, err := url.PathUnescape(entry.Name())
		if err != nil {
			continue
		}
		f.pending[key] = struct{}{}
	}

	if len(f.pending) > 0 {
		f.logger.Info("certificates stored locally still awaiting S3 sync", "count", len(f.pending))
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

// How long to wait for S3 on a read. autocert holds one global mutex across
// Cache.Get, so every concurrent handshake on the node queues behind it.
//
// The budget is what the wait can win. With no local copy there is nothing to
// serve without S3, so it is worth waiting out a slow bucket. With one in hand
// the wait buys only the chance that S3 has something fresher, which the renewal
// read and the hourly maintenance pass would pick up anyway.
const (
	s3GetTimeout          = 5 * time.Second
	s3GetTimeoutWithLocal = time.Second
)

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

// Get retrieves a certificate from S3, falling back to the local copy only when
// S3 cannot be consulted.
//
// The three answers S3 can give are kept apart. "Here it is" and "I do not have
// it" are authoritative. "I could not be reached" is not, and must never reach
// autocert as ErrCacheMiss — see ErrStorageUnavailable.
func (f *FallbackCache) Get(ctx context.Context, key string) ([]byte, error) {
	// A pending key was written while S3 was down: the local copy is the newer one.
	if f.isPending(key) {
		f.logger.Debug("FallbackCache: certificate awaiting S3 sync - using local cache", "name", key)
		return f.fallback.Get(ctx, key)
	}

	if !f.isS3Available() {
		f.logger.Debug("FallbackCache: S3 not consulted (circuit breaker open)", "name", key)
		return f.localAfterS3Failure(ctx, key, errors.New("circuit breaker open"))
	}

	// Read the local copy first to decide how long S3 is worth waiting for. It is
	// only ever the fallback: an answer from S3 still wins, which is what keeps a
	// node from serving a stale certificate the leader has already renewed.
	local, localErr := f.fallback.Get(ctx, key)
	timeout := s3GetTimeout
	if localErr == nil {
		timeout = s3GetTimeoutWithLocal
	}

	s3Ctx, s3Cancel := context.WithTimeout(ctx, timeout)
	defer s3Cancel()

	data, err := f.primary.Get(s3Ctx, key)
	switch {
	case err == nil:
		f.markS3Available()
		f.writeThrough(ctx, key, data)
		return data, nil

	case err == autocert.ErrCacheMiss:
		f.markS3Available()
		return f.localSeedingS3(ctx, key)

	case localErr == nil && errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
		f.logger.Warn("FallbackCache: S3 too slow - serving the local copy",
			"name", key, "waited", timeout)
		f.markS3Unavailable()
		return local, nil

	case callerGaveUp(ctx, err):
		// autocert hands Cache.Get the HTTP request's context when it serves an
		// http-01 challenge, so a client that disconnects mid-request produces
		// this. Counting it as an outage would let anyone open the breaker.
		f.logger.Debug("FallbackCache: S3 Get abandoned by the caller", "name", key, "error", err)
		return nil, err

	default:
		f.logger.Warn("FallbackCache: S3 Get failed (marking S3 unavailable) - trying local cache",
			"name", key, "error", err)
		f.markS3Unavailable()
		return f.localAfterS3Failure(ctx, key, err)
	}
}

// callerGaveUp reports whether an S3 error is the caller's own cancellation
// rather than a fault of the store. s3GetTimeout firing is ours, and does count
// as an outage; only a context the caller had already given up on does not.
func callerGaveUp(ctx context.Context, err error) bool {
	return ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
}

// localAfterS3Failure answers from the local copy when S3 could not be
// consulted, and reports ErrStorageUnavailable when there is none. It never
// reports ErrCacheMiss: that would tell autocert the certificate does not exist.
func (f *FallbackCache) localAfterS3Failure(ctx context.Context, key string, cause error) ([]byte, error) {
	data, err := f.fallback.Get(ctx, key)
	if err == nil {
		f.logger.Debug("FallbackCache: serving local copy while S3 is unavailable", "name", key)
		return data, nil
	}
	if err != autocert.ErrCacheMiss {
		return nil, fmt.Errorf("%w for %s: %v (local cache: %v)", ErrStorageUnavailable, key, cause, err)
	}
	return nil, fmt.Errorf("%w for %s: %v", ErrStorageUnavailable, key, cause)
}

// localSeedingS3 answers an authoritative "S3 does not have it" from the local
// copy, and queues that copy for upload.
//
// S3 losing an entry it once had - an admin deleting it, a lifecycle rule, a
// changed prefix - otherwise takes every restarted node down for the domain
// until the certificate's own renewal comes round, because the leader keeps
// serving from memory and never learns it must re-issue. The local copy cannot
// be hiding a newer one here: S3 has nothing to hide.
//
// Challenge responses are exempt. One that S3 does not have is spent, and
// answering from a leftover hands the CA the token of an earlier order.
func (f *FallbackCache) localSeedingS3(ctx context.Context, key string) ([]byte, error) {
	if isChallengeKey(key) {
		f.logger.Debug("FallbackCache: challenge response not in S3 (cache miss)", "name", key)
		return nil, autocert.ErrCacheMiss
	}

	data, err := f.fallback.Get(ctx, key)
	if err != nil {
		f.logger.Debug("FallbackCache: certificate not found in S3 or locally (cache miss)", "name", key)
		return nil, autocert.ErrCacheMiss
	}

	f.logger.Warn("FallbackCache: certificate missing from S3 - serving the local copy and restoring it",
		"name", key)
	f.setPending(key, true)
	return data, nil
}

// writeThrough keeps the local copy in step with what S3 served, so the node can
// still answer handshakes if S3 becomes unreachable.
func (f *FallbackCache) writeThrough(ctx context.Context, key string, data []byte) {
	if isChallengeKey(key) {
		return
	}

	f.putMu.Lock()
	defer f.putMu.Unlock()

	// A Put that landed while the S3 read was in flight is the newer copy.
	if f.isPending(key) {
		return
	}
	if err := f.fallback.Put(ctx, key, data); err != nil {
		f.logger.Warn("FallbackCache: failed to sync certificate to local cache", "name", key, "error", err)
	}
}

// Put stores a certificate, trying S3 first (source of truth), then falling back to local cache.
func (f *FallbackCache) Put(ctx context.Context, key string, data []byte) error {
	f.putMu.Lock()
	defer f.putMu.Unlock()

	var s3Err error

	// A challenge response reaches the validating node only through S3, so it is
	// attempted even when the breaker is open: a refusal here fails the
	// validation outright, and the breaker may well be stale.
	if f.isS3Available() || isChallengeKey(key) {
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
		if err := os.WriteFile(f.markerPath(key), nil, 0600); err != nil {
			f.logger.Warn("cannot record that a certificate awaits S3 sync - a restart would overwrite it from S3",
				"name", key, "error", err)
		}
		return
	}

	delete(f.pending, key)
	if err := os.Remove(f.markerPath(key)); err != nil && !os.IsNotExist(err) {
		f.logger.Warn("cannot clear the pending-sync marker", "name", key, "error", err)
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

	if f.supersededInS3(ctx, key, data) {
		f.logger.Info("dropping a pending upload: S3 already holds a newer certificate", "name", key)
		f.setPending(key, false)
		return nil
	}

	if err := f.primary.Put(ctx, key, data); err != nil {
		f.markS3Unavailable()
		return err
	}

	f.markS3Available()
	f.setPending(key, false)
	return nil
}

// supersededInS3 reports whether S3 holds a strictly newer certificate under the
// same key, which a pending upload must not overwrite: a marker can outlive its
// certificate (a crash between the upload and clearing it), and uploading a
// stale copy over a renewal is the overwrite this cache exists to prevent.
//
// Anything that is not a parsable certificate - the ACME account key above all -
// is never treated as superseded, so it still syncs.
func (f *FallbackCache) supersededInS3(ctx context.Context, key string, local []byte) bool {
	localExpiry, err := entryNotAfter(local)
	if err != nil {
		return false
	}

	remote, err := f.primary.Get(ctx, key)
	if err != nil {
		return false
	}

	remoteExpiry, err := entryNotAfter(remote)
	if err != nil {
		return false
	}

	return remoteExpiry.After(localExpiry)
}

// entryNotAfter returns the expiry of the first certificate in a cache entry.
func entryNotAfter(data []byte) (time.Time, error) {
	for rest := data; len(rest) > 0; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		return leaf.NotAfter, nil
	}
	return time.Time{}, errors.New("cache entry holds no certificate")
}

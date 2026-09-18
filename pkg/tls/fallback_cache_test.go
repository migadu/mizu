package tls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"golang.org/x/crypto/acme/autocert"
)

// fakeS3 is an in-memory S3API whose availability can be toggled.
type fakeS3 struct {
	mu       sync.Mutex
	objects  map[string][]byte
	down     bool
	delay    time.Duration // how long a read takes before answering
	putDelay time.Duration // how long a write takes before completing
}

func newFakeS3() *fakeS3 { return &fakeS3{objects: make(map[string][]byte)} }

func (f *fakeS3) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

func (f *fakeS3) object(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects[key]
	return data, ok
}

func (f *fakeS3) GetObject(ctx context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	delay := f.delay
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// The AWS SDK surfaces the caller's cancellation the same way.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errors.New("s3 unreachable")
	}
	data, ok := f.objects[*in.Key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
}

func (f *fakeS3) PutObject(ctx context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	delay := f.putDelay
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errors.New("s3 unreachable")
	}
	data, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	f.objects[*in.Key] = data
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errors.New("s3 unreachable")
	}
	delete(f.objects, *in.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestFallbackCache returns a cache over a fake S3 and a temp dir, with the
// circuit breaker's cool-down disabled so tests can flip S3 back on instantly.
func newTestFallbackCache(t *testing.T) (*FallbackCache, *fakeS3, string) {
	t.Helper()
	s3fake := newFakeS3()
	dir := t.TempDir()
	logger := discardLogger()
	cache := NewFallbackCache(dir, &S3Cache{S3Client: s3fake, Bucket: "b", Prefix: "certs/", Logger: logger}, logger)
	cache.checkInterval = 0
	return cache, s3fake, dir
}

func writeLocal(t *testing.T, dir, key, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, key), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func readLocal(t *testing.T, dir, key string) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, key))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data), true
}

// A node's local copy must not hide a certificate another node renewed into S3.
func TestFallbackCacheGetPrefersS3OverStaleLocal(t *testing.T) {
	cache, s3fake, dir := newTestFallbackCache(t)
	writeLocal(t, dir, "mx.example.com", "stale")
	s3fake.objects["certs/mx.example.com"] = []byte("renewed")

	got, err := cache.Get(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "renewed" {
		t.Errorf("Get = %q, want the S3 copy %q", got, "renewed")
	}
	if local, _ := readLocal(t, dir, "mx.example.com"); local != "renewed" {
		t.Errorf("local copy = %q, want it refreshed to %q", local, "renewed")
	}
}

// A challenge response missing from S3 is spent: answering one from a local
// leftover would hand the CA the token of an earlier order.
func TestFallbackCacheGetS3MissIgnoresLocalChallenge(t *testing.T) {
	cache, _, dir := newTestFallbackCache(t)
	writeLocal(t, dir, "mx.example.com+token", "spent")

	if _, err := cache.Get(context.Background(), "mx.example.com+token"); err != autocert.ErrCacheMiss {
		t.Errorf("Get error = %v, want ErrCacheMiss", err)
	}
}

// F7: a certificate missing from S3 but present locally is served, and put back
// into S3. Ignoring the local copy leaves a restarted node with no certificate
// at all - for up to sixty days, since the leader goes on serving from memory
// and so never notices that it has to re-issue.
func TestFallbackCacheGetSeedsS3FromLocalCopy(t *testing.T) {
	cache, s3fake, dir := newTestFallbackCache(t)
	writeLocal(t, dir, "mx.example.com", "held-locally")

	got, err := cache.Get(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "held-locally" {
		t.Errorf("Get = %q, want the local copy", got)
	}

	if !cache.NeedsSync() {
		t.Fatal("the local-only certificate was not queued for S3")
	}
	if err := cache.SyncPendingToS3(context.Background()); err != nil {
		t.Fatalf("SyncPendingToS3: %v", err)
	}
	if data, ok := s3fake.object("certs/mx.example.com"); !ok || string(data) != "held-locally" {
		t.Errorf("S3 copy after sync = %q (present=%v), want it re-seeded", data, ok)
	}
}

func TestFallbackCacheGetUsesLocalWhenS3Down(t *testing.T) {
	cache, s3fake, dir := newTestFallbackCache(t)
	writeLocal(t, dir, "mx.example.com", "local")
	s3fake.setDown(true)

	got, err := cache.Get(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "local" {
		t.Errorf("Get = %q, want the local copy", got)
	}
}

// Challenge responses are shared through S3 only. A copy left in the local dir
// outlives its validity and used to shadow the token of the next order.
func TestFallbackCacheChallengeKeysStayOutOfLocalDir(t *testing.T) {
	cache, s3fake, dir := newTestFallbackCache(t)
	ctx := context.Background()

	for _, key := range []string{"mx.example.com+token", "abc123+http-01"} {
		if err := cache.Put(ctx, key, []byte("challenge")); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
		if _, err := cache.Get(ctx, key); err != nil {
			t.Fatalf("Get %s: %v", key, err)
		}
		if _, ok := s3fake.object("certs/" + key); !ok {
			t.Errorf("%s missing from S3", key)
		}
		if _, ok := readLocal(t, dir, key); ok {
			t.Errorf("%s was written to the local dir", key)
		}
	}

	// A stale local token never wins over the one in S3.
	writeLocal(t, dir, "mx.example.com+token", "stale")
	got, err := cache.Get(ctx, "mx.example.com+token")
	if err != nil || string(got) != "challenge" {
		t.Errorf("Get = %q, %v; want the S3 token", got, err)
	}

	s3fake.setDown(true)
	if err := cache.Put(ctx, "mx.example.com+token", []byte("x")); err == nil {
		t.Error("Put of a challenge key succeeded while S3 was down; it cannot be shared")
	}
}

func TestFallbackCacheSyncsPendingKeysAfterOutage(t *testing.T) {
	cache, s3fake, _ := newTestFallbackCache(t)
	ctx := context.Background()
	s3fake.objects["certs/mx.example.com"] = []byte("old")

	s3fake.setDown(true)
	if err := cache.Put(ctx, "mx.example.com", []byte("new")); err != nil {
		t.Fatalf("Put during outage: %v", err)
	}
	if !cache.NeedsSync() {
		t.Fatal("NeedsSync = false after a local-only Put")
	}

	// S3 is back but still holds the old copy: the pending local one is newer.
	s3fake.setDown(false)
	got, err := cache.Get(ctx, "mx.example.com")
	if err != nil || string(got) != "new" {
		t.Errorf("Get before sync = %q, %v; want the pending local copy", got, err)
	}

	if err := cache.SyncPendingToS3(ctx); err != nil {
		t.Fatalf("SyncPendingToS3: %v", err)
	}
	if data, _ := s3fake.object("certs/mx.example.com"); string(data) != "new" {
		t.Errorf("S3 copy after sync = %q, want %q", data, "new")
	}
	if cache.NeedsSync() {
		t.Error("NeedsSync = true after a successful sync")
	}
}

// Regression: the sync used to upload every local file that differed from S3,
// so restarting a node overwrote renewed certificates with its stale copies.
func TestFallbackCacheSyncLeavesUnrelatedLocalFilesAlone(t *testing.T) {
	cache, s3fake, dir := newTestFallbackCache(t)
	writeLocal(t, dir, "mx.example.com", "stale")
	writeLocal(t, dir, "mx.example.com+token", "spent")
	s3fake.objects["certs/mx.example.com"] = []byte("renewed")

	if err := cache.SyncPendingToS3(context.Background()); err != nil {
		t.Fatalf("SyncPendingToS3: %v", err)
	}
	if data, _ := s3fake.object("certs/mx.example.com"); string(data) != "renewed" {
		t.Errorf("S3 copy = %q, want it untouched (%q)", data, "renewed")
	}
	if _, ok := s3fake.object("certs/mx.example.com+token"); ok {
		t.Error("a spent local token was uploaded to S3")
	}
}

// F1: an unreachable S3 must never look like "no such certificate". autocert
// orders a new certificate on ErrCacheMiss and propagates any other error, so
// reporting a miss during an outage makes the leader order duplicates for every
// certificate it does not happen to hold locally.
func TestFallbackCacheGetDoesNotReportMissWhenS3IsUnreachable(t *testing.T) {
	cache, s3fake, _ := newTestFallbackCache(t)
	s3fake.setDown(true)

	_, err := cache.Get(context.Background(), "mx.example.com")
	if err == nil {
		t.Fatal("Get succeeded with S3 down and no local copy")
	}
	if err == autocert.ErrCacheMiss {
		t.Error("Get reported ErrCacheMiss while S3 was unreachable; autocert will order a duplicate")
	}
}

// The same applies once the circuit breaker has opened: it means "S3 not asked",
// never "S3 has nothing".
func TestFallbackCacheGetDoesNotReportMissWhileBreakerIsOpen(t *testing.T) {
	cache, s3fake, _ := newTestFallbackCache(t)
	cache.checkInterval = time.Minute // keep the breaker open once tripped
	s3fake.setDown(true)

	if _, err := cache.Get(context.Background(), "mx.example.com"); err == nil {
		t.Fatal("setup: expected the first Get to fail and trip the breaker")
	}

	_, err := cache.Get(context.Background(), "other.example.com")
	if err == autocert.ErrCacheMiss {
		t.Error("Get reported ErrCacheMiss while the breaker was open; autocert will order a duplicate")
	}
}

// restartCache builds a second cache over the same directory and S3, as a
// process restart would.
func restartCache(t *testing.T, dir string, s3fake *fakeS3) *FallbackCache {
	t.Helper()
	logger := discardLogger()
	cache := NewFallbackCache(dir, &S3Cache{S3Client: s3fake, Bucket: "b", Prefix: "certs/", Logger: logger}, logger)
	cache.checkInterval = 0
	return cache
}

// F4: a certificate stored locally during an S3 outage is the only copy of that
// key pair. If the record of it being unsynced does not survive a restart, the
// first read puts S3's older copy back over it and the renewal the operator was
// told had succeeded is silently undone - unrecoverably, since the key is lost.
func TestFallbackCachePendingSurvivesRestart(t *testing.T) {
	cache, s3fake, dir := newTestFallbackCache(t)
	ctx := context.Background()
	s3fake.objects["certs/mx.example.com"] = []byte("old")

	s3fake.setDown(true)
	if err := cache.Put(ctx, "mx.example.com", []byte("new")); err != nil {
		t.Fatalf("Put during outage: %v", err)
	}
	s3fake.setDown(false)

	restarted := restartCache(t, dir, s3fake)
	if !restarted.NeedsSync() {
		t.Error("the unsynced certificate was forgotten across the restart")
	}

	got, err := restarted.Get(ctx, "mx.example.com")
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("Get after restart = %q, want the locally stored %q", got, "new")
	}
	if local, _ := readLocal(t, dir, "mx.example.com"); local != "new" {
		t.Errorf("local copy after restart = %q, want it intact", local)
	}
}

// A pending marker that outlived its certificate must not push a stale copy over
// a newer one in S3 - the overwrite this PR set out to stop.
func TestFallbackCacheSyncNeverOverwritesNewerS3Certificate(t *testing.T) {
	cache, s3fake, dir := newTestFallbackCache(t)
	ctx := context.Background()

	local := cacheEntry(t, "mx.example.com", false, time.Now().Add(10*24*time.Hour))
	renewed := cacheEntry(t, "mx.example.com", false, time.Now().Add(80*24*time.Hour))

	s3fake.setDown(true)
	if err := cache.Put(ctx, "mx.example.com", local); err != nil {
		t.Fatalf("Put during outage: %v", err)
	}
	s3fake.setDown(false)

	// The leader renewed the certificate while this node was cut off.
	s3fake.objects["certs/mx.example.com"] = renewed

	if err := cache.SyncPendingToS3(ctx); err != nil {
		t.Fatalf("SyncPendingToS3: %v", err)
	}

	if data, _ := s3fake.object("certs/mx.example.com"); !bytes.Equal(data, renewed) {
		t.Error("the stale local copy overwrote the renewed certificate in S3")
	}
	if cache.NeedsSync() {
		t.Error("the superseded key is still queued for upload")
	}
	if _ = dir; cache.isPending("mx.example.com") {
		t.Error("the superseded key is still marked pending")
	}
}

// F5: autocert passes the HTTP request's context to Cache.Get when serving an
// http-01 challenge, so a client that disconnects mid-request makes S3 return
// "context canceled". Counting that as an outage lets anyone on the network open
// the circuit breaker at will.
func TestFallbackCacheCallerCancellationDoesNotTripBreaker(t *testing.T) {
	cache, _, _ := newTestFallbackCache(t)
	cache.checkInterval = time.Minute

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := cache.Get(ctx, "mx.example.com"); err == nil {
		t.Fatal("Get succeeded with a cancelled context")
	}
	if !cache.isS3Available() {
		t.Error("a cancelled caller context opened the S3 circuit breaker")
	}
}

// A challenge response is the one thing the other nodes can only get from S3, so
// it must be attempted even while the breaker is open. Refusing it outright
// fails the validation for every key type, spending the CA's hourly allowance.
func TestFallbackCacheChallengePutIgnoresOpenBreaker(t *testing.T) {
	cache, s3fake, _ := newTestFallbackCache(t)
	cache.checkInterval = time.Minute
	ctx := context.Background()

	s3fake.setDown(true)
	if _, err := cache.Get(ctx, "mx.example.com"); err == nil {
		t.Fatal("setup: expected the first Get to trip the breaker")
	}
	s3fake.setDown(false)

	if err := cache.Put(ctx, "mx.example.com+token", []byte("token")); err != nil {
		t.Fatalf("challenge Put refused while the breaker was open: %v", err)
	}
	if _, ok := s3fake.object("certs/mx.example.com+token"); !ok {
		t.Error("the challenge response never reached S3")
	}
}

// F15: autocert holds one global mutex across Cache.Get, so every concurrent
// handshake on the node queues behind a slow read. When this node already holds
// a servable copy, waiting the full S3 timeout for a possibly fresher one costs
// far more than it can win.
func TestFallbackCacheSlowS3DoesNotStallWhenLocalCopyExists(t *testing.T) {
	cache, s3fake, dir := newTestFallbackCache(t)
	writeLocal(t, dir, "mx.example.com", "local")
	s3fake.objects["certs/mx.example.com"] = []byte("from-s3")
	s3fake.delay = 4 * time.Second

	start := time.Now()
	data, err := cache.Get(context.Background(), "mx.example.com")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Get blocked for %v with a servable local copy; every handshake waits behind it", elapsed)
	}
	if string(data) != "local" {
		t.Errorf("Get = %q, want the local copy once S3 proved slow", data)
	}
}

// With nothing to serve, waiting is all there is to do: the longer budget stands.
func TestFallbackCacheSlowS3StillWaitedForWithoutLocalCopy(t *testing.T) {
	cache, s3fake, _ := newTestFallbackCache(t)
	s3fake.objects["certs/mx.example.com"] = []byte("from-s3")
	s3fake.delay = 2 * time.Second

	data, err := cache.Get(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != "from-s3" {
		t.Errorf("Get = %q, want the S3 copy", data)
	}
}

// A pending marker can outlive the certificate it refers to - an operator
// clearing the cache dir, a partial restore, a local write that failed after the
// marker was written. Answering from the local copy without checking that there
// is one turns that into ErrCacheMiss, which is the one answer that makes
// autocert order a duplicate of a certificate S3 is holding perfectly well.
func TestFallbackCacheStalePendingMarkerFallsBackToS3(t *testing.T) {
	cache, s3fake, _ := newTestFallbackCache(t)
	ctx := context.Background()
	s3fake.objects["certs/mx.example.com"] = []byte("in-s3")

	cache.setPending("mx.example.com", true) // marker with no local file

	got, err := cache.Get(ctx, "mx.example.com")
	if err == autocert.ErrCacheMiss {
		t.Fatal("a stale pending marker reported a cache miss; autocert will order a duplicate")
	}
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "in-s3" {
		t.Errorf("Get = %q, want the copy S3 holds", got)
	}
	if cache.isPending("mx.example.com") {
		t.Error("the stale marker was left in place")
	}
}

// Put attempts S3 for a challenge response even with the breaker open, because
// refusing one fails the validation outright. A read has to match: the node the
// CA connects to for TLS-ALPN-01 can only answer from S3, and challenge keys are
// never written locally, so an open breaker would fail every validation.
func TestFallbackCacheChallengeGetIgnoresOpenBreaker(t *testing.T) {
	cache, s3fake, _ := newTestFallbackCache(t)
	cache.checkInterval = time.Minute
	ctx := context.Background()
	s3fake.objects["certs/mx.example.com+token"] = []byte("token")

	s3fake.setDown(true)
	if _, err := cache.Get(ctx, "mx.example.com"); err == nil {
		t.Fatal("setup: expected the first Get to trip the breaker")
	}
	s3fake.setDown(false)

	got, err := cache.Get(ctx, "mx.example.com+token")
	if err != nil {
		t.Fatalf("challenge Get refused while the breaker was open: %v", err)
	}
	if string(got) != "token" {
		t.Errorf("Get = %q, want the token from S3", got)
	}
}

// autocert holds one global mutex across Cache.Get, so anything a read waits for
// is something every handshake on the node waits for. The five-minute sync walks
// every pending key doing S3 round trips; if it holds a lock the read path also
// takes, a degraded bucket stalls handshakes for as long as the sync runs.
func TestFallbackCacheGetDoesNotWaitForAPendingSync(t *testing.T) {
	cache, s3fake, dir := newTestFallbackCache(t)
	ctx := context.Background()

	// One key left over from an outage, so the sync has work to do.
	s3fake.setDown(true)
	if err := cache.Put(ctx, "pending.example.com", []byte("pending")); err != nil {
		t.Fatalf("Put during outage: %v", err)
	}
	s3fake.setDown(false)

	// An unrelated certificate this node can serve locally.
	writeLocal(t, dir, "mx.example.com", "local")
	s3fake.objects["certs/mx.example.com"] = []byte("local")

	// Reads stay quick; it is the sync's write that takes its time.
	s3fake.mu.Lock()
	s3fake.putDelay = 5 * time.Second
	s3fake.mu.Unlock()

	synced := make(chan struct{})
	go func() {
		defer close(synced)
		cache.SyncPendingToS3(ctx)
	}()
	time.Sleep(200 * time.Millisecond) // let the sync get going

	start := time.Now()
	if _, err := cache.Get(ctx, "mx.example.com"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("Get waited %v behind the pending sync; every handshake waits with it", elapsed)
	}
	<-synced
}

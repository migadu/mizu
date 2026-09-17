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

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"golang.org/x/crypto/acme/autocert"
)

// fakeS3 is an in-memory S3API whose availability can be toggled.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	down    bool
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

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
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

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
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

// S3 answering "not found" is authoritative: a leftover local file is not served.
func TestFallbackCacheGetS3MissIgnoresLocal(t *testing.T) {
	cache, _, dir := newTestFallbackCache(t)
	writeLocal(t, dir, "mx.example.com", "deleted-from-s3")

	if _, err := cache.Get(context.Background(), "mx.example.com"); err != autocert.ErrCacheMiss {
		t.Errorf("Get error = %v, want ErrCacheMiss", err)
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

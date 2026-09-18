package tls

import (
	"context"
	"testing"
)

// F14: ordering is gated at the ACME transport now, so a node only ever holds a
// certificate it was entitled to order. Leadership can still move while an order
// is in flight - a rolling restart demotes a node within a second of the smaller
// name rejoining - and refusing the write then throws away a certificate the CA
// has already issued and counted against the weekly limit. autocert ignores the
// error, so it is not even retried.
func TestClusterAwareCacheStoresCertificateIssuedBeforeDemotion(t *testing.T) {
	underlying := newMemCache()
	leader := true
	cache := NewClusterAwareCache(underlying, func() bool { return leader }, discardLogger())

	// The order began on the leader; the node was demoted before it finished.
	leader = false

	if err := cache.Put(context.Background(), "mx.example.com", []byte("issued")); err != nil {
		t.Fatalf("Put refused after a leadership change: %v", err)
	}
	if data, err := underlying.Get(context.Background(), "mx.example.com"); err != nil {
		t.Errorf("the issued certificate was discarded: %v", err)
	} else if string(data) != "issued" {
		t.Errorf("stored %q, want the issued certificate", data)
	}
}

// Deleting shared state is still the leader's alone: it destroys something no
// other node can recover, and nothing about it is already paid for.
func TestClusterAwareCacheStillGatesDelete(t *testing.T) {
	underlying := newMemCache()
	underlying.Put(context.Background(), "mx.example.com", []byte("cert"))
	cache := NewClusterAwareCache(underlying, func() bool { return false }, discardLogger())

	if err := cache.Delete(context.Background(), "mx.example.com"); err == nil {
		t.Error("a non-leader deleted a shared certificate")
	}
	if _, err := underlying.Get(context.Background(), "mx.example.com"); err != nil {
		t.Error("the certificate was deleted anyway")
	}
}

// Letting a non-leader store certificates must not let it store the cluster's
// ACME account key. autocert generates that key and writes it *before* it
// registers, so the write is not gated by the transport: a node coming up
// against an empty bucket would put its own key over the leader's, and the
// cluster would end up with two ACME accounts the next time the leader
// restarted. Challenge responses are the leader's too - a non-leader cannot
// legitimately be answering a challenge it did not start.
func TestClusterAwareCacheKeepsSharedStateWithTheLeader(t *testing.T) {
	for _, key := range []string{"acme_account+key", "acme_account.key", "mx.example.com+token", "abc123+http-01"} {
		underlying := newMemCache()
		cache := NewClusterAwareCache(underlying, func() bool { return false }, discardLogger())

		if err := cache.Put(context.Background(), key, []byte("mine")); err == nil {
			t.Errorf("%s: a non-leader was allowed to overwrite shared state", key)
		}
		if _, err := underlying.Get(context.Background(), key); err == nil {
			t.Errorf("%s: shared state was overwritten anyway", key)
		}
	}
}

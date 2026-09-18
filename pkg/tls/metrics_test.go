package tls

import (
	"context"
	"testing"
	"time"

	"migadu/mizu/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func expiryGauge(t *testing.T, mx *metrics.Metrics, domain, keyType string) float64 {
	t.Helper()
	return testutil.ToFloat64(mx.TLSCertExpiry.WithLabelValues(domain, keyType))
}

// The two key types of one domain expire at different times — in the incident
// that prompted this metric, nine days apart. Each must be reported separately;
// with a domain-only label the second write would silently replace the first.
func TestMaintainCertificatesExportsExpiryPerKeyType(t *testing.T) {
	const domain = "mx.example.com"
	ecdsaExpiry := time.Now().Add(80 * 24 * time.Hour).Truncate(time.Second)
	rsaExpiry := time.Now().Add(71 * 24 * time.Hour).Truncate(time.Second)

	cache := newMemCache()
	cache.Put(context.Background(), certCacheKey(domain, "ecdsa"), cacheEntry(t, domain, false, ecdsaExpiry))
	cache.Put(context.Background(), certCacheKey(domain, "rsa"), cacheEntry(t, domain, true, rsaExpiry))

	mx := metrics.New("tlsexpiry_perkeytype")
	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(true), domain)
	m.SetMetrics(mx)

	m.maintainCertificates()

	if got, want := expiryGauge(t, mx, domain, "ecdsa"), float64(ecdsaExpiry.Unix()); got != want {
		t.Errorf("ecdsa expiry = %v, want %v", got, want)
	}
	if got, want := expiryGauge(t, mx, domain, "rsa"), float64(rsaExpiry.Unix()); got != want {
		t.Errorf("rsa expiry = %v, want %v", got, want)
	}
}

// Every node exports what it would serve. A leader-only walk would have left the
// nodes that actually held the stale certificates unmonitored.
func TestMaintainCertificatesExportsOnNonLeader(t *testing.T) {
	const domain = "mx.example.com"
	expiry := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)

	cache := newMemCache()
	cache.Put(context.Background(), certCacheKey(domain, "ecdsa"), cacheEntry(t, domain, false, expiry))
	cache.Put(context.Background(), certCacheKey(domain, "rsa"), cacheEntry(t, domain, true, expiry))

	mx := metrics.New("tlsexpiry_nonleader")
	base := &countingTransport{resp: refuseAll}
	m := newTestManager(cache, base, always(false), domain)
	m.SetMetrics(mx)

	m.maintainCertificates()

	for _, keyType := range certKeyTypes {
		if got, want := expiryGauge(t, mx, domain, keyType), float64(expiry.Unix()); got != want {
			t.Errorf("%s expiry on non-leader = %v, want %v", keyType, got, want)
		}
	}
	if n := base.calls.Load(); n != 0 {
		t.Errorf("non-leader sent %d request(s) to the CA while exporting metrics", n)
	}
}

// An expired cache entry reads as 0, not as a past timestamp: autocert refuses
// to load one (validCert), so there is genuinely nothing this node could hand
// out. Either value fires "expiry - time() < N", but an alert that first guards
// on "expiry > 0" would skip exactly this case.
//
// A node that loaded the certificate while it was still valid keeps serving it
// from memory and does report the real past expiry — that is what production
// showed on 2026-09-17 until the nodes were restarted.
func TestMaintainCertificatesExportsZeroForExpiredCacheEntry(t *testing.T) {
	const domain = "mx.example.com"

	cache := newMemCache()
	cache.Put(context.Background(), certCacheKey(domain, "ecdsa"),
		cacheEntry(t, domain, false, time.Now().Add(-2*time.Hour)))

	mx := metrics.New("tlsexpiry_expired")
	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)
	m.SetMetrics(mx)

	m.maintainCertificates()

	if got := expiryGauge(t, mx, domain, "ecdsa"); got != 0 {
		t.Errorf("expired cache entry reported as %v, want 0", got)
	}
}

// No certificate at all must not leave the previous value standing, where it
// would go on reading as healthy.
func TestMaintainCertificatesExportsZeroWhenNothingToServe(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	cache.Put(context.Background(), certCacheKey(domain, "ecdsa"),
		cacheEntry(t, domain, false, time.Now().Add(80*24*time.Hour)))

	mx := metrics.New("tlsexpiry_missing")
	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)
	m.SetMetrics(mx)

	m.maintainCertificates()
	if expiryGauge(t, mx, domain, "ecdsa") == 0 {
		t.Fatal("setup: expected a certificate to be reported first")
	}

	cache.Delete(context.Background(), certCacheKey(domain, "ecdsa"))
	// A reload is what drops autocert's in-memory copy, as happens on a restart.
	m.current.Store(m.newAutocert(m.cache))
	m.maintainCertificates()

	if got := expiryGauge(t, mx, domain, "ecdsa"); got != 0 {
		t.Errorf("expiry with no certificate = %v, want 0", got)
	}
	if got := expiryGauge(t, mx, domain, "rsa"); got != 0 {
		t.Errorf("expiry for a key type that was never issued = %v, want 0", got)
	}
}

// Without SetMetrics the manager records nothing and must not panic.
func TestMaintainCertificatesWithoutMetrics(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	cache.Put(context.Background(), certCacheKey(domain, "ecdsa"),
		cacheEntry(t, domain, false, time.Now().Add(80*24*time.Hour)))

	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)
	m.maintainCertificates()
}

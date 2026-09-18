package tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCA is an ACME server behind a RoundTripper. It authorizes every order on
// the spot (status "ready", no challenges) and signs whatever CSR it is sent.
type fakeCA struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	issued atomic.Int32

	mu    sync.Mutex
	certs map[string][]byte // cert URL path -> PEM chain
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeCA{t: t, key: key, cert: cert, certs: make(map[string][]byte)}
}

func (ca *fakeCA) RoundTrip(req *http.Request) (*http.Response, error) {
	const base = "https://acme.invalid"
	path := req.URL.Path

	respond := func(status int, location string, body []byte) (*http.Response, error) {
		header := http.Header{"Replay-Nonce": []string{fmt.Sprintf("nonce-%d", time.Now().UnixNano())}}
		if location != "" {
			header.Set("Location", location)
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
	}

	switch {
	case path == "/directory":
		return respond(http.StatusOK, "", []byte(`{"newNonce":"`+base+`/new-nonce","newAccount":"`+base+`/new-account","newOrder":"`+base+`/new-order"}`))
	case path == "/new-nonce":
		return respond(http.StatusOK, "", nil)
	case path == "/new-account":
		return respond(http.StatusCreated, base+"/account/1", []byte(`{"status":"valid"}`))
	case path == "/new-order":
		return respond(http.StatusCreated, base+"/order/1", []byte(`{"status":"ready","authorizations":[],"finalize":"`+base+`/finalize"}`))
	case path == "/finalize":
		certPath := ca.issue(req)
		return respond(http.StatusOK, base+"/order/1", []byte(`{"status":"valid","certificate":"`+base+certPath+`"}`))
	case strings.HasPrefix(path, "/cert/"):
		ca.mu.Lock()
		chain := ca.certs[path]
		ca.mu.Unlock()
		return respond(http.StatusOK, "", chain)
	}
	return respond(http.StatusNotFound, "", []byte(`{"type":"urn:ietf:params:acme:error:malformed","detail":"unknown path"}`))
}

// issue signs the CSR carried in a finalize request and returns the cert's path.
func (ca *fakeCA) issue(req *http.Request) string {
	var jws struct{ Payload string }
	if err := json.NewDecoder(req.Body).Decode(&jws); err != nil {
		ca.t.Errorf("fakeCA: bad JWS: %v", err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	var finalize struct{ CSR string }
	json.Unmarshal(payload, &finalize)
	csrDER, _ := base64.RawURLEncoding.DecodeString(finalize.CSR)
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		ca.t.Errorf("fakeCA: bad CSR: %v", err)
		return "/cert/none"
	}

	n := ca.issued.Add(1)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(100 + n)),
		Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		ca.t.Errorf("fakeCA: signing failed: %v", err)
	}

	var chain bytes.Buffer
	pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})

	certPath := fmt.Sprintf("/cert/%d", n)
	ca.mu.Lock()
	ca.certs[certPath] = chain.Bytes()
	ca.mu.Unlock()
	return certPath
}

func always(v bool) func() bool { return func() bool { return v } }

// mustServedLeaf returns the leaf the manager currently serves for a key type.
func mustServedLeaf(t *testing.T, m *Manager, domain, keyType string) *x509.Certificate {
	t.Helper()
	leaf, err := servedLeaf(m.current.Load(), domain, keyType)
	if err != nil {
		t.Fatalf("servedLeaf(%s, %s): %v", domain, keyType, err)
	}
	return leaf
}

// seedCerts stores a valid certificate of each key type and returns the entries.
func seedCerts(t *testing.T, cache *memCache, domain string, notAfter time.Time) map[string][]byte {
	t.Helper()
	entries := map[string][]byte{
		certCacheKey(domain, "ecdsa"): cacheEntry(t, domain, false, notAfter),
		certCacheKey(domain, "rsa"):   cacheEntry(t, domain, true, notAfter),
	}
	for key, data := range entries {
		cache.Put(context.Background(), key, data)
	}
	return entries
}

// Regression: renew-cert used to delete the cache entry and leave autocert's
// in-memory copy alone, so nothing was ordered until the leader restarted.
func TestRenewCertificateOrdersAndServesNewCertificate(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	seedCerts(t, cache, domain, time.Now().Add(80*24*time.Hour))

	ca := newFakeCA(t)
	m := newTestManager(cache, ca, always(true), domain)

	before := map[string]*x509.Certificate{}
	for _, keyType := range certKeyTypes {
		before[keyType] = mustServedLeaf(t, m, domain, keyType)
	}
	oldInstance := m.current.Load()

	renewed, err := m.RenewCertificate(domain)
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if len(renewed) != 2 || ca.issued.Load() != 2 {
		t.Errorf("renewed = %v, CA issued %d; want one certificate per key type", renewed, ca.issued.Load())
	}

	for _, keyType := range certKeyTypes {
		after := mustServedLeaf(t, m, domain, keyType)
		if bytes.Equal(after.Raw, before[keyType].Raw) {
			t.Errorf("%s: still serving the old certificate", keyType)
		}
		if after.Issuer.CommonName != "fake CA" {
			t.Errorf("%s: serving a certificate issued by %q, want the CA's", keyType, after.Issuer.CommonName)
		}
		// Other nodes and the next restart read the cache: it must hold the same one.
		cached, err := m.cachedLeaf(context.Background(), domain, keyType)
		if err != nil || !bytes.Equal(cached.Raw, after.Raw) {
			t.Errorf("%s: cache does not hold the served certificate (err=%v)", keyType, err)
		}
	}

	// The replaced instance keeps its renewal timers; it must not be able to order.
	if !oldInstance.transport.retired.Load() {
		t.Error("replaced autocert instance was not retired")
	}
}

// Nothing is removed before the replacement exists: a failed order (a rate limit,
// say) must leave the domain exactly as it was.
func TestRenewCertificateFailedOrderChangesNothing(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	entries := seedCerts(t, cache, domain, time.Now().Add(80*24*time.Hour))

	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(true), domain)
	before := mustServedLeaf(t, m, domain, "ecdsa")
	instance := m.current.Load()

	if _, err := m.RenewCertificate(domain); err == nil {
		t.Fatal("RenewCertificate succeeded without a reachable CA")
	}

	for key, want := range entries {
		if got, _ := cache.Get(context.Background(), key); !bytes.Equal(got, want) {
			t.Errorf("cache entry %q changed after a failed renewal", key)
		}
	}
	if m.current.Load() != instance {
		t.Error("autocert was reloaded after a failed renewal")
	}
	if after := mustServedLeaf(t, m, domain, "ecdsa"); !bytes.Equal(after.Raw, before.Raw) {
		t.Error("served certificate changed after a failed renewal")
	}
}

func TestRenewCertificateRefusedOnNonLeader(t *testing.T) {
	const domain = "mx.example.com"
	ca := newFakeCA(t)
	m := newTestManager(newMemCache(), ca, always(false), domain)

	if _, err := m.RenewCertificate(domain); err == nil {
		t.Error("RenewCertificate succeeded on a non-leader")
	}
	if _, err := m.RenewCertificate("other.example.com"); err == nil {
		t.Error("RenewCertificate accepted a domain that is not configured")
	}
	if ca.issued.Load() != 0 {
		t.Errorf("CA issued %d certificate(s)", ca.issued.Load())
	}
}

// A certificate replaced ahead of its renewal time (renew-cert on the leader, or
// an entry put into S3 by hand) must reach the other nodes without a restart.
func TestAdoptNewerFromCache(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	seedCerts(t, cache, domain, time.Now().Add(70*24*time.Hour))

	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)
	old := mustServedLeaf(t, m, domain, "ecdsa")

	newer := cacheEntry(t, domain, false, time.Now().Add(89*24*time.Hour))
	cache.Put(context.Background(), certCacheKey(domain, "ecdsa"), newer)

	m.adoptNewerFromCache()

	got := mustServedLeaf(t, m, domain, "ecdsa")
	if bytes.Equal(got.Raw, old.Raw) {
		t.Fatal("still serving the old certificate")
	}
	if !got.NotAfter.After(old.NotAfter) {
		t.Errorf("served NotAfter = %s, want later than %s", got.NotAfter, old.NotAfter)
	}
}

// Inside its renewal window autocert polls the cache itself; reloading there
// would replace the instance on every routine renewal.
func TestAdoptNewerFromCacheLeavesRoutineRenewalsToAutocert(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	seedCerts(t, cache, domain, time.Now().Add(10*24*time.Hour))

	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)
	mustServedLeaf(t, m, domain, "ecdsa")
	instance := m.current.Load()

	cache.Put(context.Background(), certCacheKey(domain, "ecdsa"),
		cacheEntry(t, domain, false, time.Now().Add(89*24*time.Hour)))
	m.adoptNewerFromCache()

	if m.current.Load() != instance {
		t.Error("autocert was reloaded for a certificate inside its renewal window")
	}
}

// A reload drops every certificate held in memory. If the cache cannot supply
// one of them, the working in-memory copy has to stay.
func TestReloadKeepsMemoryWhenCacheEntryIsGone(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	seedCerts(t, cache, domain, time.Now().Add(70*24*time.Hour))

	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)
	before := mustServedLeaf(t, m, domain, "rsa")
	instance := m.current.Load()

	cache.Delete(context.Background(), certCacheKey(domain, "rsa"))

	if err := m.reload("test"); err == nil {
		t.Fatal("reload succeeded although the cache lost a served certificate")
	}
	if m.current.Load() != instance {
		t.Error("instance was replaced")
	}
	if after := mustServedLeaf(t, m, domain, "rsa"); !bytes.Equal(after.Raw, before.Raw) {
		t.Error("served certificate changed")
	}
}

func TestRetiredInstanceCannotOrder(t *testing.T) {
	base := &countingTransport{resp: refuseAll}
	m := newTestManager(newMemCache(), base, always(true), "mx.example.com")

	inst := m.current.Load()
	inst.retire()

	_, err := inst.mgr.GetCertificate(certHello("mx.example.com", "ecdsa"))
	if !errors.Is(err, errInstanceRetired) {
		t.Errorf("GetCertificate error = %v, want errInstanceRetired", err)
	}
	if n := base.calls.Load(); n != 0 {
		t.Errorf("retired instance sent %d request(s) to the CA", n)
	}
}

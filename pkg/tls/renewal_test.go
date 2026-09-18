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
	t          *testing.T
	key        *ecdsa.PrivateKey
	cert       *x509.Certificate
	issued     atomic.Int32
	afterIssue func() // test hook, called once a certificate has been signed

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
	hook := ca.afterIssue
	ca.mu.Unlock()
	if hook != nil {
		hook()
	}
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

	renewed, err := m.RenewCertificate(context.Background(), domain)
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

	if _, err := m.RenewCertificate(context.Background(), domain); err == nil {
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

	if _, err := m.RenewCertificate(context.Background(), domain); err == nil {
		t.Error("RenewCertificate succeeded on a non-leader")
	}
	if _, err := m.RenewCertificate(context.Background(), "other.example.com"); err == nil {
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
	m.maintainCertificates() // loads the certificates and records what is served
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
	m.maintainCertificates()
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
	m.maintainCertificates()
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

// F3: autocert's GetCertificate orders a certificate when it does not have one,
// so using it to ask "what are we serving?" places real ACME orders. On the
// leader that turned reload and the hourly adopt check into order loops for
// every domain whose certificate was missing - inside the synchronous
// renew-cert call, and against a rate limit that was already exhausted.
func TestReloadAndAdoptNeverOrderCertificates(t *testing.T) {
	const seeded, missing = "a.example.com", "b.example.com"

	for _, tc := range []struct {
		name string
		run  func(*Manager)
	}{
		{"reload", func(m *Manager) {
			if err := m.reload("test"); err != nil {
				t.Errorf("reload: %v", err)
			}
		}},
		{"adoptNewerFromCache", func(m *Manager) { m.adoptNewerFromCache() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := newMemCache()
			seedCerts(t, cache, seeded, time.Now().Add(80*24*time.Hour))

			ca := newFakeCA(t)
			m := newTestManager(cache, ca, always(true), seeded, missing)

			tc.run(m)

			if n := ca.issued.Load(); n != 0 {
				t.Errorf("%s placed %d ACME order(s); it must only read", tc.name, n)
			}
		})
	}
}

// entryLeaf parses the leaf out of an autocert cache entry, expired or not.
func entryLeaf(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
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
			t.Fatal(err)
		}
		return leaf
	}
	t.Fatal("no certificate in entry")
	return nil
}

// F2: autocert keeps handing out a certificate that has expired - it never
// re-checks what is already in memory - but refuses to load one from the cache.
// Counting such a certificate as "in service" made it block every reload, so in
// exactly the state this PR addresses (some domains expired, the CA refusing
// more) a successful renewal of another domain was never put into service and
// was reported to the operator as a partial failure.
func TestReloadIgnoresExpiredCertificateHeldInMemory(t *testing.T) {
	const stuck, renewed = "stuck.example.com", "renewed.example.com"

	cache := newMemCache()
	seedCerts(t, cache, renewed, time.Now().Add(80*24*time.Hour))
	expired := cacheEntry(t, stuck, false, time.Now().Add(-time.Hour))
	cache.Put(context.Background(), certCacheKey(stuck, "ecdsa"), expired)

	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), stuck, renewed)
	m.maintainCertificates()
	// This node loaded stuck.example.com before it expired and is still serving it.
	m.recordServed(stuck, "ecdsa", entryLeaf(t, expired))

	if err := m.reload("renewed " + renewed); err != nil {
		t.Fatalf("reload refused over an unrelated expired certificate: %v", err)
	}
	if leaf := mustServedLeaf(t, m, renewed, "ecdsa"); leaf == nil {
		t.Error("the renewed certificate is not in service")
	}
}

// F6: reload swaps the instance and retires the one it replaced. Two running at
// once both read the same current instance, so whichever stores second replaces
// the other's instance without retiring it - leaving an autocert manager that
// nothing points at, still holding every renewal timer and an ACME transport
// that is not cut off. That is precisely the duplicate ordering the retire
// mechanism exists to prevent. The window is real: the hourly maintenance pass
// calls reload through adoptNewerFromCache while renew-cert is inside its own.
func TestReloadIsSerialized(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	seedCerts(t, cache, domain, time.Now().Add(80*24*time.Hour))

	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)
	m.maintainCertificates()

	var inside atomic.Int32
	var overlapped atomic.Bool
	cache.mu.Lock()
	cache.beforeGet = func(string) {
		if inside.Add(1) > 1 {
			overlapped.Store(true)
		}
		time.Sleep(20 * time.Millisecond)
		inside.Add(-1)
	}
	cache.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.reload("concurrent"); err != nil {
				t.Errorf("reload: %v", err)
			}
		}()
	}
	wg.Wait()

	if overlapped.Load() {
		t.Error("two reloads ran at once; one autocert instance was replaced without being retired")
	}
}

// reorderEntry rewrites a cache entry with the certificate before the key, the
// order `cat fullchain.pem privkey.pem` produces.
func reorderEntry(t *testing.T, data []byte) []byte {
	t.Helper()
	var blocks []*pem.Block
	for rest := data; len(rest) > 0; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		blocks = append(blocks, b)
	}
	if len(blocks) < 2 {
		t.Fatalf("entry has %d PEM blocks", len(blocks))
	}

	var out bytes.Buffer
	for i := len(blocks) - 1; i >= 0; i-- {
		if err := pem.Encode(&out, blocks[i]); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

// F12: cachedLeaf decides whether a reload can go ahead and whether the cache
// holds something newer, so it has to accept exactly what autocert accepts.
// tls.X509KeyPair is laxer: autocert insists the private key is the first PEM
// block and that nothing trails the last one. Accepting an entry autocert then
// refuses makes the leader silently order a replacement and overwrite the entry
// an operator placed by hand - spending the rate limit they were working around.
func TestCachedLeafMatchesWhatAutocertAccepts(t *testing.T) {
	const domain = "mx.example.com"
	valid := cacheEntry(t, domain, false, time.Now().Add(80*24*time.Hour))

	for name, entry := range map[string][]byte{
		"certificate before key": reorderEntry(t, valid),
		"trailing bytes":         append(append([]byte{}, valid...), '\n', '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			cache := newMemCache()
			cache.Put(context.Background(), certCacheKey(domain, "ecdsa"), entry)
			m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)

			// Establish what autocert does with it, rather than assuming.
			if _, err := m.current.Load().mgr.GetCertificate(certHello(domain, "ecdsa")); err == nil {
				t.Skip("autocert accepts this entry after all; nothing to match")
			}

			if _, err := m.cachedLeaf(context.Background(), domain, "ecdsa"); err == nil {
				t.Error("cachedLeaf accepted an entry autocert refuses to load")
			}
		})
	}
}

// F8: both key types of a domain draw on the same duplicate-certificate budget.
// When one succeeds and the other is refused, the operator has to be able to
// retry just the one that failed; ordering both again spends a slot on a
// certificate issued minutes earlier, and with one slot left that is the slot
// the failing key type needed.
func TestRenewCertificateOrdersOnlyTheRequestedKeyType(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	// Comfortably outside the renewal window: autocert arms a timer for every
	// certificate it loads, and one inside the window orders on its own.
	seedCerts(t, cache, domain, time.Now().Add(80*24*time.Hour))

	ca := newFakeCA(t)
	m := newTestManager(cache, ca, always(true), domain)
	m.maintainCertificates()
	beforeECDSA := mustServedLeaf(t, m, domain, "ecdsa")

	renewed, err := m.RenewCertificate(context.Background(), domain, "rsa")
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if len(renewed) != 1 {
		t.Errorf("renewed %v, want only the requested key type", renewed)
	}
	if n := ca.issued.Load(); n != 1 {
		t.Errorf("CA issued %d certificates, want 1", n)
	}
	if after := mustServedLeaf(t, m, domain, "ecdsa"); !bytes.Equal(after.Raw, beforeECDSA.Raw) {
		t.Error("the ECDSA certificate was re-ordered although only RSA was asked for")
	}
}

// A key type asked for by a name that is not one is refused rather than quietly
// turned into "both".
func TestRenewCertificateRejectsUnknownKeyType(t *testing.T) {
	const domain = "mx.example.com"
	ca := newFakeCA(t)
	m := newTestManager(newMemCache(), ca, always(true), domain)

	if _, err := m.RenewCertificate(context.Background(), domain, "ed25519"); err == nil {
		t.Error("RenewCertificate accepted a key type it cannot order")
	}
	if n := ca.issued.Load(); n != 0 {
		t.Errorf("CA issued %d certificates for an unknown key type", n)
	}
}

// Residual: renew-cert blocks until the CA answers, so the operator may well
// give up - Ctrl-C, or a dropped connection. The order then carried on server
// side, and a re-run after it finished ordered everything a second time: four
// issuances for two certificates, against a five-per-week budget.
func TestRenewCertificateStopsWhenTheCallerGivesUp(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	seedCerts(t, cache, domain, time.Now().Add(80*24*time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := newFakeCA(t)
	// The caller disconnects as the first certificate comes back.
	ca.afterIssue = cancel

	m := newTestManager(cache, ca, always(true), domain)
	m.maintainCertificates()

	if _, err := m.RenewCertificate(ctx, domain); err == nil {
		t.Error("RenewCertificate reported success after the caller gave up")
	}

	if n := ca.issued.Load(); n != 1 {
		t.Errorf("CA issued %d certificates after the caller gave up, want 1", n)
	}
}

// Residual: autocert offers no way to stop a replaced manager's renewal timers
// (stopRenew is unexported and unreachable), so every reload leaves one behind
// for the life of the process. It cannot order - its transport is retired - and
// its timers settle into a cache read per certificate per renewal period, so the
// cost is bounded by how often reload runs.
//
// This is what keeps that bounded: a steady state must not reload at all.
func TestMaintenanceDoesNotAccumulateAutocertInstances(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	seedCerts(t, cache, domain, time.Now().Add(80*24*time.Hour))

	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)
	m.maintainCertificates()
	instance := m.current.Load()

	for i := 0; i < 24; i++ {
		m.maintainCertificates()
	}

	if m.current.Load() != instance {
		t.Error("a day of maintenance passes replaced the autocert instance; every reload leaks one")
	}
}

// An order that finishes after the caller has gone must still be put into
// service. Validating it with the caller's dead context turned a certificate the
// CA had issued and charged for into a reported failure, with no reload: the
// node kept serving the old certificate and the operator was told it had failed.
func TestRenewCertificateKeepsACertificateIssuedAfterTheCallerLeft(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	seedCerts(t, cache, domain, time.Now().Add(80*24*time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := newFakeCA(t)
	ca.afterIssue = cancel // the caller hangs up as the CA answers

	m := newTestManager(cache, ca, always(true), domain)
	m.maintainCertificates()
	before := mustServedLeaf(t, m, domain, "ecdsa")

	renewed, _ := m.RenewCertificate(ctx, domain)

	if len(renewed) == 0 {
		t.Error("the certificate the CA issued was not reported as renewed")
	}
	if after := mustServedLeaf(t, m, domain, "ecdsa"); bytes.Equal(after.Raw, before.Raw) {
		t.Error("the issued certificate was never put into service")
	}
}

// Finding 7: on a node that is not the leader, GetCertificate cannot order, and
// the failed attempt leaves autocert holding a poisoned state for that name for
// a minute. Every handshake in that window fails without the cache being read at
// all - so a certificate the leader publishes seconds later is ignored, and the
// 5-minute pass poisons it again. It also burns an RSA keygen per domain.
func TestMaintainCertificatesOnNonLeaderLeavesAutocertUnpoisoned(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()

	base := &countingTransport{resp: refuseAll}
	m := newTestManager(cache, base, always(false), domain)

	m.maintainCertificates() // nothing to serve yet

	// The leader publishes the certificate a moment later.
	seedCerts(t, cache, domain, time.Now().Add(80*24*time.Hour))

	if _, err := m.current.Load().mgr.GetCertificate(certHello(domain, "ecdsa")); err != nil {
		t.Errorf("handshake still failing after the leader published the certificate: %v", err)
	}
	if !m.maintainCertificates() {
		t.Error("the next pass did not pick up the published certificate")
	}
}

// Finding 9: the whole point of naming a key type is not to spend a slot on one
// that was already issued, so asking for the same one twice must not place two
// orders. The handler can produce that: it reads key_type from the query and
// then also from the body.
func TestResolveKeyTypesDeduplicates(t *testing.T) {
	got, err := resolveKeyTypes([]string{"rsa", "rsa"})
	if err != nil {
		t.Fatalf("resolveKeyTypes: %v", err)
	}
	if len(got) != 1 || got[0] != "rsa" {
		t.Errorf("resolveKeyTypes = %v, want [rsa]", got)
	}
}

// Finding 11: autocert parses the whole chain and rejects the entry if any
// certificate in it is corrupt, so accepting one on the strength of its leaf
// alone re-creates the mismatch parseCacheEntry exists to prevent: reload swaps
// in an instance that cannot load it, and the leader re-orders over it.
func TestParseCacheEntryRejectsACorruptIntermediate(t *testing.T) {
	const domain = "mx.example.com"
	valid := cacheEntry(t, domain, false, time.Now().Add(80*24*time.Hour))

	corrupt := append([]byte{}, valid...)
	corrupt = append(corrupt, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not a certificate"),
	})...)

	cache := newMemCache()
	cache.Put(context.Background(), certCacheKey(domain, "ecdsa"), corrupt)
	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)

	if _, err := m.current.Load().mgr.GetCertificate(certHello(domain, "ecdsa")); err == nil {
		t.Skip("autocert accepts this entry after all; nothing to match")
	}
	if _, err := m.cachedLeaf(context.Background(), domain, "ecdsa"); err == nil {
		t.Error("cachedLeaf accepted an entry autocert refuses to load")
	}
}

// Finding 12: autocert converts a name to its IDNA form before it builds a cache
// key, so a Unicode domain is stored as punycode. Reading it back under the
// Unicode spelling finds nothing: reload refuses every swap, adopt never adopts,
// the orderer's hidingCache hides nothing, and the metric is filed under a label
// that never matches.
func TestUnicodeDomainUsesTheSameCacheKeyAsAutocert(t *testing.T) {
	const unicode = "wysyłka.example.com"
	const punycode = "xn--wysyka-6db.example.com" // what idna.Lookup.ToASCII gives, as autocert uses

	if got := certCacheKey(unicode, "ecdsa"); got != punycode {
		t.Errorf("certCacheKey(%q) = %q, want the punycode %q", unicode, got, punycode)
	}
	if got := certHello(unicode, "ecdsa").ServerName; got != punycode {
		t.Errorf("certHello(%q) asks for %q, want %q", unicode, got, punycode)
	}

	// Stored the way autocert stores it, it must be found.
	cache := newMemCache()
	cache.Put(context.Background(), punycode, cacheEntry(t, punycode, false, time.Now().Add(80*24*time.Hour)))

	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), unicode)
	if _, err := m.cachedLeaf(context.Background(), unicode, "ecdsa"); err != nil {
		t.Errorf("cachedLeaf could not find the certificate autocert would use: %v", err)
	}
}

// A reload that cannot go ahead must not leave anything behind. autocert offers
// no way to stop a manager's renewal timers, so every instance created is one
// kept for the life of the process; building one before deciding whether to use
// it means a reload that keeps failing leaks one per attempt. adoptNewerFromCache
// retries every hour, so a cache the leader cannot fully supply - one entry gone
// while another is newer - turns that into an unbounded leak.
func TestFailedReloadCreatesNoInstance(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	seedCerts(t, cache, domain, time.Now().Add(80*24*time.Hour))

	m := newTestManager(cache, &countingTransport{resp: refuseAll}, always(false), domain)
	m.maintainCertificates()

	// The certificate in service is no longer loadable from the cache.
	cache.Delete(context.Background(), certCacheKey(domain, "rsa"))

	created := m.instancesCreated.Load()
	for i := 0; i < 24; i++ {
		if err := m.reload("hourly retry"); err == nil {
			t.Fatal("reload succeeded although a served certificate is unloadable")
		}
	}

	if leaked := m.instancesCreated.Load() - created; leaked != 0 {
		t.Errorf("24 failed reloads created %d autocert instances, each kept until the process ends", leaked)
	}
}

// autocert.HostWhitelist converts each configured host with idna.Lookup.ToASCII
// and stores only that form, so a Unicode domain in the config is admitted under
// the punycode a client actually sends in SNI. asciiDomain must therefore agree
// with it on every path that consults the policy.
func TestUnicodeDomainPassesTheHostPolicy(t *testing.T) {
	const unicode = "wysyłka.example.com"
	const punycode = "xn--wysyka-6db.example.com"

	m := newTestManager(newMemCache(), &countingTransport{resp: refuseAll}, always(true), unicode)

	for _, name := range []string{unicode, punycode} {
		if err := m.hostPolicy(context.Background(), asciiDomain(name)); err != nil {
			t.Errorf("host policy rejected %q as %q: %v", name, asciiDomain(name), err)
		}
	}

	// The handshake path passes the SNI straight through, which is punycode.
	if err := m.hostPolicy(context.Background(), punycode); err != nil {
		t.Errorf("host policy rejected the SNI a client would send: %v", err)
	}

	// And a renewal asked for by its Unicode name reaches the same policy.
	if _, err := m.RenewCertificate(context.Background(), unicode, "ecdsa"); err != nil &&
		strings.Contains(err.Error(), "not in allowed list") {
		t.Errorf("RenewCertificate rejected a configured Unicode domain: %v", err)
	}
}

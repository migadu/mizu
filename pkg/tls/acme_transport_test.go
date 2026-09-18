package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// countingTransport records requests and answers them without any network.
type countingTransport struct {
	calls atomic.Int32
	resp  func(*http.Request) (*http.Response, error)
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return c.resp(req)
}

func refuseAll(*http.Request) (*http.Response, error) {
	return nil, errors.New("test: no network")
}

// memCache is an in-memory autocert.Cache that records the keys read from it.
type memCache struct {
	mu        sync.Mutex
	data      map[string][]byte
	gets      []string
	beforeGet func(key string) // test hook, called outside the lock
}

func newMemCache() *memCache { return &memCache{data: make(map[string][]byte)} }

func (c *memCache) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	hook := c.beforeGet
	c.mu.Unlock()
	if hook != nil {
		hook(key)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets = append(c.gets, key)
	data, ok := c.data[key]
	if !ok {
		return nil, autocert.ErrCacheMiss
	}
	return data, nil
}

func (c *memCache) Put(_ context.Context, key string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = data
	return nil
}

func (c *memCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
	return nil
}

func (c *memCache) read(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.gets {
		if k == key {
			return true
		}
	}
	return false
}

// cacheEntry builds an autocert cache entry (private key + self-signed leaf).
func cacheEntry(t *testing.T, domain string, useRSA bool, notAfter time.Time) []byte {
	t.Helper()

	var key crypto.Signer
	var keyBlock *pem.Block
	if useRSA {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, keyBlock = k, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		key, keyBlock = k, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	pem.Encode(&buf, keyBlock)
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	return buf.Bytes()
}

func accountKey(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// newTestManager wires a Manager the way NewManager does, over an in-memory
// cache and a transport that never touches the network.
func newTestManager(cache autocert.Cache, base http.RoundTripper, isLeader func() bool, domains ...string) *Manager {
	logger := discardLogger()
	m := &Manager{
		cache:        NewClusterAwareCache(cache, isLeader, logger),
		hostPolicy:   autocert.HostWhitelist(domains...),
		directoryURL: "https://acme.invalid/directory",
		acmeBase:     base,
		logger:       logger,
		domains:      domains,
		isLeaderF:    isLeader,
		renewBefore:  defaultRenewBefore,
		stopCh:       make(chan struct{}),
	}
	m.current.Store(m.newAutocert(m.cache))
	return m
}

func TestACMETransportRefusesNonLeader(t *testing.T) {
	base := &countingTransport{resp: refuseAll}
	transport := &acmeTransport{base: base, isLeaderF: func() bool { return false }, logger: discardLogger()}

	req, _ := http.NewRequest(http.MethodGet, "https://acme.invalid/directory", nil)
	if _, err := transport.RoundTrip(req); !errors.Is(err, ErrNotLeader) {
		t.Errorf("RoundTrip error = %v, want ErrNotLeader", err)
	}
	if n := base.calls.Load(); n != 0 {
		t.Errorf("non-leader sent %d request(s) to the CA", n)
	}
}

// The ACME client still has to see the problem document we read for logging.
func TestACMETransportLogsErrorsAndPreservesBody(t *testing.T) {
	const problem = `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates (5) already issued for this exact set of identifiers"}`
	base := &countingTransport{resp: func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Retry-After": []string{"3600"}},
			Body:       io.NopCloser(strings.NewReader(problem)),
		}, nil
	}}

	var logs bytes.Buffer
	transport := &acmeTransport{base: base, logger: slog.New(slog.NewTextHandler(&logs, nil))}

	req, _ := http.NewRequest(http.MethodPost, "https://acme.invalid/new-order", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != problem {
		t.Errorf("body after logging = %q, want it intact", body)
	}
	for _, want := range []string{"level=WARN", "rateLimited", "status=429", "retry_after=3600"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log output missing %q:\n%s", want, logs.String())
		}
	}
}

// Regression for the order-then-discard loop: a non-leader that finds no usable
// certificate must fail without a single request reaching the CA.
func TestNonLeaderNeverOrdersCertificates(t *testing.T) {
	const domain = "mx.example.com"
	cache := newMemCache()
	// An expired certificate is what a node holds when renewal has been failing;
	// autocert treats it as a miss and goes straight to ordering.
	cache.data[domain] = cacheEntry(t, domain, false, time.Now().Add(-time.Hour))
	// The account key is already shared, as in any cluster past its first order.
	// Without it autocert stops earlier, at the cache refusing to store a new
	// one, and the transport gate would go untested.
	cache.data["acme_account+key"] = accountKey(t)

	base := &countingTransport{resp: refuseAll}
	m := newTestManager(cache, base, func() bool { return false }, domain)

	_, err := m.current.Load().mgr.GetCertificate(certHello(domain, "ecdsa"))
	if !errors.Is(err, ErrNotLeader) {
		t.Errorf("GetCertificate error = %v, want ErrNotLeader", err)
	}
	if n := base.calls.Load(); n != 0 {
		t.Errorf("non-leader sent %d request(s) to the CA", n)
	}
}

// A non-leader reads the cache (to pick up certificates replaced early) but
// ordering is the leader's job, even for a certificate that is missing.
func TestMaintainCertificatesNonLeaderNeverContactsCA(t *testing.T) {
	cache := newMemCache()
	cache.data["acme_account+key"] = accountKey(t)
	base := &countingTransport{resp: refuseAll}
	m := newTestManager(cache, base, func() bool { return false }, "mx.example.com")

	m.maintainCertificates()

	if n := base.calls.Load(); n != 0 {
		t.Errorf("non-leader sent %d request(s) to the CA", n)
	}
}

// The leader must load both key types of every configured domain — including
// names it never receives handshakes for — so their renewal timers exist.
func TestMaintainCertificatesLoadsEveryDomainAndKeyType(t *testing.T) {
	domains := []string{"mx.example.com", "node2.example.com"}
	cache := newMemCache()
	for _, d := range domains {
		cache.data[d] = cacheEntry(t, d, false, time.Now().Add(80*24*time.Hour))
		cache.data[d+"+rsa"] = cacheEntry(t, d, true, time.Now().Add(80*24*time.Hour))
	}

	base := &countingTransport{resp: refuseAll}
	m := newTestManager(cache, base, func() bool { return true }, domains...)

	m.maintainCertificates()

	for _, d := range domains {
		for _, key := range []string{d, d + "+rsa"} {
			if !cache.read(key) {
				t.Errorf("leader did not load %q", key)
			}
		}
	}
	if n := base.calls.Load(); n != 0 {
		t.Errorf("valid cached certificates triggered %d ACME request(s)", n)
	}
}

func TestMaintainCertificatesOrdersMissingCertOnLeader(t *testing.T) {
	base := &countingTransport{resp: refuseAll}
	m := newTestManager(newMemCache(), base, func() bool { return true }, "mx.example.com")

	m.maintainCertificates()

	if base.calls.Load() == 0 {
		t.Error("leader made no ACME request for a missing certificate")
	}
}

// F9: a failed challenge is not an HTTP error. The CA answers 200 with an
// authorization whose status is "invalid", autocert discards the resulting error
// and retries silently, and the first sign is a cause-less "renewal is overdue"
// warning about fifteen days later. An operator following CLAUDE.md greps for an
// ACME error, finds none, and concludes renewal is healthy.
func TestACMETransportLogsFailedValidation(t *testing.T) {
	const authz = `{"status":"invalid","identifier":{"type":"dns","value":"mx.example.com"},` +
		`"challenges":[{"type":"tls-alpn-01","status":"invalid","error":{` +
		`"type":"urn:ietf:params:acme:error:connection",` +
		`"detail":"203.0.113.4: Timeout during connect (likely firewall problem)"}}]}`

	base := &countingTransport{resp: func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(authz)),
		}, nil
	}}

	var logs bytes.Buffer
	transport := &acmeTransport{base: base, logger: slog.New(slog.NewTextHandler(&logs, nil))}

	req, _ := http.NewRequest(http.MethodPost, "https://acme.invalid/authz/1", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != authz {
		t.Errorf("body after logging = %q, want it intact for the ACME client", body)
	}
	for _, want := range []string{"level=WARN", "Timeout during connect"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log output missing %q:\n%s", want, logs.String())
		}
	}
}

// A certificate chain is not JSON and must not be read into memory looking for
// a status, nor mistaken for one.
func TestACMETransportIgnoresNonJSONSuccess(t *testing.T) {
	base := &countingTransport{resp: func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/pem-certificate-chain"}},
			Body:       io.NopCloser(strings.NewReader("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n")),
		}, nil
	}}

	var logs bytes.Buffer
	transport := &acmeTransport{base: base, logger: slog.New(slog.NewTextHandler(&logs, nil))}

	req, _ := http.NewRequest(http.MethodPost, "https://acme.invalid/cert/1", nil)
	if _, err := transport.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("a certificate download was logged as a failure:\n%s", logs.String())
	}
}

// jwsRequest builds a request shaped like the ACME client's: a JWS whose
// payload is empty for a read (POST-as-GET, RFC 8555 §6.3) and set for a write.
func jwsRequest(t *testing.T, url, payload string) *http.Request {
	t.Helper()
	body := fmt.Sprintf(`{"protected":"eyJhbGciOiJFUzI1NiJ9","payload":%q,"signature":"c2ln"}`, payload)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(body))
	return req
}

// Residual: leadership can move while an order is in flight - a rolling restart
// demotes a node a second after the smaller name rejoins. Refusing every request
// then strands a certificate the CA has issued and charged against the weekly
// limit, because the download comes after issuance and autocert ignores the
// error rather than retrying.
//
// Reads are therefore allowed and writes are not: a demoted node can collect
// what it already caused to be issued, but can never cause an issuance.
func TestACMETransportNonLeaderMayReadButNotWrite(t *testing.T) {
	seen := make(chan string, 4)
	base := &countingTransport{resp: func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		seen <- string(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/pem-certificate-chain"}},
			Body:       io.NopCloser(strings.NewReader("chain")),
		}, nil
	}}
	leader := true
	transport := &acmeTransport{base: base, isLeaderF: func() bool { return leader }, logger: discardLogger()}

	// The order is placed while this node is the leader.
	if _, err := transport.RoundTrip(jwsRequest(t, "https://acme.invalid/new-order", "eyJ4Ijp0cnVlfQ")); err != nil {
		t.Fatalf("setup: leader could not place an order: %v", err)
	}
	<-seen
	leader = false

	// The certificate download, once the CA has issued it.
	read := jwsRequest(t, "https://acme.invalid/cert/1", "")
	if _, err := transport.RoundTrip(read); err != nil {
		t.Errorf("non-leader could not collect an issued certificate: %v", err)
	}
	select {
	case body := <-seen:
		if !strings.Contains(body, `"payload":""`) {
			t.Errorf("the request body reached the CA altered: %s", body)
		}
	default:
		t.Error("the read never reached the CA")
	}

	// Anything that could cause an issuance stays refused.
	for _, write := range []struct{ name, url, payload string }{
		{"new order", "https://acme.invalid/new-order", "eyJpZGVudGlmaWVycyI6W119"},
		{"finalize", "https://acme.invalid/finalize", "eyJjc3IiOiJ4In0"},
		{"new account", "https://acme.invalid/new-account", "eyJ0ZXJtcyI6dHJ1ZX0"},
	} {
		req := jwsRequest(t, write.url, write.payload)
		if _, err := transport.RoundTrip(req); !errors.Is(err, ErrNotLeader) {
			t.Errorf("%s: error = %v, want ErrNotLeader", write.name, err)
		}
	}

	if n := base.calls.Load(); n != 2 {
		t.Errorf("the CA saw %d requests, want the leader's order and the read", n)
	}
}

// A node that has not been leader recently does not reach the CA at all, not
// even to read: there is no order of its own left to finish.
func TestACMETransportNonLeaderWithNoOrderInFlightReadsNothing(t *testing.T) {
	base := &countingTransport{resp: refuseAll}
	transport := &acmeTransport{base: base, isLeaderF: always(false), logger: discardLogger()}

	if _, err := transport.RoundTrip(jwsRequest(t, "https://acme.invalid/cert/1", "")); !errors.Is(err, ErrNotLeader) {
		t.Errorf("error = %v, want ErrNotLeader", err)
	}
	if n := base.calls.Load(); n != 0 {
		t.Errorf("the CA saw %d requests from a node with no order in flight", n)
	}
}

package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// certKeyTypes are the key types autocert keeps a separate certificate for.
var certKeyTypes = []string{"ecdsa", "rsa"}

// certHello builds the ClientHello that makes autocert select the certificate of
// the given key type: it picks by what the client can verify, and treats a hello
// offering no ECDSA cipher suite as RSA-only.
func certHello(domain, keyType string) *tls.ClientHelloInfo {
	hello := &tls.ClientHelloInfo{ServerName: strings.ToLower(domain)}
	if keyType == "ecdsa" {
		hello.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	}
	return hello
}

// certCacheKey returns the key autocert stores the certificate under.
func certCacheKey(domain, keyType string) string {
	if keyType == "rsa" {
		return strings.ToLower(domain) + "+rsa"
	}
	return strings.ToLower(domain)
}

// autocertInstance is one autocert.Manager together with the transport that can
// cut it off from the CA.
//
// autocert keeps every certificate it has loaded in memory and offers no way to
// drop one, so making it read the cache again means replacing the whole manager
// (Manager.reload). Its renewal timers cannot be stopped either: a replaced
// manager keeps them for the life of the process. retire is what makes that
// harmless — such a manager can still adopt what it finds in the cache, but it
// can never order.
type autocertInstance struct {
	mgr         *autocert.Manager
	httpHandler http.Handler
	transport   *acmeTransport
}

func (i *autocertInstance) retire() { i.transport.retired.Store(true) }

// newAutocert builds an autocert instance over the given cache.
func (m *Manager) newAutocert(cache autocert.Cache) *autocertInstance {
	transport := &acmeTransport{base: m.acmeBase, isLeaderF: m.isLeaderF, logger: m.logger}
	mgr := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy:  m.hostPolicy,
		Cache:       cache,
		Email:       m.email,
		RenewBefore: m.renewBeforeCfg,
		// All ACME traffic goes through acmeTransport, which is what actually
		// keeps non-leaders from ordering certificates (see its doc comment).
		Client: &acme.Client{
			DirectoryURL: m.directoryURL,
			HTTPClient:   &http.Client{Transport: transport},
		},
	}
	// HTTPHandler is also what enables autocert's http-01 fallback.
	return &autocertInstance{mgr: mgr, httpHandler: mgr.HTTPHandler(nil), transport: transport}
}

// reload replaces the autocert instance with a fresh one, which reads every
// certificate from the cache again. It is the only way to make autocert let go
// of a certificate it holds in memory.
//
// The new instance must first load everything the old one is serving. A cache
// entry that has gone missing or bad would otherwise turn a working certificate
// into a failed handshake; in that case the old instance stays.
func (m *Manager) reload(reason string) error {
	// Serialized: two reloads at once both read the same current instance, and
	// the one that stores second replaces the other's without retiring it -
	// leaving an autocert manager nothing points at, with its renewal timers
	// armed and its ACME transport still live.
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	old := m.current.Load()
	next := m.newAutocert(m.cache)

	// Everything in service has to be loadable from the cache before the swap,
	// checked against the cache directly: asking autocert would order.
	verified := make([]certRecord, 0, len(m.domains)*len(certKeyTypes))
	for _, rec := range m.servedRecords() {
		if time.Now().After(rec.leaf.NotAfter) {
			continue
		}

		leaf, err := m.cachedLeaf(context.Background(), rec.domain, rec.keyType)
		if err != nil {
			next.retire()
			return fmt.Errorf("cache entry for %s (%s) is not loadable, keeping the certificates in memory: %w",
				rec.domain, rec.keyType, err)
		}
		verified = append(verified, certRecord{domain: rec.domain, keyType: rec.keyType, leaf: leaf})
	}

	m.current.Store(next)
	old.retire()

	// What the new instance will load is known already, so the record and the
	// exported expiry follow the swap instead of waiting for the next pass.
	for _, rec := range verified {
		m.recordServed(rec.domain, rec.keyType, rec.leaf)
	}

	m.logger.Info("TLS: certificates reloaded from the cache", "reason", reason)
	return nil
}

// hidingCache reports the hidden keys as missing, so that an autocert instance
// reading through it orders those certificates instead of loading them.
type hidingCache struct {
	autocert.Cache
	hidden map[string]struct{}
}

func (c *hidingCache) Get(ctx context.Context, key string) ([]byte, error) {
	if _, ok := c.hidden[key]; ok {
		return nil, autocert.ErrCacheMiss
	}
	return c.Cache.Get(ctx, key)
}

// RenewCertificate orders a new certificate for a domain and puts it into
// service. Must run on the cluster leader.
//
// keyTypes selects what to order; no argument means both. Both draw on the same
// duplicate-certificate budget, so after a partial failure the operator must be
// able to retry only the key type that was refused - ordering both again spends
// a slot on a certificate issued minutes earlier, which with one slot left is
// the slot the failing key type needed.
//
// The order comes first and nothing is removed up front: a throwaway autocert
// instance that cannot see the current certificate orders the replacement into
// the shared cache while the live instance keeps serving. If the order fails — a
// rate limit, a failed validation — the domain is left exactly as it was.
func (m *Manager) RenewCertificate(domain string, keyTypes ...string) ([]string, error) {
	if m == nil || m.current.Load() == nil {
		return nil, fmt.Errorf("TLS manager not initialized")
	}

	if m.isLeaderF != nil && !m.isLeaderF() {
		return nil, fmt.Errorf("certificate renewal must be performed on the cluster leader node")
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if err := m.hostPolicy(context.Background(), domain); err != nil {
		return nil, fmt.Errorf("domain %q not in allowed list: %w", domain, err)
	}

	keyTypes, err := resolveKeyTypes(keyTypes)
	if err != nil {
		return nil, err
	}

	if !m.renewMu.TryLock() {
		return nil, fmt.Errorf("another certificate renewal is in progress")
	}
	defer m.renewMu.Unlock()

	hidden := make(map[string]struct{}, len(keyTypes))
	for _, keyType := range keyTypes {
		hidden[certCacheKey(domain, keyType)] = struct{}{}
	}
	orderer := m.newAutocert(&hidingCache{Cache: m.cache, hidden: hidden})
	defer orderer.retire()

	var renewed []string
	var errs []error

	for _, keyType := range keyTypes {
		m.logger.Info("TLS: ordering replacement certificate", "domain", domain, "key_type", keyType)

		cert, err := orderer.mgr.GetCertificate(certHello(domain, keyType))
		if err == nil {
			// autocert ignores a failed cache write on this path. A certificate
			// that did not reach the cache is lost at the reload below.
			err = m.verifyCached(domain, keyType, cert)
		}
		if err != nil {
			m.logger.Error("TLS: certificate renewal failed", "domain", domain, "key_type", keyType, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", keyType, err))
			continue
		}

		renewed = append(renewed, fmt.Sprintf("%s (%s, expires %s)",
			domain, keyType, cert.Leaf.NotAfter.UTC().Format(time.RFC3339)))
	}

	if len(renewed) == 0 {
		return nil, errors.Join(errs...)
	}

	if err := m.reload("certificate renewed on request: " + domain); err != nil {
		errs = append(errs, fmt.Errorf("renewed and stored, but not in service yet: %w", err))
	}
	return renewed, errors.Join(errs...)
}

// resolveKeyTypes validates a requested set of key types, defaulting to all.
func resolveKeyTypes(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return certKeyTypes, nil
	}

	for _, keyType := range requested {
		if !slices.Contains(certKeyTypes, keyType) {
			return nil, fmt.Errorf("unknown key type %q, want one of %v", keyType, certKeyTypes)
		}
	}
	return requested, nil
}

// verifyCached checks that the newly issued certificate reached the cache, since
// autocert ignores a failed cache write on this path and the reload that follows
// would lose it.
//
// Anything at least as fresh counts: the live instance's own renewal timer can
// store a newer certificate for the same name while this order is in flight, and
// that satisfies the intent as well as our own bytes would.
func (m *Manager) verifyCached(domain, keyType string, cert *tls.Certificate) error {
	cached, err := m.cachedLeaf(context.Background(), domain, keyType)
	if err != nil {
		return fmt.Errorf("certificate was issued but is not in the cache: %w", err)
	}
	if bytes.Equal(cached.Raw, cert.Certificate[0]) {
		return nil
	}
	if cached.NotAfter.Before(cert.Leaf.NotAfter) {
		return fmt.Errorf("certificate was issued but the cache still holds an older one (expires %s, ordered %s)",
			cached.NotAfter.UTC().Format(time.RFC3339), cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// cachedLeaf returns the leaf of the cache entry for a domain, provided autocert
// would accept the entry: key and leaf belong together, the key type is the
// requested one, and the certificate is valid now, for this name.
func (m *Manager) cachedLeaf(ctx context.Context, domain, keyType string) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	data, err := m.cache.Get(ctx, certCacheKey(domain, keyType))
	if err != nil {
		return nil, err
	}

	leaf, err := parseCacheEntry(data)
	if err != nil {
		return nil, err
	}

	if isRSA := leaf.PublicKeyAlgorithm == x509.RSA; isRSA != (keyType == "rsa") {
		return nil, fmt.Errorf("cache entry holds a %s certificate", leaf.PublicKeyAlgorithm)
	}
	if err := leaf.VerifyHostname(strings.ToLower(domain)); err != nil {
		return nil, err
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("cache entry is not valid now (%s - %s)", leaf.NotBefore, leaf.NotAfter)
	}
	return leaf, nil
}

// parseCacheEntry returns the leaf of an autocert cache entry, accepting exactly
// what autocert's own cacheGet accepts.
//
// The rules matter because this decides whether a reload may go ahead: an entry
// accepted here but refused there swaps in an instance that cannot load the
// certificate, and on the leader that turns into an order which overwrites the
// entry. tls.X509KeyPair alone is laxer - it finds the key and the chain
// anywhere in the buffer, so it accepts `cat fullchain.pem privkey.pem` and
// tolerates trailing bytes, while autocert refuses both.
func parseCacheEntry(data []byte) (*x509.Certificate, error) {
	priv, pub := pem.Decode(data)
	if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
		return nil, errors.New("cache entry does not begin with a private key")
	}

	var chain [][]byte
	for len(pub) > 0 {
		var block *pem.Block
		if block, pub = pem.Decode(pub); block == nil {
			break
		}
		chain = append(chain, block.Bytes)
	}
	if len(pub) > 0 {
		return nil, errors.New("cache entry has trailing data after the certificate chain")
	}
	if len(chain) == 0 {
		return nil, errors.New("cache entry holds no certificate")
	}

	// Confirms the certificate belongs to the key in the same entry.
	if _, err := tls.X509KeyPair(data, data); err != nil {
		return nil, err
	}

	return x509.ParseCertificate(chain[0])
}

// adoptNewerFromCache reloads autocert when the cache holds a newer certificate
// than the one being served and autocert is not going to notice by itself.
//
// autocert reads the cache again only when a certificate's renewal time comes.
// That covers the routine case — the leader renews, the other nodes find the
// result when their own timers fire — but not a certificate replaced early: one
// renewed on request (RenewCertificate runs on the leader only) or put into the
// cache by hand. Without this, every other node would go on serving the old one
// until its renewal time, up to two months away.
func (m *Manager) adoptNewerFromCache() {
	for _, rec := range m.servedRecords() {
		// Inside the renewal window autocert is already polling the cache.
		if time.Until(rec.leaf.NotAfter) <= m.renewBefore {
			continue
		}

		cached, err := m.cachedLeaf(context.Background(), rec.domain, rec.keyType)
		if err != nil || !cached.NotAfter.After(rec.leaf.NotAfter) {
			continue
		}

		reason := fmt.Sprintf("cache holds a newer certificate for %s (%s)", rec.domain, rec.keyType)
		if err := m.reload(reason); err != nil {
			m.logger.Warn("TLS: newer certificate in the cache not adopted",
				"domain", rec.domain, "key_type", rec.keyType, "error", err)
		}
		return
	}
}

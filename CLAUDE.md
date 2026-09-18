# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Mizu is a high-performance, distributed SMTP relay server written in Go that accepts emails via SMTP and synchronously forwards them to a configured HTTP backend. It's designed for production use with comprehensive security, anti-spam features, and distributed coordination.

**Core Principle**: Zero message loss - SMTP `250 OK` is sent ONLY after receiving HTTP `200`/`202` from the backend. No internal message queue; delivery is synchronous.

## Build & Run Commands

```bash
# Build both binaries
make build                    # Builds mizu-server and mizu-admin
make mizu-server             # Build only the server
make mizu-admin              # Build only the admin CLI

# Run tests
make test                    # Run all tests
go test -race ./...          # Run with race detector
go test ./pkg/smtp -run E2E -v  # Run SMTP integration tests

# Generate documentation
make docs                    # Generate package documentation in docs/generated/
make godoc                   # Start godoc server at http://localhost:6060

# Generate example config
./mizu-server generate-config > config.toml.example

# Run server
./mizu-server --config config.toml     # Production mode
./mizu-server --local                  # Local dev mode (no TLS, dumps to terminal)

# Admin CLI operations
./mizu-admin health                    # Check server health
./mizu-admin stats                     # View statistics
./mizu-admin blocked-ips               # List blocked IPs
./mizu-admin flush-cache               # Flush caches
```

## API Documentation

The codebase is fully documented using Go documentation (godoc). View the complete API documentation:

```bash
# Generate documentation files
make docs

# Or start an interactive documentation server
make godoc
# Then visit: http://localhost:6060/pkg/migadu/mizu/
```

Key packages:
- **[pkg/validation](pkg/validation/)**: Email authentication (SPF, DKIM, DMARC, ARC)
- **[pkg/smtp](pkg/smtp/)**: SMTP protocol implementation
- **[pkg/config](pkg/config/)**: Configuration management
- **[pkg/poster](pkg/poster/)**: HTTP delivery and circuit breaker
- **[pkg/cluster](pkg/cluster/)**: Distributed coordination
- **[pkg/stats](pkg/stats/)**: Reputation tracking

## Architecture & Key Concepts

### Multi-Binary Structure

- **`cmd/mizu-server`**: Main SMTP relay server
- **`cmd/mizu-admin`**: CLI tool for operational tasks (health checks, stats viewing)

### Core Components

1. **SMTP Server** ([pkg/smtp/](pkg/smtp/))
   - `Backend`: Main server implementation, creates sessions
   - `Session`: Per-connection handler with complete email validation pipeline
   - Entry point: `Backend.NewSession()` → creates `Session` for each connection
   - Message flow: Connection → rDNS → DNSBL → SPF/DKIM/DMARC/ARC → Header validation → HTTP POST to backend
   - **Debug logging**: Enable per-server with `debug = true` in `[server]` section to see all SMTP protocol commands and responses

2. **Distributed Coordination** ([pkg/cluster/](pkg/cluster/))
   - Uses **hashicorp/memberlist** for P2P gossip protocol
   - Supports leader election for TLS certificate management
   - **A node elects nobody until its membership is confirmed**
     (`membershipConfirmed`, [pkg/cluster/memberlist.go](pkg/cluster/memberlist.go)).
     The leader is the smallest node name, and a node that has not reached its
     peers is the only name it knows — it would elect itself. With peers
     configured, `IsLeader()` is false and `GetLeader()` is `""` until another
     member is seen, or until `LeaderGracePeriod` (1 min) passes with no peer
     reachable, so a genuinely lone node can still renew certificates.
   - **memberlist never retries a join.** `rejoinLoop` retries every 15s while
     the node is alone. Without it, nodes restarted at the same moment (an
     ansible deploy) each miss the other's listener and stay one-member
     clusters — each one leader — until the next restart.
   - Shares connection state and rate limits across cluster nodes
   - Message types: `MessageTypeConnectionState`, `MessageTypeRateLimit`

3. **SMTP Authentication** ([pkg/smtp/auth.go](pkg/smtp/auth.go))
   - `HTTPAuthenticator`: HTTP-based authentication for submission servers (ports 587/465)
   - Supports AUTH PLAIN and AUTH LOGIN mechanisms (LOGIN via custom implementation)
   - Requires TLS before authentication (except in local mode)
   - 5-minute authentication cache to reduce API calls
   - Validates that authenticated users can only send from authorized addresses
   - Adds `X-Auth-User` header to delivery for authenticated messages
   - `AuthRateLimiter` ([pkg/smtp/auth_rate_limiter.go](pkg/smtp/auth_rate_limiter.go)) blocks brute force in three tiers, configured under `[server.auth.rate_limit]`:
     - Tier 1 (IP+username), Tier 2 (IP-only), Tier 3 (subnet, [pkg/smtp/auth_subnet.go](pkg/smtp/auth_subnet.go))
     - Tier 3 catches attackers rotating through sibling IPs, which never accumulate under tiers 1-2. It triggers on **breadth** (distinct failing addresses in a subnet: `subnet_max_distinct_ips`, default 8), not volume, so a shared NAT does not qualify. IPv4 groups by /24, IPv6 counts distinct /64s inside a /48
     - Every tier keys IPv6 by /64 (`bucketIP`), otherwise one allocation supplies 2^64 free identities
     - Refusals are 454 (temporary), an address that logged in successfully within `success_exempt_duration` (default 24h) bypasses subnet blocks, and private/loopback/`subnet_exempt` ranges are never blocked
     - Lift a subnet block with `./mizu-admin unblock-ip 203.0.113.0/24` (CIDR form); blocks and unblocks propagate over cluster gossip

4. **Connection Tracking & DoS Protection** ([pkg/smtp/](pkg/smtp/))
   - `ConnectionTracker`: Local per-IP and global connection limits
   - `DistributedTracker`: Cluster-wide connection tracking via gossip + S3 sync
   - `RateLimiter`: Multi-dimensional rate limiting (IP, FROM, FROM_DOMAIN, TO, TO_DOMAIN, AUTHENTICATED_USER) with optional gossip

5. **Reputation & Stats** ([pkg/stats/](pkg/stats/))
   - `Manager`: Tracks IP and domain reputation scores
   - Event-driven architecture with async processing (ring buffer, worker goroutines)
   - Syncs reputation data across cluster via S3
   - LRU-based eviction for memory efficiency (configurable max entries)

6. **Synchronous Delivery with Circuit Breaker** ([pkg/poster/](pkg/poster/))
   - **Retry logic**: Exponential backoff (1s, 2s, 4s...) with configurable max attempts
   - **Circuit breaker**: Protects backend WITHOUT blocking retries
     - Circuit breaker wraps **each individual retry attempt**, not the entire retry loop
     - States: Closed → Open → HalfOpen
     - When open: Returns `ErrCircuitOpen` (marked as retryable), so retries continue
   - **Zero message loss**: SMTP `250 OK` only after successful HTTP delivery
   - **Sender MTA retries**: If all attempts fail, sender's MTA retries for 24-48 hours (RFC 5321)

7. **TLS Certificate Management** ([pkg/tls/](pkg/tls/))
   - `Manager`: Handles autocert with Let's Encrypt (TLS-ALPN-01 and HTTP-01 challenges)
   - Distributed mode: Only cluster leader obtains certificates, stores in S3
   - Uses S3 for certificate storage across instances
   - Alternative: certmagic library for on-demand certificates
   - **The leader gate is the ACME HTTP transport** (`acmeTransport`,
     [pkg/tls/acme_transport.go](pkg/tls/acme_transport.go)), not the cache.
     autocert orders a certificate *first* and writes the cache *afterwards*, so
     refusing cache writes (`ClusterAwareCache`, kept as a backstop) cannot stop
     a non-leader ordering: it obtains a cert, fails to store it, and retries
     every 30-60 min. That loop burned Let's Encrypt's 5-per-week duplicate
     limit and let every certificate expire (2026-09-17). A non-leader now gets
     `ErrNotLeader` before any request leaves the node. The same transport logs
     every ACME error response *and* 200s carrying `"status":"invalid"` — a
     failed validation is not an HTTP error, and autocert retries silently, so
     this is the only place a 429 or a failed challenge shows up.
     One exemption: a node demoted **while an order is in flight** may still make
     ACME *reads* (POST-as-GET, RFC 8555 §6.3) for `acmeOrderGrace`. Issuance
     happens at finalize and the download that follows is a read, so refusing it
     strands a certificate the CA has already charged to the weekly limit and
     autocert drops it rather than retrying. Reads cannot cause an issuance;
     writes stay refused, and a node that has not been leader within the grace
     does not reach the CA at all.
   - **S3 is the source of truth; never read the local dir first**
     (`FallbackCache`, [pkg/tls/fallback_cache.go](pkg/tls/fallback_cache.go)).
     Every node holds a local copy of every cert it has served, so a local-first
     read never sees the leader's renewal. Challenge keys (`+token`, `+http-01`)
     never touch the local dir: a leftover outlives its 24h validity and shadows
     the token of the next order during cross-node validation.
   - **Keep S3's three answers apart.** "Here it is" and "I don't have it" are
     authoritative; **"I couldn't be reached" is not, and must never surface as
     `autocert.ErrCacheMiss`** — autocert reads a miss as proof no certificate
     exists and orders one, so an outage would have the leader re-order
     everything sitting in the bucket (and generate a fresh ACME account key).
     That path returns `ErrStorageUnavailable`, after trying the local copy.
     Challenge responses are the exception in both directions: they live only in
     S3, so a Get and a Put for one ignore the breaker entirely — refusing either
     fails the validation outright and spends the CA's hourly allowance.
     A cert *absent* from S3 but held locally is served and re-seeded into S3:
     otherwise an entry lost from the bucket (`tls delete`, a lifecycle rule, a
     changed prefix) takes every restarted node down for that domain for up to
     60 days, since the leader serves from memory and never learns to re-issue.
   - **A local copy written during an outage is the only copy of that key pair.**
     Markers under `<cache_dir>/.pending` record it, so a restart cannot put S3's
     older copy back over it; a marker that outlived its certificate cannot
     overwrite a newer one in S3 (`supersededInS3`), and one whose certificate is
     gone falls through to S3 rather than reporting a miss.
     **No lock is ever held across an S3 call.** autocert holds one global mutex
     across `Cache.Get`, so anything a read waits for, every handshake waits for;
     the pending sync round-trips outside the lock and uses `localSeq` to tell
     whether the copy it uploaded is still current.
   - **Read timeouts are sized by what waiting can win**: 1s when a servable
     local copy is in hand, 5s when there is nothing to serve. autocert holds one
     global mutex across `Cache.Get`, so a slow read stalls every handshake.
     A caller's own cancellation (autocert passes the http-01 request's context)
     is not an outage — otherwise any client could open the breaker by
     disconnecting — and challenge Puts ignore the breaker entirely.
   - **No directory sweep to S3.** Only keys this process failed to write during
     an S3 outage are pushed later (`SyncPendingToS3`). A local file says nothing
     about being newer than S3; the former startup sync let a restarted node
     overwrite renewed certificates with stale ones.
   - **The leader maintains every configured domain, both key types**
     (`maintainCertificates`, hourly, first run delayed 2 min for the cluster to
     converge). autocert only renews what it has loaded, and only loads what it
     is asked for in a handshake — a sibling node's hostname never reaches the
     leader. Non-leaders pick certs up from S3: on a handshake once the failed
     state clears (1 min), or when their own renewal timer re-reads the cache.
   - **autocert cannot drop a loaded certificate or stop its timers**, so the
     only reset is replacing the whole `autocert.Manager`
     (`Manager.reload`, [pkg/tls/renewal.go](pkg/tls/renewal.go)). The replaced
     instance is *retired* (its `acmeTransport` refuses everything): its renewal
     timers live on for the life of the process and must never order. `reload`
     first makes the new instance load everything the old one serves, and keeps
     the old one if the cache cannot supply it. It is serialized (`reloadMu`):
     two at once orphan an instance that is never retired, timers still armed.
   - **Only the leader goes through autocert to load a certificate**
     (`currentLeaf`). Elsewhere `GetCertificate` cannot order, and the refusal
     is not free: autocert keeps the failed attempt for a minute and answers
     every handshake for that name from it *without reading the cache*, so a
     certificate the leader publishes meanwhile is ignored — and it costs an RSA
     keygen per domain per pass. A non-leader reads the cache instead.
   - **Never ask autocert what it is serving.** `GetCertificate` *orders* when it
     has nothing, so on the leader a question becomes an ACME order. `reload` and
     `adoptNewerFromCache` read `Manager.served` (recorded by the handshake path
     and the maintenance walk) and verify against the cache with `cachedLeaf`,
     which accepts exactly what autocert's `cacheGet` accepts — key first,
     nothing trailing the chain. `tls.X509KeyPair` is laxer and would pass a
     hand-placed `cat fullchain.pem privkey.pem` entry that autocert then
     refuses, making the leader re-order and overwrite it. It parses the *whole*
     chain, as autocert's `validCert` does — a corrupt intermediate is enough.
   - **Cache keys are punycode** (`asciiDomain`). autocert runs
     `idna.Lookup.ToASCII` before building a cache key, so a Unicode domain in
     `letsencrypt.domains` is filed as `xn--…`; reading it back under the Unicode
     spelling finds nothing and every swap, adoption and metric label misses.
   - **An expired certificate is not "in service" for reload's purposes.**
     autocert never re-checks what it already holds, so it goes on serving an
     expired certificate while refusing to load one from the cache; counting it
     blocked every reload in exactly the state this branch addresses.
   - **`renew-cert` orders first, replaces after** (`RenewCertificate`). A
     throwaway instance behind a `hidingCache` orders into the shared cache while
     the live instance keeps serving; only then `reload`. Never delete the cache
     entry up front — a failed order (rate limit) would leave the domain with no
     certificate. The call is synchronous: `/api/renew-cert` extends its write
     deadline to 11 min and `mizu-admin` its client timeout, so the operator
     gets the CA's actual answer. Leader only.
     Takes a key type (`--key-type rsa`, `key_type` in the request): both draw on
     the *same* duplicate-certificate budget, so retrying a partial failure must
     not re-order the key type that already succeeded. It also takes a
     `context.Context` (the handler passes `r.Context()`), so an operator who
     gives up does not leave the remaining key types being ordered behind them;
     an order already in flight is allowed to finish, since abandoning one after
     issuance wastes it — and its result is verified with `context.WithoutCancel`,
     because validating it against the dead context would throw away exactly what
     finishing the order was protecting. The handler extends the **read** deadline
     as well as the write one: `ReadTimeout` otherwise bounds the whole request
     once anything reads from the connection.
     `mizu-admin tls delete` is **not** a way to force renewal — the local copy
     re-seeds S3. Use `renew-cert`.
   - **Certs replaced early reach other nodes via `adoptNewerFromCache`**
     (hourly maintenance tick, every node). autocert re-reads the cache only at
     a cert's renewal time, so a forced renewal or a hand-placed S3 entry would
     otherwise be ignored for up to two months. It reloads only when the served
     cert is *outside* its renewal window — inside it autocert polls the cache
     itself, and reloading there would replace the instance on every routine
     renewal.
   - **`mizu_tls_cert_expiry_seconds{domain,key_type}`** is set from the same
     maintenance walk, on *every* node (the ordering half is leader-only; the
     walk is not). The value is the Unix expiry of the certificate that node
     would actually hand out — no extra probing — or `0` when it has none.
     Labelled by key type because the ECDSA and RSA certificates of one domain
     expire at different times (nine days apart in production); `min by (domain)`
     collapses them. An expired *cache* entry also reads as 0, since autocert
     refuses to load one (`validCert`), while an expired certificate already in
     autocert's memory reports its real past expiry — so never write the alert
     as `expiry > 0 and expiry - time() < N`. The record is also updated on the
     handshake path and by `reload`, so the gauge follows a forced renewal
     instead of lagging an hour; a pass that leaves anything missing repeats in
     5 min rather than 60.
   - `ClusterAwareCache.Put` lets a non-leader store a **certificate** (it was
     entitled to order it; see the transport's grace above) but never the ACME
     account key or a challenge response — autocert writes the account key
     *before* it registers, so this is all that stops a node coming up against an
     empty bucket from putting its own key over the leader's.
   - **Known limitation: a replaced autocert instance leaks.** `stopRenew` is
     unexported and nothing reachable calls it, so a reload's renewal timers live
     until the process ends. They cannot order (the transport is retired) and
     settle into one cache read per certificate per renewal period, so the cost
     is bounded by how often reload runs — which is why a steady state must never
     reload (`TestMaintenanceDoesNotAccumulateAutocertInstances`).
   - Recovery when issued certs were lost: autocert's renewal reuses the private
     key, so a discarded cert is rebuildable from the CT logs (crt.sh) plus the
     key in the old cache entry — [scripts/recover-cert.sh](scripts/recover-cert.sh).

8. **Email Validation** ([pkg/validation/](pkg/validation/))
   - SPF validation (checks sender IP authorization)
   - DKIM validation (verifies email signature)
   - DMARC validation (checks alignment + policy enforcement)
   - ARC validation and signing (Authenticated Received Chain - preserves authentication through forwarding)
   - MX record validation for sender domains:
     - Checks if sender domain can receive mail (MX records, or A/AAAA fallback per RFC 5321)
     - Validates sender can receive bounce messages and replies
     - **Public Suffix List (PSL) validation**: Conservative approach prevents false positives from outdated PSL
       - Always rejects: RFC-defined invalid TLDs (`.local`, `.internal`, `.localhost`, `.invalid`, `.test`, `.example`, `.onion`)
       - Always rejects: Bare TLDs (`com`, `co.uk`)
       - Safe with outdated PSL: Unknown TLDs pass through to DNS check
     - Blocks reserved/test domains: `localhost`, `example.com`, `example.org`, `example.net`, `test.com`, `test`, `invalid` (per RFC 2606)
     - Multi-layer validation: blacklist → PSL (conservative) → DNS (MX/A/AAAA)

9. **Message Header Validation & Fixing** ([pkg/smtp/headers.go](pkg/smtp/headers.go))
   - Configurable handling of missing Message-ID and Date headers via `[server.validation]`
   - Three actions: `"reject"` (submission default), `"fix"` (relay default), `"none"`
   - Automatic header generation: RFC-compliant Date timestamps and unique Message-IDs
   - Case-insensitive header detection

### Configuration System

- TOML-based configuration ([pkg/config/](pkg/config/))
- `Config` struct in [pkg/config/types.go](pkg/config/types.go) defines all settings
- Environment variables supported for secrets: `DESTINATION_AUTH_TOKEN`, `DELIVERY_AUTH_TOKEN`, `AUTH_TOKEN`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `HEALTH_PASSWORD`, `CLUSTER_SECRET_KEY`
- Default values defined in `DefaultConfig()`

**Message Validation Configuration:**
- `[server.validation]` section controls header validation behavior
- `missing_headers_action`: "reject" | "fix" | "none"
  - **"reject"** (default for submission): Reject emails missing Date or Message-ID headers
  - **"fix"** (default for relay): Add missing headers before forwarding
  - **"none"**: Allow through without modification
- `allow_null_sender`: Allow bounce messages with null sender `<>` (typically false for submission, true for relay)

**Injected Headers Configuration:**
- Per-server `[[server]]` toggles for the X-Mizu-* headers added before
  delivery (each defaults to true; the `Received` header — which carries the
  trace ID as its `id` token — is always added regardless):
  - `enable_trace_id_header`: `X-Mizu-Trace-ID`
  - `enable_auth_results_header`: `X-Mizu-Authentication-Results` — mailqueuer
    parses this header at ingest for the ledger's auth verdicts; disabling it
    means empty verdicts on `ingested` rows
  - `enable_junk_header`: `X-Mizu-Junk` — governs only this header;
    `junk.apply_action` adds its own marker (e.g. `X-Spam`) independently, and
    rspamd's forwarded `add_headers` (X-Migadu-*) bypass these toggles entirely
- Replaced the former all-or-nothing `disable_mizu_headers` (forward-only, no
  fallback). Unknown/stale config keys produce a startup stderr warning
  (`warnUndecodedKeys` in [pkg/config/loader.go](pkg/config/loader.go))

**Received header privacy (`strip_client_identity`):**
- Per-server `[[server]]` `*bool` that omits the `from <HELO> (<client IP>)`
  clause from the `Received` header this server stamps, yielding
  `Received: by <host> with ESMTPS id <trace>;`. The trace ID is retained so
  hops stay correlatable with our own logs; a deliberate deviation from
  RFC 5321 §4.4, which recommends recording the source.
- Defaults to **true on submission**, **false on relay**: on submission the HELO
  name and client IP identify the end user's machine and home/mobile network,
  and stamping them publishes that to every recipient; on relay the full trace
  is kept because downstream receivers use it for SPF/DMARC forensics and loop
  detection. Set explicitly to override either default.
- Resolved by `ServerConfig.StripsClientIdentity()` and materialized in
  `ApplyDefaults`; threaded into `buildReceivedHeader` via `InjectMizuHeaders`
  ([pkg/smtp/headers.go](pkg/smtp/headers.go)). Independent of the X-Mizu-*
  toggles above — it governs only the `Received` `from` clause.

**Authentication Configuration (for submission servers):**
- `[server.auth]` section configures SMTP AUTH for ports 587/465
- `enabled`: Enable SMTP AUTH (advertise AUTH in EHLO response)
- `required`: Require authentication before MAIL FROM (implies enabled=true)
- `url`: HTTPS endpoint for authentication (must use https://)
- `auth_token`: Bearer token for authentication API (supports env var: `${AUTH_TOKEN}`)
- Authentication API contract (GET request with URL interpolation):
  ```
  GET /api/users/{email}?ip={ip}
  Authorization: Bearer {auth_token}

  // Response (user found)
  {
    "identity": "user@example.com",                   // Address this login acts as (optional; see Master access)
    "password_hashes": ["$2a$10$...", "$2a$10$..."],  // Array of password hashes (bcrypt, SSHA512, SHA512)
    "allowed_from": ["user@example.com", "alias@example.com", "*@team.example.com", "/^user\\+.*@example.com/"]
  }

  // Response (user not found)
  404 Not Found

  // Response (user denied submission — e.g. rcptd deny_smtp list)
  403 Forbidden
  ```
- Auth-backend status semantics: **200** = verify the returned hashes locally;
  **404** = user unknown (AUTH rejected, the only permanent failure);
  **403** = user denied submission (AUTH rejected, but temporary — the account
  exists and the deny can be lifted); any other status = backend error
- AUTH failures map to two SMTP replies. The dividing line is whether the
  **account exists**, not whether the credential was correct:
  - **535 5.7.8 (permanent)** — backend 404 only. The address is not in the
    table, so no retry can ever make it work and the client should say so.
  - **454 4.7.0 (temporary)** — *everything else that fails*: wrong password,
    an unusable/corrupt stored hash, a 200 carrying no hashes, a 403 denied
    account, and any backend 5xx/timeout. Each of these can start working with
    no change by the client, so a permanent reply would make clients discard a
    password that is about to be valid again.
  - The mechanism is `Authenticator.Authenticate`'s return pair
    ([pkg/smtp/server.go](pkg/smtp/server.go)): `(false, nil)` is the *only*
    permanent verdict. `fetchCredentials` returns the `errUserUnknown` sentinel
    for a 404 and an ordinary error for everything else; the two call sites in
    `AuthenticateWithIP` translate that sentinel into `(false, nil)` —
    **change one and you must change the other** (the second is the
    credentials-cache refetch branch, live only when `auth.cache.enabled=false`).
  - **Never key this decision off `len(PasswordHashes) == 0`.** An empty hash
    list arrives for a 404, a 403, *and* a 200 for an account with no credential
    set — three cases with two different verdicts. Use the HTTP status.
  - `auth_session.go` checks the error **first**, so an implementation that
    signals a rejection with an error can only ever be too lenient, never too
    harsh.
  - Known trade-off: 535 vs 454 is a mailbox-enumeration oracle on the
    submission port, accepted so clients can distinguish "no such address" from
    "server down". The `AuthRateLimiter` tiers bound the probing.
- `allowed_from` entries may be exact addresses, `*@domain` wildcards, or
  `/regex/` patterns (rcptd's regex_sender_login pass-through, matched
  case-insensitively against MAIL FROM with substring semantics like Postfix pcre)
- **Master access (`user@domain@SUFFIX` logins).** Sora accepts support logins
  where a suffix after a second `@` is a master username or remotelookup token
  (`sora/server/address.go`). The suffix names the *credential*; the address it
  acts as is the base address, which rcptd resolves and returns as `identity`.
  Mizu never derives it — an absent or empty `identity` means no rewrite, so a
  backend that does not serve the field behaves exactly as before.
  - `ResolveSender` ([pkg/smtp/auth.go](pkg/smtp/auth.go)) authorizes a MAIL
    FROM and returns the address to send as. A FROM equal to the login string
    resolves to `identity`; every other FROM is authorized as sent, so a master
    credential cannot send as a third party — the resolved address still has to
    pass `allowed_from`. `CanSendAs` is now a wrapper over it.
  - `Session.Mail` applies the resolution to the envelope *before* anything
    downstream reads the sender, so stats, rate limiting, the spam check and the
    envelope handed to mailqueuer all carry the identity rather than a login
    string whose "domain" is the master username.
  - `SenderIdentity` answers "is this session acting as someone else" from the
    credentials cache only (never a refetch — `Session.Mail` asks on every
    message). `Data` then calls `rewriteFromHeader`
    ([pkg/smtp/headers.go](pkg/smtp/headers.go)) when — and only when — the
    session has an identity and the `From` header holds exactly the login
    string. Deliberately independent of the envelope decision: a client that
    put the base address in MAIL FROM but the login in `From` must still have
    the header fixed.
    The display name is kept: `Support <user@dom@TOKEN>` → `Support <user@dom>`.
    Clients that prefill their compose form from the login string (Sora's
    webmail does) would otherwise publish the master username to every
    recipient and leave `From` unparseable for DMARC alignment.
  - Mizu only *verifies* DKIM; Strela signs, so the rewrite lands before the
    signature.
  - With an empty `allowed_from`, the fallback compares MAIL FROM against the
    **identity**, never the raw login — a suffixed login is not an address.
- Password verification happens **locally** (never send passwords over network)
- Supports multiple password hashes per user (tries all until one matches)
- URL supports `$email` and `$ip` placeholders for interpolation
- Authenticated messages include `X-Auth-User` header in delivery to backend
- Rate limiting supports `AUTHENTICATED_USER` dimension for per-user limits

**Recipient Validation Configuration:**
- `[server.recipient_validation]` section enables validation during RCPT TO phase
- `enabled`: Enable recipient validation before accepting message body
- `url`: HTTPS GET endpoint with URL interpolation (supports `$ip`, `$ptr`, `$helo`, `$from`, `$email`)
- `auth_token`: Bearer token for validation API
- HTTP status code semantics:
  - **200 OK**: Recipient accepted (optional JSON body with `message` field)
  - **404 Not Found**: User unknown (reject with "User unknown")
  - **403 Forbidden**: Delivery not authorized (sender blocked by recipient)
  - **450**: Temporary failure with custom message (SMTP 4xx - retry later)
  - **429 Too Many Requests**: Rate limit exceeded (temporary failure)
  - **502/503/504**: Temporary backend failures (retry later)
- Response body can be JSON `{"message": "custom text"}` or plain text
- For 450 status code, response body can include JSON `{"message": "custom text", "temporary": true}` to provide custom message for temporary failure
- Successful validations cached for 5 minutes (configurable)
- Provides early rejection before DATA phase, reducing bandwidth and processing

**DNS Checks Configuration:**
- `[server.dns_checks]` section controls connection-time DNS validation
- `require_rdns`: Reject connections whose IP has no PTR (reverse DNS) record
- `rdns_whitelist_ips`: IPs/CIDRs exempt from `require_rdns` (e.g., `["1.2.3.4", "10.0.0.0/8"]` for monitoring probes or internal hosts)
  - Exempts only the rDNS requirement — reputation checks still apply (use `reputation.whitelist_ips` to bypass those)
  - Entries are validated at startup; invalid IPs/CIDRs fail config validation
  - Sessions admitted without a PTR record interpolate `$ptr` as an empty string in sender/recipient validation URLs
- `require_sender_mx`: Require sender domain to have MX records
- `require_resolvable_helo`: Require HELO hostname to have DNS records

### Storage Backend Configuration

Mizu supports two storage backends for TLS certificates and stats synchronization:

1. **S3 (default)** - For production clusters
   ```toml
   [storage]
   backend = "s3"
   s3_endpoint = "s3.amazonaws.com"
   s3_bucket = "mizu-storage"
   s3_prefix = "certs/"
   s3_access_key = "..." # Or via S3_ACCESS_KEY env var
   s3_secret_key = "..." # Or via S3_SECRET_KEY env var
   s3_region = "us-east-1"
   ```

2. **Filesystem** - For single-node deployments
   ```toml
   [storage]
   backend = "filesystem"
   filesystem_path = "/var/lib/mizu/storage"
   ```

**When to use filesystem backend:**
- Single-node deployments without clustering
- Development/testing environments
- Scenarios where S3 is not available or desired
- Lower operational complexity

**Implementation:** [pkg/storage/](pkg/storage/) provides a `Backend` interface with both `S3Backend` and `FilesystemBackend` implementations

### Distributed Features Require Cluster Mode

Several features require `cluster.enabled=true`:
- Distributed connection tracking (`smtp.distributed.enabled`)
- Rate limit gossip (`smtp.rate_limit.gossip_enabled`)
- TLS autocert with leader election
- Reputation stats sync (uses S3 + memberlist)

## Testing Patterns

- **Unit tests**: Standard Go tests in `*_test.go` files
- **Integration tests**: E2E tests in `pkg/smtp/*_e2e_test.go` (use `-run E2E` to run)
- **Benchmarks**: DNS and rate limiter benchmarks exist
- **Mock testing**: Uses interfaces for testability (e.g., `poster.HTTPClient`)

### Manual SMTP Testing

```bash
# Start server in local mode
./mizu-server --local &

# Test with telnet
telnet localhost 25
> EHLO test.local
> MAIL FROM:<sender@example.com>
> RCPT TO:<recipient@example.com>
> DATA
> Subject: Test
>
> This is a test.
> .
> QUIT
```

## Important Implementation Details

### Panic Recovery & Graceful Shutdown

- **ALL goroutines MUST use `logging.SafeGo()`** ([pkg/logging/recovery.go](pkg/logging/recovery.go))
  - Prevents WaitGroup leaks on panics
  - Logs stack traces
  - Example: `logging.SafeGo(logger, "goroutine-name", func() { ... })`

- **Graceful shutdown** ([cmd/mizu-server/main.go](cmd/mizu-server/main.go:655-698)):
  1. Stop accepting new connections (close `ShutdownChan`, close listener)
  2. Wait for active sessions with timeout (`ActiveSessionsWg`)
  3. Stop stats manager
  4. Stop health server

### DNS Resolution

- Custom DNS resolvers supported via `dns.resolvers` config
- Round-robin + failover + caching implemented in [pkg/dns/resolver.go](pkg/dns/resolver.go)
- Default uses OS resolver
- Caching wrapper: [pkg/dns/caching_wrapper.go](pkg/dns/caching_wrapper.go)

### Stats System Architecture

- **Event-driven**: Components emit events → ring buffer → async workers → stats manager
- **Vector clocks** ([pkg/cluster/vectorclock.go](pkg/cluster/vectorclock.go)) for distributed state merging
- **S3 export/import** for cross-cluster synchronization
- **LRU eviction** when limits exceeded

### Rate Limiting

- Multi-dimensional: Can combine keys (IP, FROM, FROM_DOMAIN, TO, TO_DOMAIN, AUTHENTICATED_USER)
- Sliding window algorithm
- Gossip-based cluster-wide enforcement (optional)
- Whitelist support: IPs, domains, and senders can be exempted from ALL rate limit dimensions
  - `whitelisted_ips`: IPs/CIDRs bypass rate limits (e.g., ["1.2.3.4", "10.0.0.0/8"])
  - `whitelisted_domains`: Entire sender domains bypass rate limits (e.g., ["trusted.com"])
  - `whitelisted_senders`: Specific sender addresses bypass rate limits (e.g., ["admin@example.com"])
  - Case-insensitive matching (domains/senders)
  - **External files + hot reload**: each kind also accepts a file path — `whitelisted_ips_file`,
    `whitelisted_domains_file`, `whitelisted_senders_file` (one entry per line; blank lines and
    `#` comments ignored). File entries are unioned with the inline arrays and re-read
    automatically when the file changes on disk (`whitelist_reload_interval_seconds`, default 10).
    A missing/unreadable file logs a warning and is treated as empty until it appears.
    Implementation: [pkg/smtp/rate_limit_whitelist.go](pkg/smtp/rate_limit_whitelist.go) (atomic snapshot swap, lock-free read path)
- Configured via `smtp.rate_limit.dimensions` array

## Workflow Orchestration

### 1. Plan Node Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy
- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update tasks/lessons.md with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests - then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

### 7. Git Command Usage
- **ALWAYS** use `--no-pager` flag with git commands that may trigger a pager
- This prevents commands from blocking while waiting for pager interaction
- Examples:
  - `git --no-pager diff`
  - `git --no-pager log`
  - `git --no-pager show`
  - `git --no-pager status` (if verbose output expected)
- Alternative: Set `GIT_PAGER=cat` environment variable for the command
- **NEVER** commit alone - always ask user first before creating commits
- **NEVER** use `git push --force` or `git push -f` - always ask user for permission first
- Force push to main/master branches is especially dangerous and should always be explicitly confirmed

## Task Management

1. **Plan First**: Write plan to tasks/todo.md with checkable items
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add review section to tasks/todo.md
6. **Capture Lessons**: Update tasks/lessons.md after corrections

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.

## Development Workflow

1. **Making changes to core SMTP logic**: Edit [pkg/smtp/server.go](pkg/smtp/server.go), run E2E tests
2. **Adding new configuration options**:
   - Add field to appropriate struct in [pkg/config/types.go](pkg/config/types.go) (e.g., `ServerConfig`, `ServerValidationConfig`)
   - Update `DefaultConfig()` with sensible default if applicable
   - Add validation in `ServerConfig.Validate()` or `Config.Validate()` if the field has restricted values
   - Update [config.toml.example](config.toml.example) with examples and documentation
3. **Modifying validation logic**: Edit files in [pkg/validation/](pkg/validation/)
4. **Cluster/gossip changes**: Work in [pkg/cluster/](pkg/cluster/)
5. **Adding metrics**: Use prometheus client from [pkg/metrics/](pkg/metrics/)

## Code Change Policy

**IMPORTANT: Always make forward-only changes. Never implement backward compatibility or deprecated code paths.**

When refactoring or changing configuration structure:
- **DO**: Make clean, forward-only changes that require users to update their configuration
- **DO**: Remove old code paths and configuration options entirely
- **DO NOT**: Add "fallback to old config" logic or "deprecated but still supported" code paths
- **DO NOT**: Keep deprecated configuration options "for backward compatibility"
- **DO NOT**: Add comments like "DEPRECATED" or "legacy support"

Example of what NOT to do:
```go
// BAD - Don't do this
deliveryCfg := serverCfg.Delivery
if deliveryCfg.URL == "" {
    // Fallback to global for backward compatibility
    deliveryCfg = globalCfg.Delivery
}
```

Example of what TO do:
```go
// GOOD - Forward-only
deliveryCfg := serverCfg.Delivery
```

**Rationale**: Backward compatibility code adds complexity, increases maintenance burden, and delays adoption of better designs. Breaking changes with clear migration paths are preferable to maintaining legacy code paths indefinitely.

## Common Gotchas

1. **Distributed features require cluster mode**: Always check `cluster.enabled` before enabling distributed features
2. **Graceful shutdown timeout**: Default 60s, configurable via `smtp.shutdown_timeout_seconds`
3. **S3 is required for production**: Used for certs AND stats sync (if enabled)
4. **TLS minimum version**: Only TLS 1.2 and 1.3 supported (1.0/1.1 deprecated)
5. **Autocert leader election**: Only works with cluster mode enabled
6. **Rate limit dimensions**: Must specify at least one dimension if rate limiting enabled
7. **No internal queue**: Mizu is a synchronous relay - SMTP transaction completes ONLY after backend delivery succeeds or all retries exhausted
8. **Message loss prevention**: Relies on sender MTA retry window (24-48 hours) and backend high availability - no persistent queue

## Module Information

- Module path: `migadu/mizu`
- Go version: 1.25.0
- Key dependencies:
  - `emersion/go-smtp` - SMTP protocol implementation, replaced with the
    `github.com/migadu/go-smtp` fork in go.mod (relay-specific behavior:
    no line-length limit during DATA, session re-creation on re-EHLO,
    STARTTLS hardening)
  - `emersion/go-message` - message parsing, replaced with the
    `github.com/migadu/go-message` fork in go.mod (currently identical to
    upstream; pinned for org ownership). Note: `go get -u` does not update
    replaced modules - bump the fork pins in go.mod manually.
  - `emersion/go-msgauth` - SPF/DKIM/DMARC validation
  - `hashicorp/memberlist` - Distributed cluster coordination
  - `aws/aws-sdk-go-v2` - S3 client (certs and stats sync)
  - `prometheus/client_golang` - Metrics
  - `github.com/migadu/passwd` (local module, `replace github.com/migadu/passwd
    => ../passwd`) - password hash verification, shared with rcptd/rcptctl and
    calserver. Building mizu requires the sibling `../passwd` checkout from the
    ansible-freebsd3 tree; the Ansible build task provides it next to the clone
    in `.compile/`. (This and `github.com/migadu/emailutil` replaced the former
    single `shared` module, now split into one module per package.)

## Version Information

Build-time version injection via linker flags in Makefile:
- `VERSION`, `COMMIT`, `DATE` variables set in both `cmd/mizu-server/main.go` and `cmd/mizu-admin/main.go`
- Access via: `./mizu-server --version` or `./mizu-admin --version`

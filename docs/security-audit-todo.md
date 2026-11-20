# Security audit — fix list

Audit of 2026-11-19 on branch `cluster-rejoin`. Every item below was checked
against the code. "Reproduced" means a reviewer ran a throwaway test that
showed the behaviour; the rest are confirmed by reading only.

Workflow per item: add a failing test, build the fix, see the test pass.
A ticked box means the fix and its test are in the working tree (uncommitted);
"→" lines say what was done. Every new test is named `TestAudit_*` (plus
`TestClient_Check_ControlBytesInEnvelopeDoNotAbortScan`) and was seen failing
before its fix.

## A. Live in the deployed configuration

- [x] **A1 (high) rspamd skipped by a control byte in EHLO.**
  `validateHeloHostname` (`pkg/smtp/server.go:963`) rejects only space, tab,
  CR, LF, NUL; HELO becomes an HTTP header in `pkg/spamcheck/rspamd.go:309`;
  Go refuses to send the request and `server.go:1861` fails open. Reproduced.
  Fix: reject any non-printable / non-ASCII byte in HELO regardless of the
  `helo_validation` toggle, and make the rspamd client drop characters that
  are illegal in a header value so no envelope value can abort the request.
  → Fixed: `rejectHeloControlBytes` runs on every server type; `headerValue` in the rspamd client. Tests: `pkg/smtp/helo_audit_test.go`, `pkg/spamcheck/rspamd_audit_test.go`. The spam check still fails open on a genuine rspamd error, by design.
- [x] **A2 (high) wrong passwords are not counted by the auth rate limiter.**
  `pkg/smtp/auth_session.go:131` records only when `err == nil`; a wrong
  password is an error (`pkg/smtp/auth.go:156`, `:198`). Reproduced.
  Fix: typed "credential rejected" error; record it as a failure, keep 454.
  → Fixed: `ErrCredentialRejected` sentinel, recorded as a failure in `auth_session.go`. Tests: `pkg/smtp/auth_audit_test.go`.
- [ ] **A3 (high) health/admin API unauthenticated when `health.username` is
  empty.** `cmd/mizu-server/main.go:792`, `pkg/health/server.go:189`; all
  three inventory groups set `username: ""`. Same rule on the metrics
  listener (`main.go:843`). **Needs a decision** (see "Open questions").
- [x] **A4 (high in Mizu; downstream unverified) sender authorization bypass
  via quoted local-part.** `ResolveSender` runs `extractEmail` on the envelope
  path (`pkg/smtp/auth.go:378`, `:581`), so
  `MAIL FROM:<"<a@attacker.com>"@victim.com>` is authorized as
  `a@attacker.com` while `s.from` keeps `victim.com`. Reproduced.
  Fix: authorize the exact envelope address; reject envelope senders
  containing `<`, `>` or more than one `@`.
  → Fixed: `normalizeEnvelopeSender` + `isPlainEnvelopeAddress` in `ResolveSender`. Test: `TestAudit_ResolveSenderAuthorizesTheWholeEnvelopeAddress`. An existing test case that expected `Support <login>` to be unwrapped as an envelope was changed to expect refusal. Downstream question still open.
- [x] **A5 (medium) IPv6 client address truncated before auth rate limiting.**
  `pkg/smtp/auth_session.go:83-86` strips after the last `:` although
  `s.remoteAddr` is already a bare IP. Reproduced. Fix: use `s.remoteAddr`.
  → Fixed. Test: `TestAudit_IPv6RemoteAddrIsNotTruncatedForAuth`.
- [ ] **A6 (medium) credentials cache can be filled to lock senders out.**
  Raw-username key, written on wrong passwords, capped with "refuse to grow"
  (`pkg/smtp/auth.go:627`); `ResolveSender` rejects with a permanent 550 on a
  cache miss (`auth.go:368`), which also hits any session still sending five
  minutes after AUTH. Fix: lowercase the key; refetch on a miss; return a
  temporary failure when the backend cannot be reached.
  → Partly fixed: cache key lowercased, `ResolveSender` refetches on a miss. Tests: `TestAudit_CredCacheKeyIsCaseInsensitive`, `TestAudit_ResolveSenderRefetchesOnCredCacheMiss`. **Still open:** a backend error during that refetch is still a permanent 550, because `ResolveSender` returns `(string, bool)` and cannot say "temporary".
- [x] **A7 (medium) connection reaper frees slots of live connections.**
  `pkg/smtp/connection_tracker.go:183-189` decrements without closing the
  socket; `Release` decrements again. Reproduced.
  → Fixed: slots are `ConnLease`s (`ConnectionTracker.Acquire`); sessions hold their lease, so releasing a reaped slot is a no-op, and the address-keyed API (`TryAcquire`/`Release(addr)` on `ConnectionTracker` and `DistributedTracker`) was removed, so a slot can only be given back by the lease that owns it. Tests: `pkg/smtp/connection_lease_audit_test.go`. The reaper still frees session slots of connections that are open; the socket-level bound is now A8.
- [x] **A8 (medium) connection and rate limits only apply after EHLO.**
  The tracker is reached from `Backend.NewSession`, which the go-smtp fork
  calls from `handleGreet` (`conn.go:410`); `Server.MaxConnections` is never
  set (`cmd/mizu-server/main.go:1349-1355`). NOOP/VRFY work without a session
  and re-arm the read timeout. Fix needs a pre-greeting hook (listener
  wrapper) so the tracker counts at accept.
  → Fixed: `AcceptLimiter` (`pkg/smtp/accept_limiter.go`) counts sockets at accept with `max_connections` / `max_connections_per_ip`, wired in `runSMTPServerInstance` below PROXY protocol and TLS; trusted proxies are exempt from the per-IP count. Over-limit sockets are closed without a reply. Tests: `pkg/smtp/accept_limiter_test.go`.
- [x] **A9 (medium-low) TO / TO_DOMAIN rate-limit key is always the first
  recipient.** `pkg/smtp/rate_limiter.go:312`; the candidate recipient is
  appended last. Reproduced. Fix: key on the recipient being added.
  → Fixed: `Session.Rcpt` passes only the candidate recipient. Test: `pkg/smtp/rate_limit_audit_test.go`.
- [x] **A10 (low-medium) sender whitelist matched on the unverified MAIL
  FROM.** `pkg/smtp/rate_limiter.go:214` exempts every dimension, including
  IP, for a forged whitelisted sender on port 25. Applies only where
  `whitelisted_domains` / `whitelisted_senders` are set on a relay server.
  → Fixed: an unauthenticated whitelisted sender lifts only FROM / FROM_DOMAIN dimensions; an authenticated one is still exempt from all. Test: `TestAudit_ForgedWhitelistedSenderDoesNotBypassIPLimit`. **Behaviour change** for relay servers: a whitelisted sender domain is now subject to IP and recipient limits; use `whitelisted_ips` for hosts that must bypass those. Two existing tests were adapted.
- [ ] **A11 (low-medium) per-IP limits key IPv6 on the /128.**
  `connection_tracker.go:254`, `rate_limiter.go:292`, and reputation in
  `pkg/stats`. The auth tiers bucket by /64 (`bucketIP`); these do not.
- [x] **A12 (low-medium) reputation `whitelist_hosts` trusts an unconfirmed
  PTR.** `pkg/smtp/server.go:568` takes `names[0]` with no forward lookup;
  `server.go:599` suffix-matches it. Applies where `whitelist_hosts` is set.
  → Fixed: `ptrWhitelisted` requires the PTR name to resolve forward to the client IP. Tests: `pkg/smtp/ptr_whitelist_audit_test.go` (written with the fix; not seen failing first, since the function is new).
- [ ] **A13 (low) usernames used as Prometheus labels and unnormalized in
  limiter keys.** `pkg/smtp/auth_rate_limiter.go:430`, `:575`. Invalid UTF-8
  in a label panics (recovered by go-smtp, connection dropped).
  → Partly fixed: `normalizeAuthUsername` (lowercase, valid UTF-8) at both limiter entry points. Test: `TestAudit_AuthRateLimiterUsernameIsCaseInsensitive`. **Still open:** username remains a metric label, so cardinality is bounded only by the limiter.
- [ ] **A14 (low) `mizu-admin auth` takes password and token as arguments.**
  `cmd/mizu-admin/auth.go:43`, `:54-58`.
- [ ] **A15 (functional) reputation sync never finds a peer file.**
  `cmd/mizu-server/main.go:467` builds `http://<peer>:8080` and
  `pkg/stats/sync.go:48` uses it as the S3 object name, while exports are
  written under the plain hostname.

## B. Dormant today, live when the feature is switched on

`arc_check` and `dmarc_check` are off in the inventory but default to on in
`roles/mizu/templates/config.toml.j2`.

- [x] **B1 (high, DoS; `arc_check`) unbounded ARC instance loop.**
  `pkg/validation/arc.go:199` loops to `maxInstance`, taken from an
  uncapped `strconv.Atoi` (`arc.go:226`), logging per iteration.
  Fix: reject instances outside 1..50 (RFC 8617).
  → Fixed: `extractInstance` collapses out-of-range values to 51 and `validateARCChain` fails the chain. Tests: `pkg/validation/arc_audit_test.go`.
- [x] **B2 (high; `dmarc_check`) unparseable From skips DMARC enforcement.**
  `pkg/validation/dmarc.go:114-131` returns policy `none` before the lookup.
  Reproduced. Fix: treat an unparseable From as a DMARC failure that is
  rejected (or at least junked) instead of passed through.
  → Fixed as **junk**, not reject (`unparseableFromResult`). Test: `TestAudit_DMARCUnparseableFromIsJunk`. Say if you want reject instead.
- [x] **B3 (medium-high; `dmarc_check`) relaxed alignment matches `"" == ""`.**
  `getOrganizationalDomain` returns `""` on error (`dmarc.go:401`) for
  public-suffix and trailing-dot names. Reproduced.
  → Fixed: a domain the PSL cannot split is its own organizational domain; empty domains never align; trailing dots normalized. Tests: `pkg/validation/dmarc_audit_test.go`.
- [x] **B4 (medium; `dmarc_check`) no organizational-domain fallback, `sp=`
  never consulted.** `dmarc.go:174`; go-msgauth queries only the exact
  From domain. Reproduced.
  → Fixed: lookup falls back to the organizational domain and applies `sp=` when present. Tests: `TestAudit_DMARCFallsBackToOrganizationalDomain`, `...ExactDomainRecordWins...`. `TestCheckDMARC_NoDMARCRecord` now uses a `.invalid` domain: its old `*.example.com` name inherits example.com's real `p=reject`.
- [x] **B5 (medium-high, DoS; `dmarc_check`) unbounded DKIM signatures and
  unbounded DNS cache.** `dmarc.go:189` leaves `MaxVerifications` unset;
  `pkg/dns/resolver.go:169` has no size cap. Reproduced (5000 signatures →
  5001 lookups).
  → Partly fixed: `maxDKIMVerifications = 10`. Test: `TestAudit_DKIMSignatureCountIsCapped`. The DNS cache is now capped at 50,000 entries and skips answers over 16 KB (`pkg/dns/cache_audit_test.go`).
- [x] **B6 (high, availability; circuit breaker) breaker sticks in
  half-open.** A timed-out probe returns before `recordResult`
  (`pkg/poster/circuit_breaker.go:127`), never releasing its slot.
  Reproduced.
  → Fixed: `releaseProbe`. Test: `TestAudit_HalfOpenProbeTimeoutDoesNotWedgeBreaker`.
- [ ] **B7 (medium; circuit breaker) 4xx responses open the breaker.**
  `Call` records any error, including `HTTPStatusError` 403/404/413
  (`pkg/poster/poster.go:219`). Also `IsRetryableError` returns false for
  `http.Client` timeouts, contradicting its own comment (`poster.go:246`).
  → Partly fixed: non-retryable 4xx count as "backend alive". Tests: `TestAudit_ClientErrorsDoNotOpenBreaker` and neighbours. **Still open:** the `IsRetryableError` timeout mismatch.
- [x] **B8 (medium; `cluster_sync_enabled`) auth-limiter events never
  broadcast.** gob bytes wrapped as `json.RawMessage`
  (`pkg/cluster/memberlist.go:326`). Reproduced.
  → Fixed: events are JSON-encoded. Test: `pkg/smtp/auth_gossip_audit_test.go`.
- [x] **B9 (high when enabled; distributed tracker / rate-limit gossip)
  oversized gossip never sent and never dropped.** Whole-state snapshots
  (`distributed_tracker.go:528`, `rate_limiter.go:386`) exceed the UDP
  budget; `Invalidates` returns false (`memberlist.go:568`). Reproduced.
  → Fixed: messages above 1024 bytes go to every member over memberlist's reliable (TCP) channel, one in flight per type and scope; smaller snapshots replace the queued one of the same kind. Tests: `pkg/cluster/broadcast_audit_test.go`.
- [x] **B10 (medium-low; rate-limit gossip) expired windows are gossiped.**
  `rate_limiter.go:386-395` sends every `localCount > 0` without checking
  window expiry. Reproduced.
  → Fixed: `sendGossip` skips windows past their duration. Test: `TestAudit_ExpiredRateLimitWindowsAreNotGossiped`.
- [x] **B11 (low-medium) gossip handlers are one slot per message type.**
  `memberlist.go:270-282`; with several `[[server]]` blocks the last
  registration wins.
  → Fixed: `Cluster.Scoped(serverName)`; the envelope carries a `scope` and handlers are keyed by type and scope. Test: `TestAudit_GossipIsRoutedPerServerScope`. During a rolling upgrade, old and new nodes do not exchange scoped gossip. State and event delegates are still one slot.
- [x] **B12 (low) `--local` skips the cluster-key check.**
  `pkg/config/config.go:173` returns before the cluster block; the cluster
  still starts and only warns (`pkg/cluster/memberlist.go:139`).
  → Fixed: `validateClusterSecretKey` runs before the local-mode return. Tests: `pkg/config/audit_test.go`.
- [x] **B13 (low; `junk.apply_action = "subject"`) `modifySubject` scans
  into the body.** `pkg/smtp/headers.go:409`. Reproduced.
  → Fixed. Tests: `pkg/smtp/headers_audit_test.go`.
- [ ] **B14 (medium, suspected; `tls.provider = letsencrypt`) non-leaders
  can place ACME orders.** `pkg/tls/cluster_cache.go:60` blocks only `Put`,
  whose error autocert ignores. Not reproduced.
- [x] **B15 (medium if true) delivery 403 cached per recipient regardless
  of sender.** `pkg/smtp/server.go:2091`. Depends on whether mailqueuer's
  403 is sender-specific — check mailqueuer before changing.
  → Fixed: the "blocked" half of the delivery recipient cache is removed; a 403 is answered per delivery and never cached or gossiped. Test: `TestAudit_Delivery403DoesNotBlockOtherSenders`. Two blocked-cache tests were deleted and the rest of `recipient_cache_test.go` adapted.
## Review follow-ups (2026-11-20)

A code review of the fixes above found and fixed:

- **B11** state and event delegates were still one slot per process; now
  per scope (changes the join-time push/pull state format).
- **B4** the organizational-domain fallback ran on temporary DNS failures;
  now only when the From domain really has no record.
- **A12** the forward-confirmation lookup now goes through the DNS cache.
- **B7** only 400, 403, 404, 413 and 422 count as "backend alive"; a 401
  or a redirect is a failure again
  (`TestAudit_NonVerdictStatusesAreBackendFailures`).
- **B9** large one-off events are no longer skipped while another send is
  in flight (`TestAudit_LargeEventsAreNotSkippedWhileAnotherIsInFlight`).
- **A7** the address-keyed `TryAcquire` / `Release(addr)` API is removed from
  both trackers; tests use leases.

Raised by the review and left for a decision:

- **A8** the accept limiter uses the session limits, so an over-limit client
  is dropped silently and never sees the 421 reply. A small headroom at
  accept would restore it.
- **B4** a made-up subdomain of a `p=none` domain is no longer junked
  (RFC 7489 behaviour; mail from the parent itself was already unmarked).
- **B15** a delivery 403 is a permanent 550 only where the recipient cache is
  enabled, temporary elsewhere (kept as deployed).
- **A7** lease release is linear in the connections of one IP.

## Still open

- **A3** inventory/firewall task (see Decisions).
- **A6** remainder: a backend error while refetching at MAIL FROM is still a
  permanent 550; `ResolveSender` would need a third "temporary" outcome.
- **A11** IPv6 /64 keying for connection limits, rate limits and reputation.
  Needs a decision: large providers send from many addresses inside one /64,
  so `max_connections_per_ip` applied per /64 could throttle legitimate mail.
- **A13** remainder: username as a Prometheus label (cardinality).
- **A14** `mizu-admin auth` secrets on the command line.
- **A15** reputation sync object naming (functional, not security).
- **B7** remainder: `IsRetryableError` treats an `http.Client` timeout as
  non-retryable although its comment says timeouts retry. Changing it alters
  how long a DATA command can take, so it needs a decision.
- **B14** non-leader ACME orders: suspected only, not reproduced.

## Decisions (2026-11-20)

- **A3:** the server keeps starting without health credentials. It now logs
  a startup warning when `health.username` is empty. Closing the hole is an
  inventory/firewall task: set `health.username` + password for the three
  groups, or confirm 8080 is not reachable from outside.
- **B2:** junk, not reject. Done.
- **B15:** mailqueuer's `/ingest` never returns 403 or 404 (it answers 405,
  408, 415, 422 and 5xx), and all three inventory groups deliver to it, so
  the delivery-side recipient cache never fires today. The sender-specific
  403 lives in recipient validation, which is not negatively cached. The
  cache is therefore dormant, but wrong by construction for any backend
  whose 403 means "this sender is blocked": it would bounce every other
  sender for the TTL and gossip that cluster-wide. Proposed: remove the
  "blocked" half of the cache (keep "not found", which is sender-independent).
  Awaiting a go-ahead because it changes the gossip snapshot and removes
  existing tests.

## Open questions

- **A4:** what do mailqueuer and Strela do with
  `<a@attacker.com>@victim.com` as the envelope sender? (Mizu now refuses
  it, so this only matters for judging past exposure.)

## Round 2 (2026-11-20)

Second bug hunt, four reviewers by slice. Nothing here is fixed yet.
"read" = I read the code and agree; "test" = the reviewer reproduced it with a
throwaway test; "trace" = reviewer's code trace only, not re-checked.

### C — live in the deployed config

- [x] **C1** One successful login wipes the per-IP auth failure count
  (`auth_rate_limiter.go` `recordSuccess`). 9 guesses + own login, repeat:
  credential stuffing from one IP is unlimited. (read, test)
  → success now subtracts only that username's own failures from the IP count (`forgiveIPFailures`, per-IP `perUser` map capped at 64). Tests: `TestAudit_SuccessDoesNotForgiveGuessesAtOtherAccounts`, `TestAudit_SuccessForgivesTheUsersOwnFailures`.
- [x] **C2** Newline-heavy body allocates ~50x message size: `detectMailLoop`,
  `fixMissingHeaders`, `modifySubject`, `rewriteFromHeader` `strings.Split`
  the whole message (`headers.go:358,403,459,565`). Scan the header block
  only. (read, test)
  → `splitHeaderLines` splits the header block only; 368 MiB → under 24 MiB for a 4 MiB message. Tests: `TestAudit_HeaderHelpers*`. Left: a message with no blank line at all is still split whole.
- [x] **C3** DATA read error (stall > 3 min, session deadline) is returned raw
  → go-smtp sends permanent 554 with the socket error text; the rest of the
  body may then be parsed as commands (`server.go:1688`). Return 4xx and close.
  (read for the 554; desync is trace)
  → non-SMTP read errors → `421 4.4.2` and the connection is closed; 552 and BDAT `ErrDataReset` pass through. Tests: `TestAudit_BodyRead*`.
- [x] **C4** rspamd reply > 1 MiB is truncated, fails to parse, fails open
  (`rspamd.go:365`). Whether a sender can force such a reply on the deployed
  rspamd is unverified. (read, test)
  → cap raised to 64 MiB with an explicit error past it; logs and errors carry a 2 KB excerpt. Test: `TestAudit_LargeRspamdReplyKeepsItsVerdict`. An rspamd error or timeout still fails open (by design).
- [x] **C5** `CheckRateLimit` charges earlier dimensions before a later one
  refuses, no rollback: a blocked client can exhaust a victim's TO/FROM budget.
  (read, test)
  → check-all-then-charge under one lock. Test: `TestAudit_RefusedRequestChargesNothing`.
- [x] **C6** Every dimension is charged at EHLO, MAIL and each RCPT: 50
  recipients cost an IP dimension 52. Needs a decision on intended semantics.
  (trace)
  → decided 2026-11-20: each dimension is charged once, at its own stage (`RateLimitStage`, `stageForKeys`): IP alone = connections (EHLO), FROM/FROM_DOMAIN/AUTHENTICATED_USER = messages (MAIL), TO/TO_DOMAIN = recipients (RCPT). **Existing limits become looser for IP and sender dimensions** - review configured values. Test: `TestAudit_DimensionIsChargedOnceAtItsOwnStage`; five existing tests adapted.
- [x] **C7** Two-`@` addresses skip FROM_DOMAIN / TO_DOMAIN (`extractDomain`);
  no trailing-dot normalisation. (read, test)
  → `extractDomain` uses the last `@` and trims a trailing dot. Test: `TestAudit_DomainDimensionsCannotBeSidestepped`.
- [x] **C8** Rate-limit windows that were ever hit are never freed by
  `cleanup()` (`localCount` only reset lazily). (read, test)
  → cleanup also removes expired windows. Test: `TestAudit_ExpiredWindowsAreCleanedUp`.
- [ ] **C9** Multi-recipient delivery is not atomic: failure on recipient N
  → 451/550 for all, earlier recipients get duplicates on retry (trace ID
  rotates, so mailqueuer cannot dedupe) or a false bounce. Needs a design
  decision (one POST per message? stable idempotency key?). (trace)
  → checked mailqueuer 2026-11-20: `/ingest` accepts a comma-separated
  `X-Mail-To`, publishes per recipient, and already suppresses repeats on
  `(from, Message-ID, recipient)` for 15 min (in memory, per instance) - so a
  sender retry inside 15 min is deduplicated today. Left open: retries after
  15 min or after a mailqueuer restart, and the false bounce. Proposal: one
  POST with all recipients (not started - changes the delivery contract).
- [x] **C10** Each connection keeps its largest `mailData` capacity until it
  closes (32 MiB after one 25 MiB message). (test)
  → the buffer is local to `readMessageData`; the session field is gone. Test: `TestAudit_SessionDoesNotRetainTheMessageBuffer`.
- [x] **C11** Validation cache keys `ip:ptr:helo:from:to` are ambiguous (`:`
  allowed in HELO and local parts) — recipient/sender validator. (test)
  → fields are `%q`-quoted in both validators. Tests: `TestAudit_CacheKeyIsUnambiguous` (recipient, sender).
- [ ] **C12** BDAT: `Session.Data` runs on its own goroutine and races
  `Session.Reset` on a pipelined RSET. (test with -race)
  → partly: `mailData` is no longer shared, so the buffer race is gone. `Reset` still writes other session fields while a BDAT `Data` goroutine may be reading them - open.
- [x] **C13** Control bytes in MAIL FROM / RCPT TO reach HTTP headers in
  poster; Go refuses the request → that message gets 451 forever. With the
  breaker enabled (off in inventory) five such messages open it for everyone.
  Reject control bytes at MAIL/RCPT. (test)
  → `rejectEnvelopeControlBytes` at the top of `Mail` and `Rcpt` (553 5.1.3). Test: `TestAudit_ControlBytesInEnvelopeAreRefused`.
- [x] **C14** Circuit breaker never counts `http.Client` timeouts (they match
  `context.DeadlineExceeded`), so it never opens on a hung backend. Predates
  round 1; only skip when the caller's ctx is done. Breaker off in inventory.
  (read, test)
  → `Call(ctx, fn)`: accounting is skipped only when the caller's own ctx has ended; a client timeout counts as a failure. Tests: `TestAudit_BackendTimeoutOpensBreaker`, `TestAudit_CallerCancellationDoesNotOpenBreaker`; the B6 probe test now uses a cancelled caller ctx.
- [x] **C15** Re-EHLO after AUTH locks the session out (fork keeps `didAuth`).
  Fails closed. (trace)
  → the fork had already fixed this (a greeting after AUTH keeps the session);
  Mizu was pinned 106 commits behind. Pin bumped to `v0.24.0-migadu.3`. Test:
  `TestAudit_ReEHLOAfterAuthDoesNotLockTheSessionOut` (wire-level, red on the
  old pin). Needs a soak before deploy: 106 fork commits came with it.
- [ ] **C16** `validation.allow_null_sender`, `dkim_check`,
  `dns.cache_negative_ttl` are read nowhere. (read)
- [x] **C17** `mizu-admin flush-cache` always 501 — flusher never wired. (trace)
  → `AddCacheFlusher`, registered per server next to the checker; a flush reaches every distributed tracker. Test: `TestAudit_FlushCacheReachesEveryRegisteredFlusher`. Only servers with `distributed.enabled` have a flusher, so the deployed config still answers 501.
- [x] **C18** Health server mutated after `Start()` (checkers, unblocker, cert
  renewer) — startup race; `SetACMEHandler` after Start is a dead call. (trace)
  → registrations are guarded by a lock and handlers work on a snapshot; the ACME route is always registered and serves whatever handler is set later. `SetCacheFlusher` / `SetIPUnblocker` replaced by `Add*`. Tests: `TestAudit_RegistrationAfterStartIsSafe` (-race), `TestAudit_ACMEHandlerSetAfterStartIsServed`.
- [ ] **C19** Config: `half_open_max_calls = -1` wedges the breaker;
  `health.password = "${HEALTH_PASSWORD}"` unset → empty password accepted;
  `${VAR}` not expanded for `metrics.password` / letsencrypt S3 secret;
  negative `dns.timeout_seconds` makes MX checks pass. (trace)
  → partly: negative breaker values and negative `dns.timeout_seconds` fail validation (`validateNonNegative`, test `TestAudit_NegativeTimeoutsAndThresholdsAreRejected`). Open: unset `${HEALTH_PASSWORD}` → empty password; `${VAR}` not expanded for `metrics.password` / letsencrypt S3 secret.

### D — dormant in the deployed config

- [x] **D1** AUTH accepted mid-transaction: MAIL FROM (unauthenticated) then
  AUTH skips `allowed_from`. Needs `auth.enabled` with `required=false`.
  (read, wire test)
  → AUTH returns 503 5.5.1 once MAIL FROM is accepted. Test: `TestAudit_AuthIsRefusedDuringMailTransaction`.
- [x] **D2** DMARC evaluates only the first From address; duplicate From
  headers / multi-address From pass on the attacker's domain. `dmarc_check`.
  (read, test)
  → more than one From header, or more than one address in it, is junk (same verdict as an unparseable From). Test: `TestAudit_DMARCMultipleFromIsJunk`.
- [x] **D3** SPF adapter passes NXDOMAIN through as an error → TempError →
  `none` for `exists:` / dangling `a:` `mx:` records. `spf_check`. (test)
  → `notFoundIsEmpty` in the SPF adapter; SERVFAIL/timeouts stay errors. Tests: `TestAudit_SPFNotFoundIsAnEmptyAnswerNotAnError`, `TestAudit_SPFServerFailureStaysAnError`. Noticed, not changed: `CheckSPF` passes an empty HELO to the library (`%{h}` macro) and runs on `context.Background()`.
- [x] **D4** DKIM signature with `t=` 1 s in the future is discarded; no skew
  allowance. (trace)
  → 5 min allowance (`MaxDKIMClockSkew`, `dkimTimestampProblem`). Test: `TestAudit_DKIMTimestampAllowsClockSkew`.
- [ ] **D5** DNS cache bound is ~800 MB (50k × 16 KB); no negative caching;
  case-sensitive keys; ARC/DNSBL/HELO lookups bypass it. (trace)
- [ ] **D6** ARC: `cv=` never read and `h=` unchecked (false pass); every
  instance's AMS required (false fail on mailing lists). Informational. (test)
- [ ] **D7** Auth events pile up unbounded in memberlist's queue while peers
  are unreachable (`cluster_sync_enabled`). (test)
- [ ] **D8** Auth gossip: `FirstFailure` / `LastDelay` unsanitised, Apply paths
  ignore entry caps; one-off events reach at most 3 peers in clusters ≥ 5.
  Needs a peer with the cluster key. (test / trace)
- [ ] **D9** Rate-limit and connection gossip trust the self-declared NodeID /
  Hostname; future timestamps never pruned. (trace)
- [ ] **D10** S3 connection snapshots not scoped per server; a snapshot of any
  age counts as fresh (ghost counts from dead nodes). `distributed.enabled`.
  (read / test)
- [ ] **D11** Let's Encrypt cluster: non-leaders order and discard certs in a
  retry loop (B14 mechanism); startup `SyncAllToS3` overwrites S3 with stale
  local copies and resurrects deleted certs; `renew-cert` deletes but does not
  renew; leader election has no quorum. (trace / test)
- [ ] **D12** `mizu-admin tls clean` deletes every non-cert object under the
  prefix, which the role template shares with `[storage]` (stats files). (trace)
- [ ] **D13** Stats merge trusts peer files: unblock is undone, a `null` entry
  panics, no range checks, unbounded gunzip. Dormant until A15. Export
  "skip if unchanged" never skips (hash covers the timestamp); same in the
  distributed tracker export. (test)
  → partly: null entries are skipped and the decompressed size is capped at 256 MiB (`decodeStatsExport`). Tests: `TestAudit_StatsMergeSkipsNullEntries`, `TestAudit_StatsImportBoundsDecompressedSize`. Open: unblock undone by the next merge, no range checks on merged values, export never skipping, dead `NoSuchKey` branch.
- [ ] **D14** Minor: operator `unblock-ip` leaves IP+username blocks; gossiped
  subnet block with a different prefix length never matches; auth
  `broadcastRoutine` has no stop path; tracker S3 calls use
  `context.Background()` and can hang shutdown. (trace)

  → partly: operator unblock now also lifts that address's IP+username blocks (test `TestAudit_UnblockIPAlsoLiftsItsUsernameBlocks`). Open: subnet prefix mismatch, `broadcastRoutine` stop path, tracker S3 calls on `context.Background()`.
### Follow-ups from the 2026-11-20 questions

- [x] **C20** A comma inside one `RCPT TO` address was split by mailqueuer into
  several recipients (its `X-Mail-To` is comma-separated and its address check
  allows commas), after being counted, rate-limited and validated here as one.
  → refused with 553 in `Rcpt`. Test: `TestAudit_CommaInRecipientIsRefused`.
- **C9, checked:** mailqueuer handles a multi-recipient POST correctly - its
  tests cover a retry with the same trace ID, a retry after a partial failure
  (only the missing recipients are published) and a repeated recipient. Dedup
  is in memory, and Mizu posts to `localhost:4444`, so one instance per host:
  it is lost only on a mailqueuer restart. One POST for all recipients is safe
  to build; not started.
- **A3, checked:** the health API is *not* WireGuard-only. It listens on
  `:8080` (all interfaces), and pf allows it on the public addresses from the
  prometheus hosts and from the other hosts of the same mizu group, besides
  fernrohr over WireGuard (wg interfaces are unfiltered: `set skip`). Not open
  to the internet (`block log all`), but any host in those groups can call
  `unblock-ip` / `renew-cert` without credentials. Fix is in the inventory /
  firewall role, not here: bind `listen_addr` to the WireGuard address, or set
  credentials.
- [x] **B7** a backend timeout is retried inline (`IsRetryableError`:
  `DeadlineExceeded` is retryable, `Canceled` is not; the loop stops when the
  caller's own ctx has ended). Tests: `TestAudit_BackendTimeoutIsRetried`,
  `TestAudit_CallerCancellationIsNotRetried`.
- [x] **C16** `validation.allow_null_sender` removed (config struct, CLAUDE.md,
  role template, mizu_out inventory). What refuses `<>` on submission is
  `allowed_from`; pinned by `TestAudit_AuthenticatedNullSenderIsRefused`.
- [ ] **C9, blocked:** one POST for all recipients cannot be done in Mizu
  alone. Mizu prepends `X-Envelope-To: <recipient>` to each recipient's copy
  of the message; with one body for all recipients that header has to be
  added per recipient downstream. Mailqueuer passes the recipient to its
  backend as an HTTP header and Strela prepends its own in-body header on
  outbound, but nothing does so for inbound mailbox delivery - stored
  messages (and users' filters on that header) would lose it. Needs
  mailqueuer to prepend it at delivery first.

### Review of round 2 (2026-11-20)

Code review of the uncommitted tree; fixed:

- [x] `ApplyFailureCount` (cluster sync) dropped the per-user failure map, so
  a later success forgave nothing. It now carries the map over.
- [x] Breaker: a cancelled call released a half-open probe slot even when it
  had been admitted while closed and held none. `canProceed` reports whether
  a slot was taken.
- [x] Accept limiter logs at most one refusal line per second.
- [x] `ErrTooManySignatures` no longer lands in DMARC `FailureReasons`.
- [x] Dead `connTracker` / `distTracker` parameters of `startHealthServer`
  removed.
- [x] **A11** every per-IP limit keys IPv6 on the /64 (`bucketIP`): accept
  limiter, `ConnectionTracker`, `DistributedTracker`, the rate limiter's IP
  key. Tests: `TestAudit_*KeysIPv6ByPrefix`.
- [x] Delivery 403 is a permanent 550 on every server, not only with the
  recipient cache on. Test: `TestAudit_Delivery403IsPermanentWithoutRecipientCache`.

Left open by the review:

- [ ] A6 remainder: a backend error on the `ResolveSender` refetch is still a
  permanent 550 at MAIL FROM. Needs a third result on
  `Authenticator.ResolveSender` (interface and every mock).
- [ ] The 421 built after a body read error is never seen: the socket is
  closed first. Sending it needs a hook in the go-smtp fork.

# Migrating custom rspamd Lua plugins into mizu

**Status:** Planning
**Scope:** `roles/rspamd/templates/rspamd/plugins.d/migadu_*.lua` (+ the relaying
`migadu_relay.lua`) evaluated for reimplementation inside the mizu SMTP relay.
**Author:** planning doc, 2026-08-14

---

## 1. Background & guiding principle

The `rspamd` role ships ten custom `migadu_*` Lua plugins. They mix two very
different kinds of logic:

1. **Envelope / policy logic** — decisions based on the SMTP envelope, the
   authenticated user, the connecting IP, the server role, and small
   lookup tables (CDB maps) or counters (Redis). These need *no* message-body
   scoring.
2. **Content-scoring logic** — decisions that depend on rspamd's own engine:
   Bayes, fuzzy, neural, symbol scores, `task:learn()`.

**Architectural fact that drives every recommendation below:** mizu sits *in
front of* rspamd and *upstream of* mailqueuer. It terminates the SMTP session,
does its own connection/auth/DNS/reputation checks, POSTs the message to rspamd
`/checkv2` (`pkg/spamcheck/rspamd.go`) for scoring, then POSTs the accepted
message to **mailqueuer** `/ingest` for queueing and delivery. mizu is deployed
in the **same three roles** the plugins branch on — the Ansible groups
`mizu_in`, `mizu_out`, `mizu_rel`.

```
   SMTP client ──▶ mizu ──▶ rspamd /checkv2 (score/symbols back)
                    │
                    └────▶ mailqueuer /ingest ──▶ queue ──▶ Strela (SMTP) / Kanal (LMTP)
```

### The core design principle: mechanism in mizu, policy out of it

Most of these plugins encode **Migadu business policy** (org limits, confirmed
redirects, suspend endpoints, the `migadu.com` anti-phishing case, footer
content). If that leaks into mizu core, a general-purpose relay becomes a Migadu
appliance. The rule for every port is therefore:

> **Port the mechanism into mizu; keep the policy out of it.**

Concretely, each behaviour lands in one of three tiers:

- **Tier A — generic mechanism, in core, config-gated, default-off.** Reusable
  primitives whose only Migadu-ness is the *values in the config file*, never the
  code. The word "migadu" must not appear in `pkg/`. Nothing is constructed
  unless enabled (zero cost when off).
- **Tier B — policy delegated over HTTP** (the idiom mizu already uses in
  `pkg/sender` and `pkg/recipient`: URL interpolation + verdict contract +
  LRU cache). mizu ships the **hook and the verdict contract**; the org's policy
  backend owns the rules. This is where the us-specific logic lives — *outside*
  mizu.
- **Tier C — stays in rspamd / already covered elsewhere.** Bayes/fuzzy/neural,
  MIME footers, and per-message traffic logging (owned by mailqueuer).

Because mizu sits in front of rspamd, moving **policy** upstream means earlier
rejection (before DATA / before rspamd) and less rspamd load. **Content
scoring** stays in rspamd; mizu already consumes the resulting score/symbols, so
plugins that merely *act on* the score can move while the scoring stays put.

`migadu_flow` is special: it sets the `MIGADU_FLOW` symbol nearly every other
plugin reads. In mizu that becomes intrinsic **session context** (mizu already
knows its role + whether the sender authenticated), not a plugin — so "flow"
stops being a thing to port and becomes a `session.Direction` value.

---

## 2. What mizu already does (baseline)

Relevant existing capabilities (so we don't rebuild them):

| Area                                                                                                   | mizu today | Source                                                |
|--------------------------------------------------------------------------------------------------------|------------|-------------------------------------------------------|
| rDNS / DNSBL / connection limits                                                                       | Yes        | `pkg/smtp/server.go`, `pkg/blacklist/`                |
| Multi-dimensional rate limiting (+ gossip, whitelists, hot-reload files)                               | Yes        | `pkg/smtp/rate_limiter.go`, `rate_limit_whitelist.go` |
| SPF / DKIM / DMARC / ARC validation + ARC signing                                                      | Yes        | `pkg/validation/`                                     |
| rspamd scoring integration (score, action, symbols, add_headers)                                       | Yes        | `pkg/spamcheck/`                                      |
| Header inject/strip/sanitize, Date & Message-ID fixing, subject rewrite                                | Yes        | `pkg/smtp/headers.go`                                 |
| Sender validation (HTTP) & recipient validation (HTTP), LRU-cached                                     | Yes        | `pkg/sender/`, `pkg/recipient/`                       |
| IP/domain reputation + stats, S3/gossip sync                                                           | Yes        | `pkg/stats/`                                          |
| Auth abuse blocking (progressive delay, IP/user blocks)                                                | Yes        | `pkg/smtp/auth_rate_limiter.go`                       |
| Feeds mailqueuer `/ingest`: envelope, origin, client IP, auth user, rspamd score/action, junk verdict | Yes        | `pkg/poster` `Delivery`; contract in §2.1             |

**Gaps** mizu does not have: GeoIP/country, per-recipient-domain allow/deny/junk
lists, external-map lookups, MIME **body** rewriting (footers), hierarchical
daily counters, forwarding authorization.

### 2.1 mizu → mailqueuer ingest contract (as sent)

mizu makes **one `POST` per envelope recipient** to `[server.delivery] url`.
The body is the raw RFC 822 message, including the headers mizu stamps into it
(`X-Envelope-To`, `Received`, and the `X-Mizu-*` set such as
`X-Mizu-Authentication-Results`). All other metadata travels as **HTTP request
headers only**. It is never written into the message, so recipients never see it.
Built by `Delivery.applyHeaders` in `pkg/poster/poster.go`.

| Header (wire casing) | Value                                                       | Sent when                           |
|----------------------|-------------------------------------------------------------|-------------------------------------|
| `Content-Type`       | `message/rfc822`                                            | always                              |
| `Authorization`      | `Bearer <delivery.auth_token>`                              | a token is configured               |
| `X-Mail-To`          | the single envelope recipient of this POST                  | always                              |
| `X-Mail-From`        | envelope `MAIL FROM`                                        | sender is not null (`<>`)           |
| `X-Trace-Id`         | session trace ID, same as the `Received` header's `id`      | always                              |
| `X-Mail-Origin`      | `relay` or `submission`                                     | always                              |
| `X-Client-Ip`        | connecting client IP, no port, PROXY-protocol aware         | always                              |
| `X-Auth-User`        | SMTP AUTH login                                             | authenticated submission            |
| `X-Junk`             | `yes`                                                       | any check classified the message junk |
| `X-Junk-Action`      | configured `junk.apply_action`, default `header`            | whenever `X-Junk` is sent           |
| `X-Spam-Score`       | rspamd score, two decimals (`7.50`)                         | rspamd check ran                    |
| `X-Spam-Action`      | rspamd action (`no action`, `add header`, `greylist`, …)    | rspamd check ran                    |

Captured from real SMTP sessions against a recording backend. The host, port,
trace ID, and `Content-Length` vary per message; the header set does not.

Relay, message flagged by rspamd and a matching junk header:

```http
POST /ingest HTTP/1.1
Host: 127.0.0.1:49421
Accept-Encoding: gzip
Authorization: Bearer delivery-secret
Content-Length: 488
Content-Type: message/rfc822
User-Agent: Go-http-client/1.1
X-Client-Ip: 127.0.0.1
X-Junk: yes
X-Junk-Action: header
X-Mail-From: alice@sender.example
X-Mail-Origin: relay
X-Mail-To: bob@dest.example
X-Spam-Action: add header
X-Spam-Score: 7.50
X-Trace-Id: 0f93c52719187abc
```

Submission over STARTTLS with AUTH PLAIN, clean message, rspamd disabled:

```http
POST /ingest HTTP/1.1
Host: 127.0.0.1:49421
Accept-Encoding: gzip
Authorization: Bearer delivery-secret
Content-Length: 416
Content-Type: message/rfc822
User-Agent: Go-http-client/1.1
X-Auth-User: alice@sender.example
X-Client-Ip: 127.0.0.1
X-Mail-From: alice@sender.example
X-Mail-Origin: submission
X-Mail-To: bob@dest.example
X-Trace-Id: 0189652b3f0499d2
```

A clean relay message with rspamd disabled carries only the always-sent rows:
no `X-Auth-User`, `X-Junk`, `X-Junk-Action`, `X-Spam-Score` or `X-Spam-Action`.

Notes for mailqueuer:

- **Match header names case-insensitively.** Go canonicalizes names on the wire,
  so the code's `X-Trace-ID` and `X-Client-IP` arrive as `X-Trace-Id` and
  `X-Client-Ip`. HTTP header names are case-insensitive (RFC 9110).
- **`Host`, `Content-Length`, `User-Agent` and `Accept-Encoding` come from Go's
  HTTP client**, not from mizu. They are not part of the contract.
- **`X-Junk-Action` is a policy setting, not an outcome.** Only `header` and
  `subject` change the body, and `reject` is enforced only when a
  `junk.check_headers` entry matches. Junk flagged by rspamd or DMARC on a
  server set to `reject` is still delivered, verified by capture with
  `X-Junk-Action: reject`. Do not read it as "mizu rejected this".
- **There is no HELO header, by design.** HELO is client-supplied text, and a
  single control byte in any header value makes Go's HTTP client refuse the
  whole request. That turns a hostile or buggy HELO into a failed delivery on
  every retry, so no client-controlled text goes into this contract.
- mailqueuer does not read `X-Mail-Origin`, `X-Client-Ip`, `X-Spam-Score` or
  `X-Spam-Action` yet. They are available for the ledger and for the CSV
  `score` and `action` columns (§3.10).

---

## 3. Plugin-by-plugin assessment

Legend — **Tier** (A/B/C per §1). **Effort**: rough size.
**Verdict**: Port / Port (adapt) / Delegate / Keep out.

### 3.1 `migadu_flow` — flow tagging & loop detection  → **Tier A · PORT (foundational)**

- **Does:** Classifies the message as `FLOW_IN` / `FLOW_OUT` / `FLOW_REL` /
  `FLOW_AUTO` from server role + auth user; adds `X-Migadu-Flow`, on incoming
  `X-Migadu-Country` / `X-Migadu-To`; on relay adds `X-Migadu-Redirected-From`,
  rejects mail loops, strips `Delivered-To`.
- **mizu fit:** Native. Becomes a `session.Direction` enum set at connect/auth
  time (mizu already knows role + auth), plus a small header step reusing
  `pkg/smtp/headers.go`. Header names use a configurable prefix — no `X-Migadu-*`
  literal in core.
- **Effort:** Small. **Verdict:** **Port first** — substrate for the
  date/mxproxy/relay/suspender/spamlists logic.

### 3.2 `migadu_date` — rewrite `Date:` to UTC on outgoing  → **Tier A · PORT**

- **Does:** On `FLOW_OUT`, replaces `Date:` with a GMT timestamp; adds one if
  missing.
- **mizu fit:** Native; extends the existing missing-header fixer.
- **Effort:** Trivial. **Verdict:** **Port.** Gate on outbound role + config flag
  (`[server.validation] rewrite_date_utc`).

### 3.3 `migadu_mxproxy` — per-recipient-domain inbound IP allowlist  → **Tier A · PORT**

- **Does:** On `FLOW_IN`, for recipient domains in a CDB map, rejects unless the
  connecting IP is in that domain's allowed-IP list.
- **mizu fit:** Good — generic per-domain IP allowlist enforced at RCPT (before
  DATA). Backed by the external-map primitive (§4).
- **Effort:** Small–Medium. **Verdict:** **Port.** Contents are org data.

### 3.4 `migadu_relay` — forwarding authorization  → **Tier B · DELEGATE**

- **Does:** On the relaying role, permits forwarding only for confirmed redirects
  (CDB), with fast-path accepts (DMARC reports, calendar invites,
  `Auto-Submitted`, same-domain, hard-coded pre-approved domains); rejects
  unconfirmed forwarding + null senders.
- **mizu fit:** Envelope policy, role-aligned (`mizu_rel`), but the redirect
  table and pre-approved domains are **business data**. Express as an HTTP
  forwarding-authorization verdict (like recipient validation); the map/domains
  live in the policy backend, not mizu. The generic envelope mechanics
  (`X-Envelope-To`/`Delivered-To`/`Auto-Submitted`/plus-suffix handling) are the
  part that lives in mizu.
- **Effort:** Medium. **Verdict:** **Delegate** the decision; port only the
  envelope plumbing.

### 3.5 `migadu_geo` — geo-velocity abuse detection  → **Tier A (mechanism) + B (action); needs GeoIP**

- **Does:** On outgoing auth mail, tracks distinct countries per user in a 2-min
  window (Redis); if >2, soft-rejects and calls an HTTP suspend URL.
- **mizu fit:** Velocity tracking is generic and can live on mizu's cluster/stats
  infra; the **suspend call** is a Tier-B webhook. Requires a new **GeoIP**
  provider (also feeds the flow country header).
- **Effort:** Medium (GeoIP is the bulk). **Verdict:** **Port after GeoIP
  exists.**

### 3.6 `migadu_suspender` — outgoing abuse suspension  → **Tier B · PORT decision, DELEGATE action**

- **Does:** On outgoing auth mail to external recipients: if the outgoing
  rate-limit symbol fired, or rspamd score/action crosses a threshold, or spambot
  header fingerprints are present, soft-rejects and calls the HTTP suspend
  endpoint.
- **mizu fit:** mizu already has rspamd's `action`/`score`/`symbols` in the
  `/checkv2` response, so it can evaluate the (config) threshold + trigger symbols
  itself and call the suspend webhook. Fingerprint symbols stay in rspamd.
- **Effort:** Medium. **Verdict:** **Port the decision to mizu; the suspend
  endpoint + whitelisted-domain list are config/backend** (replace hard-coded
  `linux.dev`/`dejanstrbac.com`).

### 3.7 `migadu_counters` — hierarchical daily send/receive counters  → **Tier B / rate-limiter extension (DECIDE)**

- **Does:** Per address/domain/organization daily Redis counters, limits from a
  CDB, in/out flows, breach webhook + soft-reject/reject, 31-day retention for
  charts.
- **mizu fit:** Overlaps mizu's existing rate limiter (FROM_DOMAIN / TO_DOMAIN /
  AUTHENTICATED_USER + gossip). Missing bits: **organization** tier (domains→
  account map), **daily** windows w/ long retention, breach notification.
- **Effort:** Medium–High if ported faithfully. **Verdict:** **Decide, don't
  auto-port.** Preferred: add an `ORGANIZATION` dimension + daily window +
  notification hook to the existing limiter, rather than a parallel Redis
  subsystem. The 31-day charting store is a reporting concern better left
  external (mailqueuer ledger / stats already persist per-message data — see
  §3.10). **Needs a decision** — §6 Q1.

### 3.8 `migadu_spamlists` — per-recipient-domain allow/deny/junk lists  → **Tier A (engine) + data/B (content); largest policy piece**

- **Does:** Per recipient domain, a list of regex entries with a type sigil:
  `!` deny sender, `#` deny recipient, `?` junk (add-header + `learn spam`),
  `=` absolute allow, `~` conditional allow (only if SPF/DKIM/DMARC don't fail);
  plus intra-domain outgoing auto-allow and a `migadu.com` phishing/bounce case.
- **mizu fit:** Core envelope policy and the biggest single item. The
  allow/deny/junk **matching engine** (regex vs SMTP+MIME sender & recipient →
  SMTP action, using mizu's SPF/DKIM/DMARC results for `~`) is generic (Tier A);
  the **list contents** and the `migadu.com` special-case are org data/policy.
- **Caveat:** `task:learn()` feeds rspamd Bayes; mizu can't call it. If a list
  hit short-circuits before rspamd, that outcome isn't learned unless mizu signals
  rspamd (§6 Q2).
- **Effort:** High. **Verdict:** **Port the engine; contents are data; learning
  stays in rspamd.** Do after the map primitive is proven by mxproxy.

### 3.9 `migadu_footers` — per-sender MIME footer injection  → **Tier C · KEEP in rspamd**

- **Does:** On `FLOW_OUT`, looks up a footer (HTML+plain UCL in CDB) and rewrites
  the MIME body, handling CT/CTE rewrites and dedup.
- **mizu fit:** Poor — requires full MIME multipart **body** rewriting, which
  mizu deliberately avoids (it streams the body, edits only headers). High risk
  of corrupting mail.
- **Effort:** High. **Verdict:** **Keep in rspamd.** Revisit only if mizu grows a
  general MIME-rewrite layer for another reason.

### 3.10 `migadu_logs_writer` — CSV traffic logs  → **Tier C · DO NOT PORT (already in mailqueuer)** ⭐ corrected

- **Does:** Appends a per-minute-rotated CSV row per message (direction, ts,
  date, queue id, country, msg id, local domain, from, principal recipient,
  recipient count, recipients, subject, score, action); `copy_migadu_traffic.sh`
  rsyncs completed files to the statistics host.
- **Finding:** **mailqueuer already implements this**, downstream of mizu:
  - `mailqueuer/internal/stats/writer.go` writes the **same 14-field CSV schema**
    (flow, received_at, date, queue_id, country, msg_id, local_domain,
    envelope_from, principal_recipient, recipient_count, envelope_to, subject,
    score, action) on delivery success.
  - `mailqueuer/internal/ledger/ledger.go` is a richer **25-column SQLite
    ledger** (ingested/delivered/bounced/retrying/dead, plus `auth_spf/dkim/dmarc/
    arc`, `auth_user`, smtp_code, mx_host, trace_id, size, attempt, duration…),
    populated from what mizu sends to `/ingest`: `X-Mizu-Authentication-Results`
    in the message body, and `X-Auth-User` and `X-Trace-Id` as HTTP headers.
    mizu now also sends `X-Spam-Score`, `X-Spam-Action`, `X-Client-Ip` and
    `X-Mail-Origin`, which can populate the CSV `score`/`action` columns once
    mailqueuer reads them. Full contract in §2.1.
- **Verdict:** **Do not port.** mizu's only responsibility here is to keep
  emitting accurate ingest headers (it already does). Duplicating a per-message
  log in mizu would be redundant. **One dependency to note:** the CSV `country`
  column needs a source — if country is wanted there, mizu should pass it as an
  `X-Mizu-Country`-style header (once GeoIP lands, §3.5) for mailqueuer to record;
  otherwise the field stays blank. No mizu-side logging feature is needed.

---

## 4. Keeping mizu clean — the extension model

### One interface, not ten integrations

Define a small, stable set of session-lifecycle hooks with typed verdicts; every
built-in feature *and* every HTTP backend is just an implementation:

```
OnConnect(ctx)        → accept | reject | annotate
OnMailFrom(ctx)       → accept | reject
OnRcpt(ctx)           → accept | reject | defer
OnData / PostScan(ctx)→ accept | defer | reject | addHeaders   // has rspamd score/symbols
```

Adding a feature never edits `server.go`'s core path — it registers a hook.
Disabled feature = nil/absent hook, never constructed → zero hot-path cost.

### Clean-code rules

1. **No vendor identifiers in core.** `X-Migadu-*` → `[server] header_prefix`;
   `MIGADU_FLOW` → `Direction` enum; every hard-coded domain (`linux.dev`,
   `libre.space`, `jetfood.com`, `iydo.com`, `migadu.com`, `dejanstrbac.com`) →
   config lists. A grep for `migadu` in `pkg/` must return nothing.
2. **Everything default-off, forward-only config** (per CLAUDE.md: add fields to
   `pkg/config/types.go`, defaults in `DefaultConfig()`, validation, and
   `config.toml.example`; no backward-compat fallbacks).
3. **Prefer externalizing policy over embedding it.** Judgment calls / anything
   touching Migadu systems → Tier-B HTTP verdict, not core code.
4. **Build the three shared primitives once** (below); no bespoke Redis/CDB code
   per plugin.

### Three shared primitives to build first (reused everywhere)

- **P1 — External map source:** inline + file + HTTP, atomic hot-reload
  (generalize `rate_limit_whitelist.go`). Used by mxproxy, spamlists, and
  (if kept local) counters limits.
- **P2 — GeoIP/country provider:** MaxMind mmdb. Feeds the flow country header,
  the `X-Mizu-Country` ingest header for mailqueuer, and the geo-velocity check.
- **P3 — HTTP verdict/webhook helper:** clone of the sender/recipient validator
  (URL interpolation, verdict semantics, LRU cache). Used by relay auth,
  suspender, geo suspend, counters notify.

### Where Migadu-specific code ends up (almost none in mizu)

- **Config values** (thresholds, domain lists, header prefix, map paths) → Ansible
  templates.
- **Business decisions** (suspend, org limits+notify, confirmed-redirect
  forwarding, dynamic spamlist content, `migadu.com` case) → the **policy
  backend** behind the HTTP hooks.
- **Per-message logging/audit** → already **mailqueuer** (§3.10).
- **If in-process Migadu logic is ever unavoidable** → a **separate out-of-tree
  module** that imports mizu as a library and registers hooks — *not* `//go:build`
  tags through core.

---

## 5. Summary table & sequencing

| Plugin | Tier | Verdict | Effort | Priority |
|--------|------|---------|--------|----------|
| `migadu_flow` | A | Port (foundational) | S | **1** |
| `migadu_date` | A | Port | XS | 2 |
| `migadu_mxproxy` | A | Port | S–M | 2 |
| `migadu_suspender` | B | Port decision, delegate action | M | 3 |
| `migadu_relay` | B | Delegate (port envelope plumbing) | M | 3 |
| `migadu_geo` | A+B | Port after GeoIP | M | 4 |
| `migadu_spamlists` | A+data | Port engine; learn stays in rspamd | H | 4 |
| `migadu_counters` | B / limiter | Decide vs. rate limiter | M–H | 5 (decision) |
| `migadu_footers` | C | Keep in rspamd | H | — |
| `migadu_logs_writer` | C | **Do not port — mailqueuer owns it** | — | — |

**Phased rollout**

- **Phase 0 — Foundations:** `session.Direction` + flow headers (`migadu_flow`);
  the hook interface (§4); primitive **P1** (external map).
- **Phase 1 — Cheap wins:** `migadu_date`, `migadu_mxproxy`.
- **Phase 2 — Role policy (Tier B):** primitive **P3** (verdict helper), then
  `migadu_suspender`, `migadu_relay`.
- **Phase 3 — GeoIP:** primitive **P2**, then enrich flow/ingest country headers,
  then `migadu_geo`.
- **Phase 4 — Big engine:** `migadu_spamlists`.
- **Phase 5 — Counters decision:** extend the rate limiter, or leave in rspamd.
- **Not planned:** `migadu_footers` (rspamd), `migadu_logs_writer` (mailqueuer).

---

## 6. Open decisions

- **Q1 — counters:** Extend mizu's rate limiter (org dimension + daily window +
  webhook), or keep counters in rspamd/Redis? Charting relies on 31-day
  retention — is that a mailqueuer-ledger concern now rather than mizu's?
- **Q2 — Bayes learning:** `migadu_spamlists`/`migadu_suspender` call
  `task:learn()`. If mizu decides before rspamd, drop learn feedback or add a
  learn-hint to the `/checkv2` request?
- **Q3 — hard-coded exemptions:** Confirm all literal domains become config.
- **Q4 — footers:** Confirm footers stay in rspamd (no MIME-rewrite in mizu).
- **Q5 — country header:** Add `X-Mizu-Country` to the mailqueuer ingest contract
  once GeoIP lands, so mailqueuer's CSV `country` column is populated?

---

## 7. TODO checklist

### Phase 0 — Foundations
- [ ] Define the hook interface (`OnConnect/OnMailFrom/OnRcpt/OnData`) with typed
      verdicts; wire an (empty) registry into the session path with zero cost when
      no hooks are registered.
- [ ] Add `session.Direction` (inbound / outbound / relay / auto) derived from
      role + auth; replace any notion of a "flow" plugin.
- [ ] Config: `[server] header_prefix` (default e.g. `X-Mizu-`); emit
      direction/loop/`Delivered-To` handling via `pkg/smtp/headers.go`.
- [ ] Mail-loop detection on the relay role (`X-...-Redirected-From`).
- [ ] **P1** external-map primitive: inline + file + HTTP source, atomic
      hot-reload snapshot (generalize `rate_limit_whitelist.go`); unit tests.
- [ ] Neutralize naming: ensure no `migadu`/vendor literals in `pkg/`.

### Phase 1 — Cheap wins
- [ ] `rewrite_date_utc` (outbound role) + config flag + tests.
- [ ] Per-recipient-domain inbound IP allowlist (mxproxy) using P1; enforce at
      RCPT; config + `config.toml.example` + tests.

### Phase 2 — Role policy (Tier B)
- [ ] **P3** HTTP verdict/webhook helper (URL interpolation + verdict + LRU
      cache), modeled on `pkg/sender`/`pkg/recipient`.
- [ ] Suspender: evaluate rspamd score/action + trigger symbols from `/checkv2`
      response against config threshold → soft-reject + suspend webhook;
      intra-domain exemption; config for threshold/symbols/URL/whitelist domains.
- [ ] Relay forwarding authorization: port envelope plumbing
      (`X-Envelope-To`/`Delivered-To`/`Auto-Submitted`/plus-suffix); delegate the
      confirmed-redirect decision to the policy backend via P3.

### Phase 3 — GeoIP
- [ ] **P2** GeoIP/country provider (MaxMind mmdb) with config + graceful
      absence.
- [ ] Populate flow country header + add `X-Mizu-Country` to mailqueuer ingest
      (pending Q5).
- [ ] Geo-velocity check: per-user country set in a short window on cluster/stats
      infra; soft-reject + suspend webhook on breach.

### Phase 4 — Spamlists engine
- [ ] Allow/deny/junk regex engine (sigils `! # ? = ~`) matching SMTP+MIME sender
      & recipient → SMTP action; use SPF/DKIM/DMARC results for `~`; intra-domain
      auto-allow; contents via P1.
- [ ] Decide Bayes-learning handling (Q2).
- [ ] Make the `migadu.com` phishing/bounce special-case config/backend, not core.

### Phase 5 — Counters decision
- [ ] Decide (Q1). If porting: add `ORGANIZATION` dimension (domains→account map
      via P1) + daily window + breach webhook to the rate limiter. Else: document
      that counters stay in rspamd and reporting is mailqueuer's.

### Cross-cutting / done-criteria
- [ ] Every feature default-off; disabled = not constructed.
- [ ] Forward-only config (types + defaults + validation + example) per CLAUDE.md.
- [ ] Resolve Q1–Q5 with product before coding the affected items.
- [ ] Confirm no per-message logging is added to mizu (mailqueuer owns it).

---

## 8. What stays out of mizu regardless

Bayes, fuzzy, neural, and the symbol/score engine remain **rspamd's** job (mizu
consumes the result). Per-message traffic logging and the delivery audit ledger
remain **mailqueuer's** job (`internal/stats/writer.go`, `internal/ledger/`).
MIME footer rewriting stays in **rspamd**. mizu ports only the envelope/policy
*mechanism* (flow, date, mxproxy, geo-velocity, spamlists engine) and delegates
the *business rules* (relay auth, suspend, counters) to HTTP policy backends.

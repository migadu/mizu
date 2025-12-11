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
   - Shares connection state and rate limits across cluster nodes
   - Message types: `MessageTypeConnectionState`, `MessageTypeRateLimit`

3. **SMTP Authentication** ([pkg/smtp/auth.go](pkg/smtp/auth.go))
   - `HTTPAuthenticator`: HTTP-based authentication for submission servers (ports 587/465)
   - Supports AUTH PLAIN and AUTH LOGIN mechanisms (LOGIN via custom implementation)
   - Requires TLS before authentication (except in local mode)
   - 5-minute authentication cache to reduce API calls
   - Validates that authenticated users can only send from authorized addresses
   - Adds `X-Auth-User` header to delivery for authenticated messages

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
    "password_hashes": ["$2a$10$...", "$2a$10$..."],  // Array of password hashes (bcrypt, SSHA512, SHA512)
    "allowed_from": ["user@example.com", "alias@example.com"]
  }

  // Response (user not found)
  404 Not Found
  ```
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
  - **429 Too Many Requests**: Rate limit exceeded (temporary failure)
  - **502/503/504**: Temporary backend failures (retry later)
- Response body can be JSON `{"message": "custom text"}` or plain text
- Successful validations cached for 5 minutes (configurable)
- Provides early rejection before DATA phase, reducing bandwidth and processing

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

- Multi-dimensional: Can combine keys (IP, FROM, FROM_DOMAIN, TO, TO_DOMAIN)
- Sliding window algorithm
- Gossip-based cluster-wide enforcement (optional)
- Configured via `smtp.rate_limit.dimensions` array

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
- Go version: 1.24.1
- Key dependencies:
  - `emersion/go-smtp` - SMTP protocol implementation
  - `emersion/go-msgauth` - SPF/DKIM/DMARC validation
  - `hashicorp/memberlist` - Distributed cluster coordination
  - `caddyserver/certmagic` - TLS certificate automation
  - `minio/minio-go` - S3 client
  - `prometheus/client_golang` - Metrics

## Version Information

Build-time version injection via linker flags in Makefile:
- `VERSION`, `COMMIT`, `DATE` variables set in both `cmd/mizu-server/main.go` and `cmd/mizu-admin/main.go`
- Access via: `./mizu-server --version` or `./mizu-admin --version`

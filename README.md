# Mizu - High-Performance, Distributed SMTP Relay Server

Mizu is a production-ready, high-performance SMTP relay server designed for reliability and security. It accepts incoming emails via SMTP and synchronously forwards them to a configured backend via HTTP POST. Mizu guarantees zero message loss by confirming successful delivery to your backend before acknowledging receipt to the sender.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## ✨ Key Features

### 🔒 Security & Anti-Spam

- **Mandatory STARTTLS** with automatic Let's Encrypt certificate management.
- **SMTP Authentication** (AUTH PLAIN, AUTH LOGIN) for submission servers (ports 587/465):
  - GET-based authentication API with local password verification (passwords never sent over network)
  - Supports bcrypt, SSHA512, and SHA512 password hashes
  - Multiple passwords per user (backend returns array of hashes, tries all until match)
  - Per-user rate limiting and sender address validation
  - 5-minute authentication caching to reduce API load
  - Authenticated username passed to delivery backend via `X-Auth-User` header
- **SPF, DKIM & DMARC Validation** with alignment checking.
- **ARC (Authenticated Received Chain)** validation and signing for preserving authentication through forwarding.
- **DNS Blacklists (RBL/DNSBL)** support (e.g., Spamhaus).
- **Reverse DNS and Sender MX Validation**.
- **Header Validation** with configurable handling of missing headers:
  - **Submission mode**: Reject malformed messages missing required headers (Message-ID, Date)
  - **Relay mode**: Automatically fix missing headers before forwarding
  - **Configurable**: Choose "reject", "fix", or "none" per server via `[server.validation]`
- **Null Sender Control**: Configurable acceptance of bounce messages with null sender `<>`
- **Custom DNS Resolvers** to globally use providers like Cloudflare or Google.

### 🛡️ DoS Protection & Rate Limiting

- **Connection Limiting**: Global and per-IP concurrent connection limits.
- **Rate Limiting**: Sliding window algorithm (connections/minute per IP).
- **Distributed State**: Rate limiting and connection tracking state is shared across the cluster using a P2P gossip protocol for cluster-wide enforcement.
- **Circuit Breaker**: Protects your backend from being overwhelmed during failures while still allowing retries to continue.

### 📊 Reputation & Intelligence

- **Real-time Reputation Tracking**: Scores IPs and domains to identify bad actors.
- **Distributed Stats Sync**: Reputation data is shared across the cluster via S3.
- **Automatic Blocking**: Malicious actors are automatically blocked based on reputation.
- **Recipient Caching**: Caches backend responses (e.g., 404/403) cluster-wide to reduce redundant checks.

### 🔄 High Availability & Resilience

- **Distributed by Design**: Built for multi-instance deployments with P2P coordination.
- **Graceful Shutdown**: Waits for active sessions to complete before shutting down.
- **Health Monitoring**: HTTP health check endpoints provide detailed component status.
- **Panic Recovery**: Prevents server crashes and WaitGroup leaks, with stack trace logging.

### 🔧 Operational Excellence

- **Structured Logging**: JSON or text format with trace IDs for easy correlation.
- **Admin CLI**: A dedicated tool (`mizu-admin`) for health checks, stats, and operational tasks.
- **HTTP Basic Auth**: Protects health and API endpoints.
- **Comprehensive Testing**: Over 100 tests, including integration and E2E tests.

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/[organization]/mizu.git
cd mizu

# Build the server and admin CLI
go build -o ./bin/mizu ./cmd/mizu-server
go build -o ./bin/mizu-admin ./cmd/mizu-admin

# The binaries will be in the ./bin directory
```

### 2. Configuration

Generate an example configuration file:
```bash
./bin/mizu generate-config > config.toml
```

Edit `config.toml` with your settings. A minimal configuration requires:

**Relay Server (Port 25 - MX):**
```toml
[defaults]
domain = "mail.example.com"

[[server]]
name = "mx-primary"
type = "relay"
listen_addr = ":25"

[server.delivery]
url = "https://your-backend.example.com/email"
auth_token = "${DELIVERY_AUTH_TOKEN}"  # Use env var in production
max_retry_attempts = 3
http_timeout_seconds = 30

[server.delivery.circuit_breaker]
enabled = true
failure_threshold = 5
timeout_seconds = 30

[tls]
email = "admin@example.com" # For Let's Encrypt

[storage]
backend = "s3"  # or "filesystem" for single-node
s3_bucket = "your-s3-bucket-for-certs-and-stats"
s3_access_key = "${S3_ACCESS_KEY}"      # Use env var
s3_secret_key = "${S3_SECRET_KEY}"  # Use env var
```

**Submission Server (Port 587/465 - With Authentication):**
```toml
[[server]]
name = "submission-tls"
type = "submission"
listen_addr = ":465"

[server.auth]
enabled = true
required = true  # Require authentication before sending
url = "https://auth.example.com/api/validate"
auth_token = "${AUTH_TOKEN}"

[server.tls]
mode = "implicit"  # Always-on TLS for port 465

[server.delivery]
url = "https://your-backend.example.com/email"
auth_token = "${DELIVERY_AUTH_TOKEN}"
# Authenticated user passed as X-Auth-User header

[[server.rate_limit.dimensions]]
name = "per_user_hourly"
keys = ["AUTHENTICATED_USER"]
limit = 100  # 100 emails per hour per user
window_seconds = 3600
```

### 3. Run Mizu

```bash
# Run in production mode
./bin/mizu --config ./config.toml

# Run in local development mode (disables TLS, dumps emails to terminal)
./bin/mizu --local
```

## 📚 Documentation

Comprehensive guides for deploying and operating Mizu:

- **[Documentation Home](docs/)** - Complete documentation portal
- **[Deployment Guide](docs/deployment/)** - Single-node and clustered deployment
- **[Configuration Reference](docs/configuration/)** - All configuration options
- **[Operations Guide](docs/operations/)** - Day-to-day operations and troubleshooting
- **[Monitoring Guide](docs/operations/monitoring.md)** - Prometheus metrics and health checks

Quick links:
- [Single Node Deployment](docs/deployment/single-node.md)
- [Monitoring & Metrics](docs/operations/monitoring.md)
- [Configuration Examples](config.toml.example)

### Environment Variables

For enhanced security, critical secrets like API keys and S3 credentials can be provided via environment variables.

- `DELIVERY_AUTH_TOKEN`: Authentication token for the backend delivery endpoint
- `AUTH_TOKEN`: Authentication token for the authentication endpoint (submission servers)
- `RECIPIENT_VALIDATION_AUTH_TOKEN`: Authentication token for recipient validation endpoint (if enabled)
- `S3_ACCESS_KEY`: AWS/S3 access key
- `S3_SECRET_KEY`: AWS/S3 secret access key
- `HEALTH_PASSWORD`: Password for the health/API endpoints if basic auth is enabled
- `CLUSTER_SECRET_KEY`: Secret key for cluster gossip encryption (if cluster mode enabled)

## 🚀 Production Deployment

For production, we recommend running a cluster of at least 3 Mizu instances for high availability.

- **Load Balancing**: Use DNS round-robin to distribute SMTP traffic across your instances.
- **Cluster Mode**: Enable cluster mode in the configuration to allow instances to coordinate via P2P gossip.
- **Shared Storage**: Configure all instances to use the same S3 bucket for distributed certificate management and reputation stats.
- **Systemd**: Run Mizu as a `systemd` service for automatic restarts.

See the **Production Checklist** in the [Architecture](#-architecture) section for more details.

## 📊 Monitoring & Observability

Mizu provides comprehensive monitoring through:

- **Prometheus Metrics**: Detailed metrics for SMTP, validation, circuit breaker, and rate limiting
- **Health Check Endpoint**: HTTP endpoint for load balancers and monitoring systems
- **Admin CLI**: Command-line tool for operational tasks
- **Structured Logging**: JSON logs with trace IDs for correlation

See the [Monitoring Guide](docs/operations/monitoring.md) for complete details.

### Quick Monitoring

```bash
# Check health
curl http://localhost:8080/health

# View Prometheus metrics
curl http://localhost:8080/metrics

# Use admin tool
mizu-admin -server http://localhost:8080 -config config.toml stats
```

### Key Metrics
- `mizu_smtp_connections_total`: Total SMTP connections
- `mizu_smtp_messages_received`: Messages received
- `mizu_smtp_messages_rejected`: Messages rejected (with reason labels)
- `mizu_circuit_breaker_state`: Circuit breaker state
- `mizu_rate_limit_exceeded`: Rate limit violations
- `mizu_smtp_spf_checks`, `mizu_smtp_dkim_checks`, `mizu_smtp_dmarc_checks`, `mizu_smtp_arc_checks`: Validation results

## 🔧 Admin CLI

Mizu includes a command-line tool, `mizu-admin`, for operational tasks.

```bash
# Check health of a remote Mizu instance
./bin/mizu-admin health --addr http://localhost:8080

# View stats
./bin/mizu-admin stats --addr http://localhost:8080

# List blocked IPs
./bin/mizu-admin blocked-ips --addr http://localhost:8080

# Flush recipient cache (distributed mode)
./bin/mizu-admin flush-cache --addr http://localhost:8080

# Use with authentication
./bin/mizu-admin health --addr http://localhost:8080 -u admin -p changeme
```

## 🧪 Testing

Mizu has a comprehensive test suite.

```bash
# Run all tests
make test

# Run tests with the race detector
go test -race ./...

# Run integration tests for the SMTP package
go test ./pkg/smtp -run E2E -v
```

You can also perform a manual test using `telnet` while Mizu is running in local mode.
```bash
./bin/mizu --local &
telnet localhost 25
```
Example SMTP session:
```
EHLO test.local
MAIL FROM:<sender@example.com>
RCPT TO:<recipient@example.com>
DATA
Subject: Test Email

This is a test.
.
QUIT
```

## 🏗️ Architecture

```
┌─────────────┐              ┌──────────────┐
│   Internet  │              │ Email Clients│
│  (MX Mail)  │              │ (Submission) │
└──────┬──────┘              └──────┬───────┘
       │                             │
       │ Port 25 (STARTTLS)          │ Port 587/465 (TLS + AUTH)
       │                             │
       ▼                             ▼
┌──────────────────────────────────────────────────┐
│            Mizu SMTP Relay Cluster               │
│                                                  │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐          │
│  │ Mizu #1 │  │ Mizu #2 │  │ Mizu #3 │          │
│  │ MX:25   │  │ MX:25   │  │ MX:25   │          │
│  │ Sub:587 │  │ Sub:587 │  │ Sub:587 │          │
│  │ Sub:465 │  │ Sub:465 │  │ Sub:465 │          │
│  └─────────┘  └─────────┘  └─────────┘          │
│       │            │            │                │
│       └────────────┼────────────┘                │
│              P2P Gossip                          │
│ (Connections, Rate Limits, Reputation, Auth)     │
└─────────────────┬────────────────────────────────┘
                  │
        ┌─────────┴─────────┬──────────────┐
        │                   │              │
        ▼                   ▼              ▼
   ┌─────────┐         ┌─────────┐   ┌──────────┐
   │   S3    │         │  HTTP   │   │   Auth   │
   │  Certs  │         │ Backend │   │ Backend  │
   │  Stats  │         │Endpoint │   │(Submit)  │
   └─────────┘         └─────────┘   └──────────┘
```

### Core Design Principles

1.  **Zero Message Loss**: The SMTP `250 OK` response is sent **only after** receiving a successful HTTP `200` or `202` from the destination backend. No internal queue - delivery is synchronous with immediate retry logic (exponential backoff: 1s, 2s, 4s...).
2.  **Synchronous Delivery**: Messages are delivered during the SMTP session without internal queues. If backend is temporarily unavailable, SMTP returns `4xx` error and sender's MTA retries per RFC 5321 (24-48 hour retry window).
3.  **Circuit Breaker Protection**: Protects backend during failures WITHOUT blocking retries. Circuit breaker wraps each individual retry attempt - when open, retries continue but fail fast to prevent overwhelming the backend.
4.  **Production Ready**: Features comprehensive error handling, panic recovery, and graceful shutdowns.
5.  **Distributed Architecture**: Designed from the ground up for multi-instance deployments.
6.  **Security First**: Enforces TLS and a strict regimen of anti-spam and sender validation checks.

### Message Flow

**Relay Server (Port 25):**
1.  **SMTP Reception**: Accept connection and check against connection and rate limits.
2.  **Security Validation**: Perform rDNS, DNSBL, SPF, DKIM, DMARC, and ARC checks.
3.  **Content Validation**: Validate headers (From, Date, Message-ID), size, and check for duplicates. Missing headers automatically fixed.
4.  **Synchronous Delivery**: Send the message to the destination via HTTP POST with retry logic.
5.  **SMTP Response**: `250 OK` only if HTTP delivery succeeded.
6.  **Stats Recording**: Update reputation scores and sync to the cluster.

**Submission Server (Port 587/465):**
1.  **SMTP Reception**: Accept connection, require TLS.
2.  **Authentication**: Require SMTP AUTH (PLAIN/LOGIN), validate credentials against auth backend.
3.  **Sender Validation**: Verify authenticated user can send from specified FROM address.
4.  **Per-User Rate Limiting**: Check per-user email sending limits.
5.  **Content Validation**: Validate headers, reject missing Message-ID/Date.
6.  **Synchronous Delivery**: Send to backend with `X-Auth-User` header containing authenticated username.
7.  **SMTP Response**: `250 OK` only if HTTP delivery succeeded.

## 🎯 Architecture Decisions

### No Internal Message Queue (By Design)

Mizu operates as a **synchronous SMTP relay** without an internal message queue. This is an intentional architectural decision:

**How it works:**
- Messages are delivered to the backend during the SMTP session
- SMTP `250 OK` sent ONLY after successful HTTP delivery
- If backend fails after all retries, SMTP returns `4xx`/`5xx` error
- Sender's MTA retries per RFC 5321 (standard 24-48 hour window)

**Why no queue:**
- **Simplicity**: No persistent queue to manage, monitor, or recover
- **Immediate feedback**: Sender knows delivery status immediately
- **Backend responsibility**: Routing and queuing handled by backend (e.g., Cloudflare Workers)
- **Zero message loss**: Relies on standard SMTP retry behavior + backend high availability

**Message loss prevention:**
- ✅ Backend temporarily down (<48 hours): Sender MTA retries → **No loss**
- ✅ Transient failures (network blips, timeouts): Mizu retries immediately → **No loss**
- ❌ Backend down >48 hours continuously: Sender MTA gives up → **Loss expected**
  - **Solution**: Focus on backend high availability (99.9%+ uptime)

**When to use Mizu:**
- Backend has high availability (>99.9% uptime)
- Backend can handle routing/forwarding logic
- You want simple, stateless relay architecture
- You prefer standard SMTP semantics over async queuing

## 🤝 Contributing

Contributions are welcome! Before submitting a pull request, please:

1.  Review the architecture and design principles.
2.  Ensure all existing tests pass by running `make test`.
3.  Add new tests for any new features or bug fixes.
4.  Follow the existing code style and patterns.
5.  Update documentation if necessary.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🙏 Credits

Mizu is built on several excellent open-source libraries, including:
- [caddyserver/certmagic](https://github.com/caddyserver/certmagic) for automatic TLS.
- [emersion/go-smtp](https://github.com/emersion/go-smtp) for the core SMTP server implementation.
- [emersion/go-msgauth](https://github.com/emersion/go-msgauth) for DMARC, DKIM, and SPF validation.
- [minio/minio-go](https://github.com/minio/minio-go) for the S3 client.
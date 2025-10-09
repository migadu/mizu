# Queue Features Guide

This document provides an overview of advanced queue features in Mizu, including Dead Letter Queue (DLQ) management and job prioritization.

## Features Overview

### Dead Letter Queue (DLQ)
When email delivery jobs fail permanently (after exhausting retries), they are moved to the DLQ for manual review and management.

**Key capabilities:**
- 7-day retention for failed jobs
- CLI and API management
- Health monitoring and alerting
- Comprehensive metrics

**Documentation:**
- [DLQ Management Guide](operations/dlq-management.md)
- [DLQ Monitoring and Alerting](monitoring/dlq-monitoring.md)

### Job Prioritization
Process emails by priority instead of strict FIFO order, ensuring time-sensitive emails are delivered faster.

**Key capabilities:**
- Priority-based job ordering (0-100 scale)
- Configurable via routing service
- Dual-mode workers (FIFO or Priority)
- Backward compatible

**Documentation:**
- [Job Prioritization Guide](configuration/job-prioritization.md)

## Quick Start

### Enable DLQ Management

DLQ is automatically available when using persistent queue:

```toml
[queue]
enabled = true
data_dir = "./data/queue"
```

**CLI Commands:**
```bash
# List failed jobs
./mizu-admin dlq list

# Inspect specific job
./mizu-admin dlq inspect <job-id>

# Reprocess failed job
./mizu-admin dlq reprocess <job-id>

# Delete from DLQ
./mizu-admin dlq delete <job-id>
```

### Enable Job Prioritization

```toml
[queue]
enabled = true
priority_mode = true    # Enable priority-based processing
```

**Routing Service Integration:**
```json
{
  "accepted": true,
  "deliver_to": ["user@domain.com"],
  "priority": 15,  // 0-100, higher = more urgent
  "delivery_endpoint": "https://api.example.com/deliver"
}
```

## Architecture

### Queue Processing Flow

```
┌──────────────┐
│ SMTP Session │
└──────┬───────┘
       │ Email Accepted
       ▼
┌──────────────┐
│ Routing      │ ← Assigns Priority
│ Service      │
└──────┬───────┘
       │ Creates DeliveryJob
       ▼
┌──────────────┐
│ Persistent   │
│ Queue        │
│ (BadgerDB)   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Scheduler    │ ← Gets due jobs (time-based)
└──────┬───────┘
       │
       ▼
   ┌───────────────────┐
   │   FIFO Mode       │   Priority Mode
   │                   │
   │ Time-ordered      │   Priority-ordered
   │ Channel           │   Heap Queue
   └───────┬───────────┘
           │
           ▼
   ┌────────────────┐
   │ Worker Pool    │
   │ (10 workers)   │
   └───────┬────────┘
           │
           ▼
   ┌────────────────┐
   │ HTTP Delivery  │
   └───────┬────────┘
           │
      ┌────┴─────┐
      │          │
   Success     Failure
      │          │
      ▼          ▼
  Delete    Retry Schedule
   Job          │
                ▼
            ┌───────────┐
            │ Retries   │
            │ Exhausted?│
            └─────┬─────┘
                  │
                  ▼ Yes
            ┌───────────┐
            │    DLQ    │
            │ (7 days)  │
            └───────────┘
```

### DLQ Lifecycle

```
Active Job
    │
    ├─ Retry 1 → Fail
    ├─ Retry 2 → Fail
    ├─ ...
    └─ Retry 39 → Fail (after 48h)
         │
         ▼
    ┌─────────────────────────┐
    │       Move to DLQ       │
    │  (with failure reason)  │
    └───────┬─────────────────┘
            │
            ▼
    ┌─────────────────────────┐
    │     DLQ Storage         │
    │   (7-day retention)     │
    └─────┬───────────────────┘
          │
          ├─ Inspect
          ├─ Reprocess → Active Queue
          ├─ Delete → Permanent removal
          └─ Auto-expire (7 days) → Deleted
```

## Configuration Reference

### Queue Configuration

```toml
[queue]
# Required
enabled = true                     # Enable persistent queue
data_dir = "./data/queue"          # BadgerDB storage directory

# Worker configuration
workers = 10                       # Concurrent workers
max_retry_hours = 48               # Max retry time (DLQ after)
shutdown_timeout_seconds = 30      # Graceful shutdown timeout

# Priority processing (optional)
priority_mode = false              # Enable priority-based processing
```

### Health Check Configuration

```go
// Server initialization
dlqChecker := health.NewCheckDLQ(
    dlqProvider,
    50,                // Warn threshold (entries)
    100,               // Error threshold (entries)
    24 * time.Hour,    // Age threshold
)

healthServer.AddChecker(dlqChecker)
```

## Metrics Reference

### DLQ Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `mizu_queue_jobs_dlq` | Gauge | Current DLQ size |
| `mizu_queue_dlq_moved_total{reason}` | Counter | Jobs moved to DLQ by reason |
| `mizu_queue_dlq_reprocessed_total` | Counter | Jobs reprocessed from DLQ |
| `mizu_queue_dlq_deleted_total` | Counter | Jobs deleted from DLQ |
| `mizu_queue_dlq_oldest_age_seconds` | Gauge | Age of oldest DLQ entry |

### Queue Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `mizu_queue_jobs_active` | Gauge | Current active jobs |
| `mizu_queue_jobs_total` | Counter | Total jobs enqueued |
| `mizu_queue_jobs_delivered_total` | Counter | Total successful deliveries |
| `mizu_queue_jobs_failed_total` | Counter | Total permanent failures |
| `mizu_queue_jobs_retries_total` | Counter | Total retry attempts |
| `mizu_queue_workers` | Gauge | Active worker count |

## Common Use Cases

### Use Case 1: Monitoring Failed Deliveries

**Scenario:** Backend service was down for maintenance, emails failed

**Solution:**
1. Check DLQ: `./mizu-admin dlq list`
2. Verify backend is healthy
3. Reprocess all DLQ entries:
   ```bash
   for job_id in $(./mizu-admin dlq list | tail -n +4 | awk '{print $1}'); do
       ./mizu-admin dlq reprocess $job_id
   done
   ```

### Use Case 2: Prioritizing Transactional Emails

**Scenario:** Marketing emails are delaying password reset emails

**Solution:**
1. Enable priority mode in config:
   ```toml
   [queue]
   priority_mode = true
   ```

2. Configure routing service:
   ```go
   func determinePriority(req ResolveRequest) int {
       if strings.Contains(req.Subject, "password reset") {
           return 15  // Urgent
       }
       if strings.Contains(req.Sender, "marketing@") {
           return 2   // Low priority
       }
       return 5  // Normal
   }
   ```

3. Restart server

### Use Case 3: Alerting on DLQ Growth

**Scenario:** Want to be notified when DLQ grows unexpectedly

**Solution:**
1. Add Prometheus alert:
   ```yaml
   - alert: DLQSizeHigh
     expr: mizu_queue_jobs_dlq > 50
     for: 30m
     labels:
       severity: warning
   ```

2. Configure Alertmanager routing

3. Set up Slack/PagerDuty notifications

### Use Case 4: Investigating Failure Patterns

**Scenario:** Multiple jobs failing for unknown reason

**Solution:**
1. Query failure reasons:
   ```promql
   sum by (reason) (rate(mizu_queue_dlq_moved_total[1h]))
   ```

2. Check most common reason:
   ```promql
   topk(1, rate(mizu_queue_dlq_moved_total[1h])) by (reason)
   ```

3. Inspect sample jobs:
   ```bash
   ./mizu-admin dlq list
   ./mizu-admin dlq inspect <job-id>
   ```

4. Take corrective action based on reason

## API Reference

### DLQ Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dlq` | GET | List DLQ entries (supports `?limit=N`) |
| `/api/dlq/{job-id}` | GET | Get specific DLQ entry |
| `/api/dlq/{job-id}` | POST | Reprocess job (move to active queue) |
| `/api/dlq/{job-id}` | DELETE | Permanently delete DLQ entry |

**Authentication:** HTTP Basic Auth (same as `/health` endpoint)

**Example:**
```bash
curl -u admin:password http://localhost:8080/api/dlq?limit=10
```

### Health Endpoint

Check DLQ health status:

```bash
curl -u admin:password http://localhost:8080/health
```

Response includes `dead_letter_queue` component with status and details.

## Priority Levels Reference

| Range | Level | Use Cases | Examples |
|-------|-------|-----------|----------|
| 0-4 | Low | Bulk, newsletters | Marketing campaigns |
| 5-9 | Normal | Standard emails | User-to-user communication |
| 10-14 | High | Transactional | Order confirmations, receipts |
| 15-19 | Urgent | Time-sensitive | OTP codes, password resets |
| 20+ | Critical | Emergency | Security alerts, system failures |

**Default:** Priority 0 if not specified by routing service

## Troubleshooting

### DLQ Not Available

**Error:** `DLQ not available (persistent queue required)`

**Solution:** Enable persistent queue:
```toml
[queue]
enabled = true
data_dir = "./data/queue"
```

### Priority Not Working

**Symptoms:** All jobs processed in FIFO order

**Solutions:**
1. Verify `priority_mode = true` in config
2. Check routing service returns `priority` field
3. Restart server after config changes

### High DLQ Size

**Symptoms:** DLQ growing rapidly

**Investigation:**
1. Check backend health
2. Review failure reasons via metrics
3. Check circuit breaker state
4. Review recent deployments

**Actions:**
- Fix underlying service issues
- Reprocess once resolved
- Consider scaling backend if needed

## Performance Considerations

### DLQ Storage
- Uses BadgerDB with 7-day TTL
- Minimal performance impact (async operations)
- Scales to millions of entries

### Priority Mode
- **FIFO Mode**: O(1) enqueue/dequeue
- **Priority Mode**: O(log n) enqueue/dequeue
- Negligible impact at < 100k emails/hour
- Use FIFO if all emails have equal priority

## Best Practices

### DLQ Management
1. Review DLQ daily
2. Set up alerts for size and age thresholds
3. Document common failure patterns
4. Automate cleanup of known invalid entries

### Priority Assignment
1. Use full priority range (0-20)
2. Don't mark everything as high priority
3. Document your priority scheme
4. Monitor priority distribution

### Monitoring
1. Set up all recommended Prometheus alerts
2. Create Grafana dashboards
3. Configure alert routing (PagerDuty, Slack)
4. Track DLQ trends over time

### Operations
1. Maintain runbooks for common issues
2. Script repetitive operations
3. Regular backup of queue data
4. Test DLQ procedures periodically

## See Also

- [DLQ Management Guide](operations/dlq-management.md)
- [DLQ Monitoring](monitoring/dlq-monitoring.md)
- [Job Prioritization](configuration/job-prioritization.md)
- [Queue Configuration](configuration/queue.md)
- [Routing Configuration](configuration/routing.md)
- [Metrics Guide](monitoring/metrics.md)
- [Health Checks](monitoring/health-checks.md)

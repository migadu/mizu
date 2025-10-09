# Dead Letter Queue (DLQ) Management

The Dead Letter Queue (DLQ) is a critical component for managing failed email deliveries in Mizu. When jobs exceed retry limits or encounter permanent failures, they are moved to the DLQ for inspection, reprocessing, or deletion.

## Overview

### What is the DLQ?

The DLQ stores delivery jobs that have permanently failed after exhausting all retry attempts. Jobs in the DLQ:

- Are retained for **7 days** before automatic expiration
- Include the original job data and failure reason
- Can be inspected, reprocessed, or deleted
- Do not consume active queue resources

### When Jobs Move to DLQ

Jobs are moved to the DLQ when:

1. **Time-based expiration**: Job age exceeds `max_retry_hours` (default: 48 hours)
2. **Permanent HTTP errors**: Backend returns 404, 410, or other permanent failures
3. **Circuit breaker exhaustion**: All retries fail while circuit breaker is open
4. **Manual intervention**: Operator moves job to DLQ via API

## CLI Operations

### List DLQ Entries

View all jobs currently in the DLQ:

```bash
./mizu-admin dlq list

# Output:
Dead Letter Queue (3 entries)

JOB ID      FROM                    RECIPIENTS              ATTEMPTS  REASON                          MOVED AT             EXPIRES
──────      ────                    ──────────              ────────  ──────                          ────────             ───────
abc123...   sender@example.com      user@domain.com         39        Exceeded max retry hours (48h)  2024-10-08 14:30:00  2024-10-15 14:30:00
def456...   marketing@example.com   bulk@lists.com          25        Permanent HTTP 404 error        2024-10-08 12:15:00  2024-10-15 12:15:00
ghi789...   alerts@example.com      admin@domain.com        15        Circuit breaker open            2024-10-08 10:00:00  2024-10-15 10:00:00
```

### Inspect DLQ Entry

View detailed information about a specific failed job:

```bash
./mizu-admin dlq inspect abc123-456-789

# Output:
DLQ Entry Details
=================

Job ID:           abc123-456-789-def
From:             sender@example.com
Original To:      user@domain.com
Recipients:       user@domain.com, user2@domain.com
Endpoint:         https://api.example.com/deliver
Is Forwarding:    false
Is Custom Endpoint: false
Is Junk:          false

Attempts:         39
Max Attempts:     0
Created At:       2024-10-06 14:30:00
Last Attempt:     2024-10-08 14:15:00

Moved to DLQ:     2024-10-08 14:30:00
Expires At:       2024-10-15 14:30:00
Reason:           Exceeded max retry hours (48h)

Email Content Preview:
----------------------
Subject: Important Message
From: sender@example.com
To: user@domain.com

[Email body content...]
```

### Reprocess DLQ Entry

Move a job back to the active queue for retry:

```bash
./mizu-admin dlq reprocess abc123-456-789

# Output:
Reprocessing job abc123-456-789...
✓ Job moved back to active queue for reprocessing
  Job abc123-456-789 moved back to active queue for reprocessing
```

**What happens during reprocessing:**
- Job is removed from DLQ
- Job is added back to active queue
- Attempts counter is reset to 0
- NextRetry is set to immediate (now)
- CreatedAt is reset to current time (extends retry window)
- Job will be retried according to normal retry schedule

**When to reprocess:**
- Backend service was down temporarily and is now restored
- Infrastructure issue has been resolved
- Email was blocked due to temporary policy that's been lifted
- You want to give the job another chance after fixing the root cause

### Delete DLQ Entry

Permanently remove a job from the DLQ:

```bash
./mizu-admin dlq delete abc123-456-789

# Output:
Deleting DLQ entry abc123-456-789...
Warning: This permanently deletes the job and cannot be undone.
Continue? (y/N): y
✓ DLQ entry deleted successfully
```

**Note:** Deletion is permanent and cannot be undone. The email content and metadata will be lost.

## API Operations

The DLQ can also be managed via HTTP API endpoints.

### List DLQ Entries

```bash
curl -u admin:password http://localhost:8080/api/dlq

# With limit:
curl -u admin:password "http://localhost:8080/api/dlq?limit=50"
```

Response:
```json
{
  "status": "success",
  "entries": [
    {
      "job": {
        "id": "abc123-456-789",
        "from": "sender@example.com",
        "recipients": ["user@domain.com"],
        "endpoint": "https://api.example.com/deliver",
        "attempts": 39,
        "created_at": "2024-10-06T14:30:00Z",
        "priority": 5
      },
      "reason": "Exceeded max retry hours (48h)",
      "moved_at": "2024-10-08T14:30:00Z",
      "expires_at": "2024-10-15T14:30:00Z"
    }
  ]
}
```

### Get DLQ Entry

```bash
curl -u admin:password http://localhost:8080/api/dlq/abc123-456-789
```

### Reprocess DLQ Entry

```bash
curl -X POST -u admin:password http://localhost:8080/api/dlq/abc123-456-789
```

### Delete DLQ Entry

```bash
curl -X DELETE -u admin:password http://localhost:8080/api/dlq/abc123-456-789
```

## Monitoring

### Health Checks

The DLQ health checker monitors queue health and alerts on issues:

```bash
./mizu-admin health

# Output includes:
✓ dead_letter_queue  healthy  {"entries": 0, "message": "DLQ is empty"}

# Or with issues:
⚠ dead_letter_queue  degraded {"entries": 75, "oldest_age_hours": 36.5,
                                "message": "DLQ has 75 entries (warning threshold: 50)",
                                "age_warning": "Oldest entry is 36 hours old (threshold: 24 hours)"}
```

**Health States:**
- `healthy`: DLQ empty or below warning threshold
- `degraded`: DLQ exceeds warning threshold or has old entries
- `unhealthy`: DLQ exceeds error threshold
- `disabled`: Persistent queue not enabled

### Prometheus Metrics

Track DLQ operations and size:

```promql
# Current DLQ size (gauge)
mizu_queue_jobs_dlq

# Jobs moved to DLQ by reason (counter)
mizu_queue_dlq_moved_total{reason="expired_after_48h"}
mizu_queue_dlq_moved_total{reason="permanent_http_404"}
mizu_queue_dlq_moved_total{reason="circuit_breaker_open"}

# DLQ operations (counters)
mizu_queue_dlq_reprocessed_total
mizu_queue_dlq_deleted_total

# Age of oldest entry (gauge, seconds)
mizu_queue_dlq_oldest_age_seconds
```

### Alerting Examples

Create alerts for DLQ issues:

```yaml
# Alert if DLQ has stale jobs (> 24 hours old)
- alert: DLQStaleJobs
  expr: mizu_queue_dlq_oldest_age_seconds > 86400
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "DLQ has jobs stuck for over 24 hours"
    description: "Oldest DLQ entry is {{ $value | humanizeDuration }} old"

# Alert if DLQ is growing too large
- alert: DLQSizeHigh
  expr: mizu_queue_jobs_dlq > 100
  for: 30m
  labels:
    severity: critical
  annotations:
    summary: "DLQ has {{ $value }} entries"
    description: "DLQ size exceeds threshold, investigate failed deliveries"

# Track failure patterns
- alert: HighDLQMovementRate
  expr: rate(mizu_queue_dlq_moved_total[5m]) > 1
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "High rate of jobs moving to DLQ"
    description: "{{ $value }} jobs/sec moving to DLQ, check backend health"
```

## Common Failure Reasons

### Time-Based Expiration

**Reason:** `Exceeded max retry hours (48h)`

**Cause:** Job has been retrying for 48 hours (or configured `max_retry_hours`) without success.

**Investigation:**
1. Check if backend was down during this period
2. Review backend logs for errors
3. Check network connectivity issues
4. Verify endpoint URL is correct

**Resolution:**
- Fix backend service
- Run `dlq reprocess` to retry the job

### Permanent HTTP Errors

**Reason:** `Permanent HTTP 404 error` / `Permanent HTTP 410 error`

**Cause:** Backend returned a permanent error status code indicating the resource doesn't exist or is gone.

**Investigation:**
1. Verify the delivery endpoint URL
2. Check if the recipient exists in your system
3. Review backend API changes

**Resolution:**
- If recipient no longer exists, delete the DLQ entry
- If endpoint changed, update routing configuration
- Do not reprocess unless the issue is fixed

### Circuit Breaker Open

**Reason:** `Circuit breaker open`

**Cause:** Too many consecutive failures caused the circuit breaker to open, preventing further attempts.

**Investigation:**
1. Check circuit breaker metrics
2. Review backend service health
3. Check for cascading failures

**Resolution:**
- Wait for backend service to recover
- Monitor circuit breaker metrics
- Once backend is healthy, reprocess DLQ entries

## Best Practices

### Regular Monitoring

1. **Set up alerts**: Monitor DLQ size and age metrics
2. **Daily reviews**: Check DLQ daily for patterns
3. **Trend analysis**: Track `dlq_moved_total` by reason to identify systemic issues

### Handling DLQ Entries

1. **Investigate first**: Always understand why a job failed before reprocessing
2. **Batch operations**: Use API for bulk reprocessing if needed
3. **Clean up old entries**: Delete entries that are no longer relevant
4. **Document patterns**: Keep track of common failure modes

### Preventive Measures

1. **Backend monitoring**: Monitor delivery endpoint health proactively
2. **Circuit breaker tuning**: Adjust thresholds based on your backend's characteristics
3. **Retry configuration**: Tune `max_retry_hours` based on your SLA requirements
4. **Routing validation**: Ensure routing service returns valid endpoints

### When to Reprocess vs Delete

**Reprocess when:**
- Backend service was temporarily down
- Infrastructure issue has been fixed
- Transient network errors occurred
- Policy changes allow previously blocked emails

**Delete when:**
- Recipient no longer exists
- Email is outdated or irrelevant
- Permanent configuration error (wrong endpoint)
- Spam or unwanted email

## Configuration

### Health Checker Thresholds

Configure DLQ health checker in server code:

```go
dlqChecker := health.NewCheckDLQ(
    dlqProvider,
    50,                // Warn threshold (entries)
    100,               // Error threshold (entries)
    24 * time.Hour,    // Age threshold
)
```

### Retention Period

DLQ entries are retained for **7 days** (hardcoded). After expiration:
- Entry is automatically deleted from DLQ
- Email content is permanently removed
- No recovery is possible

## Troubleshooting

### "DLQ not available" Error

**Cause:** Persistent queue is not enabled.

**Solution:** Enable persistent queue in `config.toml`:
```toml
[queue]
enabled = true
data_dir = "./data/queue"
```

### High DLQ Growth Rate

**Symptoms:** DLQ size increasing rapidly

**Investigation:**
1. Check backend service health
2. Review recent `dlq_moved_total` by reason
3. Check circuit breaker state
4. Review recent configuration changes

**Actions:**
- Investigate most common failure reason
- Fix underlying service issues
- Consider reprocessing once fixed

### Old DLQ Entries Not Expiring

**Symptoms:** Entries older than 7 days still in DLQ

**Cause:** BadgerDB garbage collection may be delayed

**Solution:**
- Entries will expire eventually (BadgerDB TTL)
- Manually delete if needed: `dlq delete <job-id>`
- Restart server to trigger GC

## See Also

- [Queue Configuration](../configuration/queue.md)
- [Monitoring Guide](../monitoring/metrics.md)
- [Health Checks](../monitoring/health-checks.md)
- [Alerting Best Practices](../monitoring/alerting.md)

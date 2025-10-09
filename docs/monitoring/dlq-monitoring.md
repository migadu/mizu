# DLQ Monitoring and Alerting

This guide covers monitoring and alerting for the Dead Letter Queue (DLQ) to ensure failed email deliveries are tracked and resolved promptly.

## Metrics

### Core DLQ Metrics

#### `mizu_queue_jobs_dlq` (Gauge)
Current number of jobs in the Dead Letter Queue.

**Use cases:**
- Monitor DLQ growth
- Alert on excessive failures
- Track DLQ cleanup effectiveness

**Example queries:**
```promql
# Current DLQ size
mizu_queue_jobs_dlq

# DLQ size over time
mizu_queue_jobs_dlq[1h]

# Average DLQ size (last 24h)
avg_over_time(mizu_queue_jobs_dlq[24h])
```

#### `mizu_queue_dlq_moved_total` (Counter)
Total number of jobs moved to DLQ, labeled by failure reason.

**Labels:**
- `reason`: Why the job was moved to DLQ

**Common reasons:**
- `"expired_after_48h"` - Job exceeded max retry hours
- `"permanent_http_404"` - Backend returned 404
- `"permanent_http_410"` - Backend returned 410 (Gone)
- `"circuit_breaker_open"` - All retries exhausted while circuit breaker open

**Example queries:**
```promql
# Rate of jobs moving to DLQ
rate(mizu_queue_dlq_moved_total[5m])

# Jobs moved to DLQ by reason
sum by (reason) (rate(mizu_queue_dlq_moved_total[5m]))

# Total moved to DLQ (last 24h)
increase(mizu_queue_dlq_moved_total[24h])

# Most common failure reason
topk(1, rate(mizu_queue_dlq_moved_total[1h])) by (reason)
```

#### `mizu_queue_dlq_reprocessed_total` (Counter)
Total number of jobs reprocessed from DLQ back to active queue.

**Use cases:**
- Track manual interventions
- Monitor recovery efforts
- Measure reprocessing success rate

**Example queries:**
```promql
# Rate of reprocessing
rate(mizu_queue_dlq_reprocessed_total[5m])

# Total reprocessed (last 24h)
increase(mizu_queue_dlq_reprocessed_total[24h])

# Reprocessing vs DLQ additions
rate(mizu_queue_dlq_reprocessed_total[5m]) /
rate(mizu_queue_dlq_moved_total[5m])
```

#### `mizu_queue_dlq_deleted_total` (Counter)
Total number of jobs permanently deleted from DLQ.

**Use cases:**
- Track DLQ cleanup
- Monitor manual deletions
- Audit DLQ management

**Example queries:**
```promql
# Rate of deletions
rate(mizu_queue_dlq_deleted_total[5m])

# Total deleted (last 24h)
increase(mizu_queue_dlq_deleted_total[24h])
```

#### `mizu_queue_dlq_oldest_age_seconds` (Gauge)
Age of the oldest entry in DLQ (in seconds). Zero if DLQ is empty.

**Use cases:**
- Alert on stale entries
- Monitor DLQ health
- Track time-to-resolution

**Example queries:**
```promql
# Age of oldest entry (hours)
mizu_queue_dlq_oldest_age_seconds / 3600

# Alert if oldest entry > 24 hours
mizu_queue_dlq_oldest_age_seconds > 86400

# Average age over time
avg_over_time(mizu_queue_dlq_oldest_age_seconds[1h]) / 3600
```

## Health Checks

### DLQ Health Endpoint

Query the health endpoint to check DLQ status:

```bash
curl -u admin:password http://localhost:8080/health
```

Response includes DLQ component:
```json
{
  "status": "healthy",
  "components": {
    "dead_letter_queue": {
      "status": "healthy",
      "details": {
        "entries": 5,
        "oldest_age_seconds": 3600,
        "oldest_age_hours": 1.0,
        "message": "DLQ has 5 entries"
      }
    }
  }
}
```

### Health States

- **healthy**: DLQ is empty or within normal thresholds
- **degraded**: DLQ has entries above warning threshold or old entries
- **unhealthy**: DLQ exceeds error threshold
- **disabled**: Persistent queue not configured

### Configure Health Thresholds

In server initialization code:

```go
import (
    "time"
    "migadu/mizu/pkg/health"
    "migadu/mizu/pkg/queue"
)

// Create DLQ health checker
dlqChecker := health.NewCheckDLQ(
    dlqProvider,
    50,                // Warn at 50 entries
    100,               // Error at 100 entries
    24 * time.Hour,    // Warn if oldest entry > 24 hours
)

// Register with health server
healthServer.AddChecker(dlqChecker)
```

## Alerting Rules

### Prometheus Alert Rules

```yaml
groups:
  - name: dlq_alerts
    interval: 30s
    rules:
      # Critical: DLQ size exceeds threshold
      - alert: DLQSizeHigh
        expr: mizu_queue_jobs_dlq > 100
        for: 30m
        labels:
          severity: critical
          component: dlq
        annotations:
          summary: "DLQ has {{ $value }} entries"
          description: |
            The Dead Letter Queue has {{ $value }} entries, exceeding the critical threshold of 100.
            This indicates a sustained problem with email delivery.

            Actions:
            1. Check backend service health
            2. Review DLQ entries: `mizu-admin dlq list`
            3. Investigate most common failure reason
            4. Consider reprocessing once issue is resolved

      # Warning: DLQ growing
      - alert: DLQSizeWarning
        expr: mizu_queue_jobs_dlq > 50
        for: 1h
        labels:
          severity: warning
          component: dlq
        annotations:
          summary: "DLQ has {{ $value }} entries (warning threshold)"
          description: |
            The DLQ has {{ $value }} entries, above the warning threshold of 50.
            Monitor for continued growth.

      # Critical: Stale DLQ entries
      - alert: DLQStaleJobs
        expr: mizu_queue_dlq_oldest_age_seconds > 86400
        for: 1h
        labels:
          severity: critical
          component: dlq
        annotations:
          summary: "DLQ has jobs stuck for over 24 hours"
          description: |
            Oldest DLQ entry is {{ $value | humanizeDuration }} old.
            Jobs should not remain in DLQ this long.

            Actions:
            1. Inspect oldest entry: `mizu-admin dlq list`
            2. Determine if issue is resolved
            3. Reprocess or delete as appropriate

      # Warning: High DLQ movement rate
      - alert: HighDLQMovementRate
        expr: rate(mizu_queue_dlq_moved_total[5m]) > 1
        for: 15m
        labels:
          severity: warning
          component: dlq
        annotations:
          summary: "High rate of jobs moving to DLQ ({{ $value }}/sec)"
          description: |
            {{ $value | humanizePercentage }} jobs per second are moving to DLQ.
            This indicates an ongoing delivery problem.

            Check:
            - Backend service health
            - Circuit breaker state
            - Network connectivity
            - Recent configuration changes

      # Info: Unusual failure pattern
      - alert: DLQFailurePattern
        expr: |
          sum by (reason) (rate(mizu_queue_dlq_moved_total[5m])) > 0.1
        for: 30m
        labels:
          severity: info
          component: dlq
        annotations:
          summary: "DLQ failures due to {{ $labels.reason }}"
          description: |
            Seeing consistent failures with reason: {{ $labels.reason }}
            Rate: {{ $value | humanizePercentage }} per second

            This may indicate:
            - Backend API changes (404/410 errors)
            - Service degradation (timeouts)
            - Configuration issues

      # Warning: No reprocessing activity
      - alert: DLQNotBeingManaged
        expr: |
          mizu_queue_jobs_dlq > 10 and
          rate(mizu_queue_dlq_reprocessed_total[24h]) == 0 and
          rate(mizu_queue_dlq_deleted_total[24h]) == 0
        for: 24h
        labels:
          severity: warning
          component: dlq
        annotations:
          summary: "DLQ has entries but no management activity"
          description: |
            DLQ has {{ $value }} entries with no reprocessing or deletion in 24h.
            DLQ entries should be reviewed and managed regularly.

            Actions:
            1. Review DLQ entries: `mizu-admin dlq list`
            2. Investigate failures
            3. Reprocess or delete as appropriate
```

### Alert Routing Example (Alertmanager)

```yaml
route:
  receiver: 'team-email'
  group_by: ['alertname', 'component']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h

  routes:
    # Critical DLQ alerts - page on-call
    - match:
        severity: critical
        component: dlq
      receiver: 'pagerduty'
      continue: true

    # Warning DLQ alerts - Slack channel
    - match:
        severity: warning
        component: dlq
      receiver: 'slack-alerts'
      group_interval: 5m
      repeat_interval: 4h

    # Info DLQ alerts - Slack monitoring
    - match:
        severity: info
        component: dlq
      receiver: 'slack-monitoring'
      group_interval: 15m
      repeat_interval: 24h

receivers:
  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: '<pagerduty-service-key>'
        description: '{{ .CommonAnnotations.summary }}'

  - name: 'slack-alerts'
    slack_configs:
      - api_url: '<slack-webhook-url>'
        channel: '#mizu-alerts'
        title: '{{ .CommonAnnotations.summary }}'
        text: '{{ .CommonAnnotations.description }}'

  - name: 'slack-monitoring'
    slack_configs:
      - api_url: '<slack-webhook-url>'
        channel: '#mizu-monitoring'
        title: '{{ .CommonAnnotations.summary }}'
```

## Dashboards

### Grafana Dashboard Example

```json
{
  "dashboard": {
    "title": "Mizu DLQ Monitoring",
    "panels": [
      {
        "title": "DLQ Size",
        "targets": [
          {
            "expr": "mizu_queue_jobs_dlq",
            "legendFormat": "DLQ Entries"
          }
        ],
        "type": "graph"
      },
      {
        "title": "DLQ Movement Rate",
        "targets": [
          {
            "expr": "rate(mizu_queue_dlq_moved_total[5m])",
            "legendFormat": "Moved to DLQ"
          },
          {
            "expr": "rate(mizu_queue_dlq_reprocessed_total[5m])",
            "legendFormat": "Reprocessed"
          },
          {
            "expr": "rate(mizu_queue_dlq_deleted_total[5m])",
            "legendFormat": "Deleted"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Failure Reasons",
        "targets": [
          {
            "expr": "sum by (reason) (rate(mizu_queue_dlq_moved_total[5m]))",
            "legendFormat": "{{ reason }}"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Oldest Entry Age",
        "targets": [
          {
            "expr": "mizu_queue_dlq_oldest_age_seconds / 3600",
            "legendFormat": "Age (hours)"
          }
        ],
        "type": "graph"
      },
      {
        "title": "DLQ Health",
        "targets": [
          {
            "expr": "up{job=\"mizu-health\"}",
            "legendFormat": "Health Check"
          }
        ],
        "type": "stat",
        "valueMappings": [
          { "value": "1", "text": "UP", "color": "green" },
          { "value": "0", "text": "DOWN", "color": "red" }
        ]
      }
    ]
  }
}
```

### Key Dashboard Panels

1. **DLQ Size Timeline**: Track DLQ growth over time
2. **Movement Rate**: Monitor jobs entering/leaving DLQ
3. **Failure Reasons**: Pie chart or bar graph of failure reasons
4. **Oldest Entry Age**: Alert if entries are getting stale
5. **Health Status**: DLQ health check result
6. **Reprocessing Activity**: Track manual interventions

## Monitoring Workflows

### Daily DLQ Review

```bash
#!/bin/bash
# daily-dlq-check.sh

# Get DLQ size
DLQ_SIZE=$(curl -s -u admin:password http://localhost:8080/api/dlq | jq '.entries | length')

echo "DLQ Size: $DLQ_SIZE"

if [ "$DLQ_SIZE" -gt 0 ]; then
    echo "DLQ Entries:"
    ./mizu-admin dlq list

    # Alert if over threshold
    if [ "$DLQ_SIZE" -gt 50 ]; then
        echo "WARNING: DLQ size exceeds threshold"
        # Send alert to Slack, email, etc.
    fi
else
    echo "DLQ is empty ✓"
fi
```

### Automated Cleanup Script

```bash
#!/bin/bash
# dlq-cleanup.sh - Remove old, irrelevant DLQ entries

# Get all DLQ entries
ENTRIES=$(curl -s -u admin:password http://localhost:8080/api/dlq | jq -r '.entries[].job.id')

for JOB_ID in $ENTRIES; do
    # Get entry details
    ENTRY=$(curl -s -u admin:password "http://localhost:8080/api/dlq/$JOB_ID")

    # Extract reason
    REASON=$(echo "$ENTRY" | jq -r '.entry.reason')

    # Auto-delete certain categories
    if [[ "$REASON" == *"404"* ]] || [[ "$REASON" == *"410"* ]]; then
        echo "Deleting $JOB_ID (permanent error: $REASON)"
        curl -X DELETE -u admin:password "http://localhost:8080/api/dlq/$JOB_ID"
    fi
done
```

## Runbooks

### High DLQ Size Alert

**Severity**: Critical
**Alert**: `DLQSizeHigh`

**Investigation:**
1. Check current DLQ size: `mizu-admin dlq list`
2. Review failure reasons: Check metrics `sum by (reason) (rate(mizu_queue_dlq_moved_total[1h]))`
3. Check backend health: `curl https://api.example.com/health`
4. Review recent changes: Check deployment logs

**Resolution:**
1. If backend is down: Fix backend service, then reprocess DLQ entries
2. If permanent errors (404/410): Review and delete invalid entries
3. If circuit breaker issues: Wait for circuit breaker to close, then reprocess
4. If configuration error: Fix config, then reprocess

**Reprocessing:**
```bash
# Get list of DLQ jobs
./mizu-admin dlq list

# Reprocess specific jobs
for job_id in $(./mizu-admin dlq list | tail -n +4 | awk '{print $1}'); do
    ./mizu-admin dlq reprocess $job_id
    sleep 1  # Rate limit reprocessing
done
```

### Stale DLQ Entries Alert

**Severity**: Critical
**Alert**: `DLQStaleJobs`

**Investigation:**
1. Check oldest entries: `mizu-admin dlq list | head -20`
2. Inspect oldest entry: `mizu-admin dlq inspect <job-id>`
3. Determine if issue is resolved
4. Check if entry is still relevant

**Resolution:**
1. If issue resolved: `mizu-admin dlq reprocess <job-id>`
2. If entry irrelevant: `mizu-admin dlq delete <job-id>`
3. If issue persists: Escalate to development team

## Best Practices

### Monitoring

1. **Set up alerts**: Configure all recommended alerts
2. **Daily reviews**: Check DLQ daily, automate if possible
3. **Trend analysis**: Monitor DLQ size trends over weeks/months
4. **Failure patterns**: Track common failure reasons to identify systemic issues

### Alerting

1. **Tune thresholds**: Adjust based on your normal DLQ activity
2. **Reduce noise**: Use `for` clauses to avoid flapping alerts
3. **Actionable alerts**: Include investigation steps in alert descriptions
4. **Alert routing**: Route critical alerts to on-call, warnings to Slack

### Operations

1. **Regular cleanup**: Remove irrelevant DLQ entries regularly
2. **Document patterns**: Keep runbooks for common DLQ issues
3. **Track metrics**: Monitor reprocessing success rate
4. **Automate where possible**: Script common operations

## See Also

- [DLQ Management](../operations/dlq-management.md)
- [Prometheus Metrics](./metrics.md)
- [Health Checks](./health-checks.md)
- [Alerting Best Practices](./alerting.md)

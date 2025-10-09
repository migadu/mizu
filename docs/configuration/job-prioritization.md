# Job Prioritization

Mizu supports priority-based email delivery processing, allowing certain emails to be delivered before others based on their importance. This feature is useful for ensuring time-sensitive emails (like password resets, security alerts, or transactional messages) are processed with higher priority than bulk or marketing emails.

## Overview

### How It Works

1. **Priority Assignment**: Your routing service assigns a priority value (0-100) to each email
2. **Time-Based Scheduling**: Jobs become "due" based on retry schedule (time-based)
3. **Priority Ordering**: When jobs are due, they are processed by priority (highest first)
4. **Worker Processing**: Workers pull highest-priority jobs from the queue

### Processing Modes

Mizu supports two processing modes:

#### FIFO Mode (Default)
- Jobs processed in strict time-due order
- Simple buffered channel dispatch
- Lower CPU overhead
- Best for uniform priority workloads

#### Priority Mode
- Jobs processed by priority within due jobs
- Heap-based priority queue
- Slightly higher CPU overhead
- Best for mixed priority workloads

## Configuration

### Enable Priority Mode

In `config.toml`:

```toml
[queue]
enabled = true
priority_mode = true    # Enable priority-based processing
workers = 10
max_retry_hours = 48
```

### Routing Service Integration

Your routing service returns priority in the response:

```json
{
  "accepted": true,
  "deliver_to": ["user@domain.com"],
  "delivery_endpoint": "https://api.example.com/deliver",
  "priority": 15
}
```

Priority field:
- **Type**: Integer (0-100)
- **Range**: 0 (lowest) to 100 (highest)
- **Default**: 0 if not specified
- **Higher values = more urgent**

## Priority Ranges

We recommend the following priority convention:

| Range | Level    | Use Cases                                          | Examples                                      |
|-------|----------|----------------------------------------------------|-----------------------------------------------|
| 0-4   | Low      | Bulk emails, newsletters, marketing                | Newsletter, promotional emails                |
| 5-9   | Normal   | Standard user emails                               | User-to-user emails, notifications            |
| 10-14 | High     | Transactional emails                               | Order confirmations, password resets          |
| 15-19 | Urgent   | Time-sensitive alerts                              | Security alerts, OTP codes, account lockouts  |
| 20+   | Critical | System alerts, emergency notifications             | Server down alerts, fraud alerts              |

**Note:** These are recommendations. Define priority ranges that match your use case.

## Routing Service Implementation

### Basic Example

```go
package main

import (
    "encoding/json"
    "net/http"
    "strings"
)

type ResolveRequest struct {
    Recipient string `json:"recipient"`
    Sender    string `json:"sender"`
    ClientIP  string `json:"client_ip"`
    Subject   string `json:"subject"`
}

type ResolveResponse struct {
    Accepted         bool     `json:"accepted"`
    DeliverTo        []string `json:"deliver_to"`
    DeliveryEndpoint string   `json:"delivery_endpoint"`
    Priority         int      `json:"priority"`
}

func handleResolve(w http.ResponseWriter, r *http.Request) {
    var req ResolveRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Determine priority based on email characteristics
    priority := determinePriority(req)

    response := ResolveResponse{
        Accepted:         true,
        DeliverTo:        []string{req.Recipient},
        DeliveryEndpoint: "https://api.example.com/deliver",
        Priority:         priority,
    }

    json.NewEncoder(w).Encode(response)
}

func determinePriority(req ResolveRequest) int {
    // Critical: Security alerts
    if strings.Contains(req.Subject, "[SECURITY]") ||
       strings.Contains(req.Subject, "[FRAUD]") {
        return 20
    }

    // Urgent: OTP, password resets
    if strings.Contains(req.Subject, "verification code") ||
       strings.Contains(req.Subject, "reset your password") ||
       strings.Contains(req.Subject, "OTP") {
        return 15
    }

    // High: Transactional emails
    if isTransactionalSender(req.Sender) {
        return 12
    }

    // Low: Bulk/marketing
    if isBulkSender(req.Sender) ||
       strings.Contains(req.Subject, "[Newsletter]") {
        return 2
    }

    // Normal: Everything else
    return 5
}

func isTransactionalSender(sender string) bool {
    transactionalDomains := []string{
        "orders@",
        "receipts@",
        "billing@",
        "payments@",
    }
    for _, domain := range transactionalDomains {
        if strings.HasPrefix(sender, domain) {
            return true
        }
    }
    return false
}

func isBulkSender(sender string) bool {
    bulkSenders := []string{
        "no-reply@",
        "noreply@",
        "marketing@",
        "newsletter@",
    }
    for _, sender := range bulkSenders {
        if strings.HasPrefix(sender, sender) {
            return true
        }
    }
    return false
}
```

### Advanced Example: Database-Driven Priorities

```go
func determinePriority(req ResolveRequest) int {
    // Check if sender is VIP user
    if isVIPUser(req.Sender) {
        return 18
    }

    // Check recipient preferences
    prefs := getUserPreferences(req.Recipient)
    if prefs.PriorityForSender(req.Sender) > 0 {
        return prefs.PriorityForSender(req.Sender)
    }

    // Check email category from ML classifier
    category := classifyEmail(req.Subject, req.Sender)
    return categoryToPriority(category)
}

func isVIPUser(email string) bool {
    // Query database for VIP status
    var vip bool
    db.QueryRow("SELECT is_vip FROM users WHERE email = ?", email).Scan(&vip)
    return vip
}

type UserPreferences struct {
    senderPriorities map[string]int
}

func getUserPreferences(email string) UserPreferences {
    // Load user's priority preferences from database
    prefs := UserPreferences{
        senderPriorities: make(map[string]int),
    }
    // ... load from DB
    return prefs
}

func (p UserPreferences) PriorityForSender(sender string) int {
    if priority, ok := p.senderPriorities[sender]; ok {
        return priority
    }
    return 0
}

func classifyEmail(subject, sender string) string {
    // Use ML model to classify email
    // Returns: "transactional", "marketing", "personal", "notification"
    // ... ML classification logic
    return "personal"
}

func categoryToPriority(category string) int {
    priorities := map[string]int{
        "security":      20,
        "transactional": 12,
        "notification":  8,
        "personal":      5,
        "marketing":     2,
        "bulk":          1,
    }
    if p, ok := priorities[category]; ok {
        return p
    }
    return 5 // Default
}
```

## Behavior and Guarantees

### What Priority Does

✅ **Affects processing order** of jobs that are currently due
✅ **Higher priority jobs are processed first** within due jobs
✅ **Respects time-based retry schedule** (jobs must be due to be processed)

### What Priority Doesn't Do

❌ **Does NOT skip retry schedule** (job still waits for NextRetry time)
❌ **Does NOT change retry intervals** (backoff schedule is unchanged)
❌ **Does NOT bypass rate limits** or circuit breakers

### Example Timeline

```
Time  | Job A (Priority 20, Due at T0)  | Job B (Priority 5, Due at T1)
------|----------------------------------|----------------------------------
T0    | ✓ Job A due, processed           | Job B not due yet, waiting
T1    | Job A delivered                  | ✓ Job B due, processed
```

Even though Job B has lower priority, it's processed at T1 when it becomes due, not delayed indefinitely.

### With Multiple Due Jobs

```
Time  | Due Jobs                         | Processing Order
------|----------------------------------|----------------------------------
T0    | A (P=20), B (P=5), C (P=15)     | A → C → B (by priority)
T1    | D (P=10), E (P=25)              | E → D (by priority)
```

## Performance Considerations

### FIFO Mode Performance
- **Enqueue**: O(1) - direct channel send
- **Dequeue**: O(1) - direct channel receive
- **Memory**: O(workers * 2) - buffered channel
- **CPU**: Minimal overhead

### Priority Mode Performance
- **Enqueue**: O(log n) - heap insert
- **Dequeue**: O(log n) - heap pop
- **Memory**: O(active_due_jobs) - heap storage
- **CPU**: Slightly higher due to heap operations

### When to Use Each Mode

**Use FIFO Mode when:**
- All emails have equal importance
- Performance is critical (ultra-high volume)
- Simplicity is preferred
- Volume < 10,000 emails/hour

**Use Priority Mode when:**
- You have different classes of email with different SLAs
- Time-sensitive emails need faster delivery
- You want to throttle bulk sends without blocking transactional
- Volume > 10,000 emails/hour with mixed priorities

## Monitoring

### Queue Metrics

Monitor priority distribution:

```promql
# Jobs in queue (no priority breakdown in current implementation)
mizu_queue_jobs_active

# Jobs delivered
rate(mizu_queue_jobs_delivered_total[5m])

# Jobs retrying
rate(mizu_queue_jobs_retries_total[5m])
```

### Worker Utilization

```promql
# Active workers processing jobs
mizu_queue_workers

# Job age when delivered (latency)
histogram_quantile(0.95, mizu_queue_job_age_seconds)
```

## Testing Priority

### Manual Testing

1. Enable priority mode
2. Enqueue jobs with different priorities
3. Observe processing order in logs

```bash
# Watch logs for processing order
tail -f /var/log/mizu/mizu-server.log | grep "Dispatching due jobs"
```

### Load Testing

Test priority behavior under load:

```bash
# Send mixed priority emails
for i in {1..100}; do
  curl -X POST http://localhost:25 \
    --data "MAIL FROM:<sender@example.com>
RCPT TO:<test$i@example.com>
DATA
Subject: Test Priority $((i % 5 * 5))

Test email with priority.
.
QUIT"
done
```

## Troubleshooting

### Priority Not Working

**Symptoms:** All jobs processed in FIFO order regardless of priority

**Causes:**
1. `priority_mode = false` in config
2. Routing service not returning priority
3. All jobs have same priority (default 0)

**Solution:**
1. Verify `priority_mode = true` in `config.toml`
2. Check routing service returns `priority` field
3. Add logging to verify priority values: `zap.Int("priority", job.Priority)`

### High Priority Jobs Delayed

**Symptoms:** High priority jobs not processed immediately

**Cause:** Jobs must wait for `NextRetry` time even with high priority

**Explanation:** Priority only affects order of due jobs. Jobs must still wait for retry schedule.

**Solution:** This is expected behavior. Priority determines order once jobs are due, not when they become due.

### All Jobs Same Priority

**Symptoms:** Routing returns priority but all jobs show priority=0

**Cause:** Priority not copied from routing response to DeliveryJob

**Solution:** Verify server is up-to-date. Priority should flow automatically from routing response.

## Best Practices

### Priority Assignment

1. **Be conservative**: Don't mark everything as high priority
2. **Use the full range**: Spread priorities across 0-20 range
3. **Document your scheme**: Maintain a priority convention document
4. **Monitor distribution**: Track how many emails fall into each bucket

### Routing Logic

1. **Keep it simple**: Start with basic sender/subject rules
2. **Avoid over-engineering**: Don't create too many priority levels
3. **Test thoroughly**: Verify priority logic with real emails
4. **Monitor effectiveness**: Track delivery latency by priority

### Operations

1. **Set up metrics**: Monitor job latency by priority (if tracked)
2. **Review regularly**: Adjust priority ranges based on SLA requirements
3. **Document changes**: Keep changelog of priority logic changes
4. **Load test**: Verify behavior under high load

## Migration from FIFO to Priority Mode

### Step-by-Step Migration

1. **Add priority to routing service** (optional, defaults to 0)
   ```go
   response.Priority = determinePriority(request)
   ```

2. **Deploy routing service changes** (priority field ignored in FIFO mode)

3. **Test priority logic** with `priority_mode = false` (no impact)

4. **Enable priority mode** in config:
   ```toml
   [queue]
   priority_mode = true
   ```

5. **Restart server** (graceful restart recommended)

6. **Monitor metrics** for any issues

### Rollback Plan

If issues occur after enabling priority mode:

1. Set `priority_mode = false` in config
2. Restart server (graceful restart)
3. Jobs will resume FIFO processing
4. Investigate issues before re-enabling

## See Also

- [Queue Configuration](../configuration/queue.md)
- [Routing Service](../configuration/routing.md)
- [DLQ Management](../operations/dlq-management.md)
- [Monitoring Guide](../monitoring/metrics.md)

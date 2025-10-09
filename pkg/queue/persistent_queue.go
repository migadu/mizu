package queue

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"migadu/mizu/pkg/logging"
	"migadu/mizu/pkg/metrics"
	"migadu/mizu/pkg/poster"

	"go.uber.org/zap"
)

// PersistentQueue manages async email delivery with persistent storage and 48-hour retry window
// This is a proper mail queue implementation that survives restarts and retries over days
type PersistentQueue struct {
	config QueueConfig

	// Persistent storage
	storage      *Storage
	emailStorage *EmailStorage // Filesystem storage for large emails (>1MB)
	schedule     *RetrySchedule

	// Worker management
	workers      int
	workersWg    sync.WaitGroup
	shutdownCh   chan struct{}
	isShutdown   atomic.Bool
	activeJobs   atomic.Int64      // Number of jobs currently being processed
	jobsChan     chan *DeliveryJob // Channel for dispatching jobs to workers
	priorityMode bool              // Enable priority-based processing

	// Priority queue (used when priorityMode is enabled)
	priorityQueue     *PriorityQueue
	priorityQueueCond *sync.Cond

	// Scheduler ticker
	schedulerTicker *time.Ticker
	schedulerDone   chan struct{}

	// HTTP delivery
	httpClient               *http.Client
	deliveryCircuitBreaker   *poster.CircuitBreaker
	forwardingCircuitBreaker *poster.CircuitBreaker

	// Observability
	logger  *zap.Logger
	metrics *metrics.Metrics

	// Statistics
	statsTotal struct {
		enqueued  atomic.Int64
		delivered atomic.Int64
		failed    atomic.Int64
		retries   atomic.Int64
		dlq       atomic.Int64 // Moved to dead letter queue
	}
}

// NewPersistentQueue creates a new persistent delivery queue
func NewPersistentQueue(
	config QueueConfig,
	dataDir string,
	httpClient *http.Client,
	deliveryCircuitBreaker *poster.CircuitBreaker,
	forwardingCircuitBreaker *poster.CircuitBreaker,
	logger *zap.Logger,
	m *metrics.Metrics,
) (*PersistentQueue, error) {
	if config.Workers <= 0 {
		return nil, fmt.Errorf("workers must be > 0")
	}

	if dataDir == "" {
		return nil, fmt.Errorf("data_dir is required for persistent queue")
	}

	// Create metrics recorder for storage operations
	var metricsRecorder *queueMetricsRecorder
	if m != nil {
		metricsRecorder = &queueMetricsRecorder{metrics: m}
	}

	// Create storage with sync writes enabled
	// CRITICAL: Sync writes guarantee messages are durably stored BEFORE sending SMTP 250 OK
	storage, err := NewStorage(StorageConfig{
		DataDir:    dataDir,
		SyncWrites: true, // REQUIRED for mail queue - never lose messages after SMTP acceptance
		Logger:     logger,
		Metrics:    metricsRecorder,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Create email storage for large emails (>1MB)
	// Emails > 1MB are stored on filesystem, not in BadgerDB
	emailStorageDir := filepath.Join(dataDir, "emails")
	emailStorage, err := NewEmailStorage(emailStorageDir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create email storage: %w", err)
	}

	// Create retry schedule
	schedule := NewRetrySchedule()
	if config.MaxRetryHours > 0 {
		schedule.MaxAge = time.Duration(config.MaxRetryHours) * time.Hour
	}

	q := &PersistentQueue{
		config:                   config,
		storage:                  storage,
		emailStorage:             emailStorage,
		schedule:                 schedule,
		workers:                  config.Workers,
		shutdownCh:               make(chan struct{}),
		schedulerDone:            make(chan struct{}),
		jobsChan:                 make(chan *DeliveryJob, config.Workers*2), // Buffered channel for job dispatch
		priorityMode:             config.PriorityMode,
		httpClient:               httpClient,
		deliveryCircuitBreaker:   deliveryCircuitBreaker,
		forwardingCircuitBreaker: forwardingCircuitBreaker,
		logger:                   logger,
		metrics:                  m,
	}

	// Initialize priority queue if priority mode is enabled
	if config.PriorityMode {
		q.priorityQueue = NewPriorityQueue()
		q.priorityQueueCond = sync.NewCond(&sync.Mutex{})
		logger.Info("Priority-based job processing enabled")
	}

	return q, nil
}

// Start begins processing jobs with worker pool and scheduler
func (q *PersistentQueue) Start() error {
	if q.isShutdown.Load() {
		return fmt.Errorf("queue already shutdown")
	}

	q.logger.Info("Starting persistent delivery queue",
		zap.Int("workers", q.workers),
		zap.Duration("max_retry_age", q.schedule.MaxAge),
		zap.Int("estimated_retry_count", q.schedule.EstimateRetryCount()))

	// Recover jobs from storage
	if err := q.recoverJobs(); err != nil {
		return fmt.Errorf("failed to recover jobs: %w", err)
	}

	// Start worker goroutines
	for i := 0; i < q.workers; i++ {
		q.workersWg.Add(1)
		workerID := i
		logging.SafeGo(q.logger, fmt.Sprintf("persistent-queue-worker-%d", workerID), func() {
			defer q.workersWg.Done()
			q.worker(workerID)
		})
	}

	// Start scheduler goroutine
	// Use configured interval, or default to 10 seconds
	schedulerInterval := q.config.SchedulerTicker
	if schedulerInterval == 0 {
		schedulerInterval = 10 * time.Second
	}
	q.schedulerTicker = time.NewTicker(schedulerInterval)
	logging.SafeGo(q.logger, "persistent-queue-scheduler", func() {
		defer close(q.schedulerDone)
		q.scheduler()
	})

	q.logger.Info("Persistent delivery queue started",
		zap.Int("workers_active", q.workers))

	return nil
}

// Enqueue adds a job to the persistent queue
func (q *PersistentQueue) Enqueue(job *DeliveryJob) error {
	if q.isShutdown.Load() {
		return fmt.Errorf("queue is shutdown")
	}

	// Set initial timestamps
	now := time.Now()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	if job.LastAttempt.IsZero() {
		job.LastAttempt = now
	}
	if job.NextRetry.IsZero() {
		job.NextRetry = q.schedule.NextRetryTime(job, now)
	}

	// Handle email content: use hybrid storage (filesystem for >1MB, BadgerDB for smaller)
	// This MUST happen before SaveJob() to ensure content is durably stored
	if job.EmailContent != "" {
		if err := job.SetEmailContent(job.EmailContent, q.emailStorage); err != nil {
			return fmt.Errorf("failed to store email content: %w", err)
		}
	}

	// Persist to storage (this fsyncs to disk before returning)
	if err := q.storage.SaveJob(job); err != nil {
		return fmt.Errorf("failed to save job: %w", err)
	}

	q.statsTotal.enqueued.Add(1)
	if q.metrics != nil {
		q.metrics.QueueJobsTotal.Inc()
		q.metrics.QueueJobsActive.Set(float64(q.Size()))
	}

	q.logger.Debug("Job enqueued to persistent storage",
		zap.String("job_id", job.ID),
		zap.Time("next_retry", job.NextRetry),
		zap.Strings("recipients", job.Recipients),
		zap.Bool("large_email", job.EmailStorageKey != ""))

	return nil
}

// worker processes jobs from the jobs channel or priority queue
func (q *PersistentQueue) worker(workerID int) {
	q.logger.Debug("Persistent queue worker started",
		zap.Int("worker_id", workerID),
		zap.Bool("priority_mode", q.priorityMode))

	if q.priorityMode {
		q.workerPriorityMode(workerID)
	} else {
		q.workerFIFOMode(workerID)
	}
}

// workerFIFOMode processes jobs in FIFO order from channel
func (q *PersistentQueue) workerFIFOMode(workerID int) {
	for {
		select {
		case <-q.shutdownCh:
			q.logger.Debug("Persistent queue worker shutting down", zap.Int("worker_id", workerID))
			return
		case job := <-q.jobsChan:
			if job != nil {
				q.processJob(job, time.Now())
			}
		}
	}
}

// workerPriorityMode processes jobs by priority from priority queue
func (q *PersistentQueue) workerPriorityMode(workerID int) {
	for {
		select {
		case <-q.shutdownCh:
			q.logger.Debug("Persistent queue worker shutting down (priority mode)", zap.Int("worker_id", workerID))
			return
		default:
			// Wait for jobs in priority queue
			q.priorityQueueCond.L.Lock()
			for q.priorityQueue.Len() == 0 && !q.isShutdown.Load() {
				q.priorityQueueCond.Wait()
			}

			if q.isShutdown.Load() {
				q.priorityQueueCond.L.Unlock()
				return
			}

			job := q.priorityQueue.PopJob()
			q.priorityQueueCond.L.Unlock()

			if job != nil {
				q.processJob(job, time.Now())
			}
		}
	}
}

// scheduler periodically checks for due jobs and dispatches them to workers
func (q *PersistentQueue) scheduler() {
	q.logger.Debug("Persistent queue scheduler started")

	for {
		select {
		case <-q.shutdownCh:
			q.logger.Debug("Persistent queue scheduler shutting down")
			return

		case <-q.schedulerTicker.C:
			q.processDueJobs()
		}
	}
}

// processDueJobs retrieves and dispatches all jobs that are due for retry
func (q *PersistentQueue) processDueJobs() {
	// Get jobs that are due (NextRetry <= now)
	jobs, err := q.storage.GetDueJobs(100) // Process up to 100 jobs per tick
	if err != nil {
		q.logger.Error("Failed to get due jobs", zap.Error(err))
		return
	}

	if len(jobs) == 0 {
		return
	}

	q.logger.Debug("Dispatching due jobs to workers",
		zap.Int("count", len(jobs)),
		zap.Bool("priority_mode", q.priorityMode))

	if q.priorityMode {
		// Priority mode: Add jobs to priority queue
		q.priorityQueueCond.L.Lock()
		for _, job := range jobs {
			if q.isShutdown.Load() {
				q.priorityQueueCond.L.Unlock()
				return
			}
			q.priorityQueue.PushJob(job)
		}
		// Signal all waiting workers
		q.priorityQueueCond.Broadcast()
		q.priorityQueueCond.L.Unlock()
	} else {
		// FIFO mode: Dispatch to channel
		for _, job := range jobs {
			select {
			case <-q.shutdownCh:
				return
			case q.jobsChan <- job:
				// Job dispatched to worker
			}
		}
	}
}

// processJob attempts to deliver a single job
func (q *PersistentQueue) processJob(job *DeliveryJob, now time.Time) {
	q.activeJobs.Add(1)
	defer q.activeJobs.Add(-1)

	// Check if job has expired
	if q.schedule.ShouldGiveUp(job, now) {
		q.logger.Warn("Job expired, moving to DLQ",
			zap.String("job_id", job.ID),
			zap.Duration("age", now.Sub(job.CreatedAt)),
			zap.Int("attempts", job.Attempts))

		if err := q.storage.MoveToDLQ(job, "expired after max retry age"); err != nil {
			q.logger.Error("Failed to move job to DLQ", zap.String("job_id", job.ID), zap.Error(err))
		} else {
			q.statsTotal.dlq.Add(1)
			// Note: We keep email files for DLQ entries until DLQ expires (7 days)
			// They will be cleaned up by periodic orphan cleanup
		}
		return
	}

	// Attempt delivery
	job.Attempts++
	job.LastAttempt = now

	q.logger.Debug("Attempting delivery",
		zap.String("job_id", job.ID),
		zap.Int("attempt", job.Attempts),
		zap.Duration("age", now.Sub(job.CreatedAt)),
		zap.Bool("is_forwarding", job.IsForwarding))

	deliveryStart := time.Now()
	err := q.deliverJob(job)
	deliveryDuration := time.Since(deliveryStart)

	if err == nil {
		// Success - delete from queue
		q.logger.Info("Delivery successful",
			zap.String("job_id", job.ID),
			zap.Int("attempts", job.Attempts),
			zap.Duration("total_duration", now.Sub(job.CreatedAt)))

		// Delete from BadgerDB
		if err := q.storage.DeleteJob(job); err != nil {
			q.logger.Error("Failed to delete successful job", zap.String("job_id", job.ID), zap.Error(err))
		}

		// Clean up email file if stored on filesystem
		if job.EmailStorageKey != "" {
			if err := q.emailStorage.Delete(job.EmailStorageKey); err != nil {
				q.logger.Warn("Failed to delete email file",
					zap.String("job_id", job.ID),
					zap.String("storage_key", job.EmailStorageKey),
					zap.Error(err))
			}
		}

		q.statsTotal.delivered.Add(1)
		if q.metrics != nil {
			q.metrics.QueueJobsDelivered.Inc()
			q.metrics.QueueJobsActive.Set(float64(q.Size()))
			q.metrics.QueueDeliveryDuration.Observe(deliveryDuration.Seconds())
			q.metrics.QueueJobAge.Observe(now.Sub(job.CreatedAt).Seconds())
		}
		return
	}

	// Delivery failed - check if we should retry
	if !q.shouldRetry(job, err) {
		q.logger.Warn("Job failed permanently, moving to DLQ",
			zap.String("job_id", job.ID),
			zap.Int("attempts", job.Attempts),
			zap.Error(err))

		if err := q.storage.MoveToDLQ(job, fmt.Sprintf("permanent failure: %v", err)); err != nil {
			q.logger.Error("Failed to move job to DLQ", zap.String("job_id", job.ID), zap.Error(err))
		} else {
			q.statsTotal.dlq.Add(1)
			q.statsTotal.failed.Add(1)
			if q.metrics != nil {
				q.metrics.QueueJobsFailed.Inc()
				q.metrics.QueueJobsDLQ.Set(float64(q.statsTotal.dlq.Load()))
			}
			// Note: We keep email files for DLQ entries until DLQ expires (7 days)
			// They will be cleaned up by periodic orphan cleanup
		}
		return
	}

	// Schedule retry
	q.statsTotal.retries.Add(1)
	if q.metrics != nil {
		q.metrics.QueueJobsRetries.Inc()
	}
	q.scheduleRetry(job, now, err)
}

// deliverJob performs the actual HTTP delivery
func (q *PersistentQueue) deliverJob(job *DeliveryJob) error {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), q.config.DeliveryTimeout)
	defer cancel()

	// Retrieve email content from storage (may be inline or on filesystem)
	emailContent, err := job.GetEmailContent(q.emailStorage)
	if err != nil {
		return fmt.Errorf("failed to load email content: %w", err)
	}

	// Select the correct circuit breaker based on job type
	// IMPORTANT: Only use circuit breakers for default endpoints.
	// Custom endpoints from routing responses should NOT use circuit breakers
	// because they may be completely different infrastructure.
	var circuitBreaker *poster.CircuitBreaker
	if !job.IsCustomEndpoint {
		if job.IsForwarding {
			circuitBreaker = q.forwardingCircuitBreaker
		} else {
			circuitBreaker = q.deliveryCircuitBreaker
		}
	}
	// If job.IsCustomEndpoint == true, circuitBreaker stays nil

	// Use the poster package for delivery
	err = poster.PostEmailToDestinationWithContext(
		ctx,
		emailContent,
		job.Endpoint,
		job.APIKey,
		0, // No retries here - queue handles retries
		job.IsJunk,
		job.From,
		job.Recipients,
		job.TraceID,
		circuitBreaker,
		q.httpClient,
		q.logger,
	)

	return err
}

// shouldRetry determines if a job should be retried based on the error
func (q *PersistentQueue) shouldRetry(job *DeliveryJob, err error) bool {
	if err == nil {
		return false
	}

	// Always retry errors - let the time-based retry schedule handle backoff
	// The 48-hour retry window will eventually move jobs to DLQ if they keep failing
	return true
}

// scheduleRetry schedules a job for retry using time-based scheduling
func (q *PersistentQueue) scheduleRetry(job *DeliveryJob, now time.Time, err error) {
	// Calculate next retry time based on job age
	job.NextRetry = q.schedule.NextRetryTime(job, now)

	q.logger.Info("Scheduling retry",
		zap.String("job_id", job.ID),
		zap.Int("attempt", job.Attempts),
		zap.Time("next_retry", job.NextRetry),
		zap.Duration("retry_in", job.NextRetry.Sub(now)),
		zap.Duration("age", now.Sub(job.CreatedAt)),
		zap.Error(err))

	// Save updated job with new retry time
	if err := q.storage.SaveJob(job); err != nil {
		q.logger.Error("Failed to save job for retry",
			zap.String("job_id", job.ID),
			zap.Error(err))
	}

}

// recoverJobs loads all pending jobs from storage on startup
func (q *PersistentQueue) recoverJobs() error {
	jobs, err := q.storage.GetAllJobs()
	if err != nil {
		return err
	}

	q.logger.Info("Recovered jobs from storage",
		zap.Int("count", len(jobs)))

	// Jobs are already in storage, scheduler will pick them up
	return nil
}

// Shutdown gracefully shuts down the queue
func (q *PersistentQueue) Shutdown(ctx context.Context) error {
	if q.isShutdown.Swap(true) {
		return fmt.Errorf("queue already shutdown")
	}

	q.logger.Info("Shutting down persistent queue...")

	// Stop scheduler if it was started
	if q.schedulerTicker != nil {
		q.schedulerTicker.Stop()
	}

	// Close shutdown channel if not already closed
	select {
	case <-q.shutdownCh:
		// Already closed
	default:
		close(q.shutdownCh)
	}

	// Wake up priority queue workers if in priority mode
	if q.priorityMode {
		q.priorityQueueCond.Broadcast()
	}

	// Wait for scheduler to finish (only if it was started)
	if q.schedulerDone != nil {
		select {
		case <-q.schedulerDone:
			// Scheduler finished
		case <-ctx.Done():
			q.logger.Warn("Timeout waiting for scheduler to stop")
		case <-time.After(1 * time.Second):
			// Give scheduler 1 second max to stop
		}
	}

	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		q.workersWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		q.logger.Info("All workers finished gracefully")
	case <-ctx.Done():
		q.logger.Warn("Shutdown timeout, some jobs may still be processing")
	}

	// Close storage
	if err := q.storage.Close(); err != nil {
		q.logger.Error("Failed to close storage", zap.Error(err))
		return err
	}

	q.logger.Info("Persistent queue shutdown complete")
	return nil
}

// GetStats returns queue statistics
func (q *PersistentQueue) GetStats() QueueStats {
	storageStats, err := q.storage.GetStats()
	if err != nil {
		q.logger.Error("Failed to get storage stats", zap.Error(err))
		storageStats = make(map[string]interface{})
	}

	jobCount := 0
	if count, ok := storageStats["jobs"].(int); ok {
		jobCount = count
	}

	dlqSize := 0
	if count, ok := storageStats["dlq_entries"].(int); ok {
		dlqSize = count
	}

	// Get oldest DLQ entry age
	var dlqOldestAge float64
	if dlqSize > 0 {
		if entries, err := q.storage.GetDLQEntries(1); err == nil && len(entries) > 0 {
			dlqOldestAge = time.Since(entries[0].MovedAt).Seconds()
		}
	}

	return QueueStats{
		TotalEnqueued:  q.statsTotal.enqueued.Load(),
		TotalDelivered: q.statsTotal.delivered.Load(),
		TotalFailed:    q.statsTotal.failed.Load(),
		TotalRetries:   q.statsTotal.retries.Load(),
		CurrentSize:    jobCount,
		WorkersActive:  q.workers,
		WorkersRunning: int(q.activeJobs.Load()),
		DLQSize:        dlqSize,
		DLQOldestAge:   dlqOldestAge,
	}
}

// Size returns the current number of jobs in the queue
func (q *PersistentQueue) Size() int {
	stats, err := q.storage.GetStats()
	if err != nil {
		return 0
	}
	if count, ok := stats["jobs"].(int); ok {
		return count
	}
	return 0
}

// getActiveStorageKeys returns all storage keys currently in use by jobs
func (q *PersistentQueue) getActiveStorageKeys() (map[string]bool, error) {
	activeKeys := make(map[string]bool)

	// Get all active jobs
	jobs, err := q.storage.GetAllJobs()
	if err != nil {
		return nil, fmt.Errorf("failed to get all jobs: %w", err)
	}

	for _, job := range jobs {
		if job.EmailStorageKey != "" {
			activeKeys[job.EmailStorageKey] = true
		}
	}

	return activeKeys, nil
}

// CleanupOrphanedEmails removes email files that don't have corresponding jobs
// This should be called periodically (e.g., daily) to clean up after crashes
func (q *PersistentQueue) CleanupOrphanedEmails() (int, error) {
	q.logger.Info("Starting orphaned email cleanup")

	// Get active storage keys from all jobs
	activeKeys, err := q.getActiveStorageKeys()
	if err != nil {
		return 0, fmt.Errorf("failed to get active keys: %w", err)
	}

	q.logger.Debug("Active storage keys",
		zap.Int("count", len(activeKeys)))

	// Clean up orphaned email files
	cleaned, err := q.emailStorage.CleanupOrphaned(activeKeys)
	if err != nil {
		return 0, fmt.Errorf("cleanup failed: %w", err)
	}

	if cleaned > 0 {
		q.logger.Info("Orphaned email cleanup complete",
			zap.Int("files_removed", cleaned))
	} else {
		q.logger.Debug("Orphaned email cleanup complete - no orphans found")
	}

	return cleaned, nil
}

// GetStorageStats returns BadgerDB storage statistics
func (q *PersistentQueue) GetStorageStats() (map[string]interface{}, error) {
	return q.storage.GetStats()
}

// GetEmailStorageStats returns filesystem email storage statistics
func (q *PersistentQueue) GetEmailStorageStats() (map[string]interface{}, error) {
	return q.emailStorage.GetStats()
}

// UpdateMetrics updates Prometheus metrics with current queue stats
func (q *PersistentQueue) UpdateMetrics() {
	if q.metrics == nil {
		return
	}

	// Get all stats
	stats := q.GetStats()
	storageStats, _ := q.GetStorageStats()
	emailStats, _ := q.GetEmailStorageStats()

	// Update counter metrics (use Set for gauges, Add for counters)
	q.metrics.QueueJobsTotal.Add(0)     // Initialize if not set
	q.metrics.QueueJobsDelivered.Add(0) // Initialize if not set
	q.metrics.QueueJobsFailed.Add(0)    // Initialize if not set
	q.metrics.QueueJobsRetries.Add(0)   // Initialize if not set

	// Update gauge metrics
	q.metrics.QueueJobsActive.Set(float64(stats.CurrentSize))
	q.metrics.QueueWorkers.Set(float64(stats.WorkersActive))

	// Update DLQ size
	if dlqCount, ok := storageStats["dlq_entries"].(int); ok {
		q.metrics.QueueJobsDLQ.Set(float64(dlqCount))
	}

	// Update DLQ oldest age
	q.updateDLQOldestAge()

	// Update schedule entries
	if scheduleCount, ok := storageStats["schedule_entries"].(int); ok {
		q.metrics.QueueScheduleEntries.Set(float64(scheduleCount))
	}

	// Update email storage metrics
	if emailStats != nil {
		if files, ok := emailStats["total_files"].(int); ok {
			q.metrics.QueueEmailFiles.Set(float64(files))
		}
		if bytes, ok := emailStats["total_bytes"].(int64); ok {
			q.metrics.QueueStorageSize.Set(float64(bytes))
		}
	}
}

// updateDLQOldestAge updates the metric for oldest DLQ entry age
func (q *PersistentQueue) updateDLQOldestAge() {
	entries, err := q.storage.GetDLQEntries(1) // Get oldest entry
	if err != nil || len(entries) == 0 {
		q.metrics.QueueDLQOldestAge.Set(0)
		return
	}

	age := time.Since(entries[0].MovedAt).Seconds()
	q.metrics.QueueDLQOldestAge.Set(age)
}

// GetDLQEntries returns DLQ entries with optional limit
func (q *PersistentQueue) GetDLQEntries(limit int) ([]*DLQEntry, error) {
	return q.storage.GetDLQEntries(limit)
}

// GetDLQEntry retrieves a specific DLQ entry by job ID
func (q *PersistentQueue) GetDLQEntry(jobID string) (*DLQEntry, error) {
	return q.storage.GetDLQEntry(jobID)
}

// ReprocessDLQJob moves a job from DLQ back to the active queue for retry
func (q *PersistentQueue) ReprocessDLQJob(jobID string) error {
	q.logger.Info("Reprocessing DLQ job", zap.String("job_id", jobID))
	return q.storage.ReprocessDLQJob(jobID)
}

// DeleteDLQEntry removes a specific entry from the DLQ
func (q *PersistentQueue) DeleteDLQEntry(jobID string) error {
	// Get the DLQ entry first to clean up email file if needed
	entry, err := q.storage.GetDLQEntry(jobID)
	if err != nil {
		return err
	}

	// Delete email file if stored on filesystem
	if entry.Job.EmailStorageKey != "" {
		if err := q.emailStorage.Delete(entry.Job.EmailStorageKey); err != nil {
			q.logger.Warn("Failed to delete email file for DLQ entry",
				zap.String("job_id", jobID),
				zap.String("storage_key", entry.Job.EmailStorageKey),
				zap.Error(err))
			// Continue with deletion even if file cleanup fails
		}
	}

	q.logger.Info("Deleting DLQ entry", zap.String("job_id", jobID))
	return q.storage.DeleteDLQEntry(jobID)
}

// DLQProviderWrapper wraps PersistentQueue to implement health.DLQProvider interface
// This allows the queue to be used with the health server's DLQ endpoints
type DLQProviderWrapper struct {
	queue *PersistentQueue
}

// NewDLQProviderWrapper creates a wrapper that implements health.DLQProvider
func NewDLQProviderWrapper(queue *PersistentQueue) *DLQProviderWrapper {
	return &DLQProviderWrapper{queue: queue}
}

func (w *DLQProviderWrapper) GetDLQEntries(limit int) (any, error) {
	return w.queue.GetDLQEntries(limit)
}

func (w *DLQProviderWrapper) GetDLQEntry(jobID string) (any, error) {
	return w.queue.GetDLQEntry(jobID)
}

func (w *DLQProviderWrapper) ReprocessDLQJob(jobID string) error {
	return w.queue.ReprocessDLQJob(jobID)
}

func (w *DLQProviderWrapper) DeleteDLQEntry(jobID string) error {
	return w.queue.DeleteDLQEntry(jobID)
}

// queueMetricsRecorder implements storage.MetricsRecorder
type queueMetricsRecorder struct {
	metrics *metrics.Metrics
}

func (r *queueMetricsRecorder) RecordDLQMoved(reason string) {
	if r != nil && r.metrics != nil {
		r.metrics.QueueDLQMovedTotal.WithLabelValues(reason).Inc()
	}
}

func (r *queueMetricsRecorder) RecordDLQReprocessed() {
	if r != nil && r.metrics != nil {
		r.metrics.QueueDLQReprocessed.Inc()
	}
}

func (r *queueMetricsRecorder) RecordDLQDeleted() {
	if r != nil && r.metrics != nil {
		r.metrics.QueueDLQDeleted.Inc()
	}
}

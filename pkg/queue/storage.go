package queue

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"go.uber.org/zap"
)

// Storage provides persistent storage for the queue using BadgerDB
type Storage struct {
	db      *badger.DB
	logger  *zap.Logger
	metrics MetricsRecorder
}

// MetricsRecorder defines metrics that can be recorded by storage operations
type MetricsRecorder interface {
	RecordDLQMoved(reason string)
	RecordDLQReprocessed()
	RecordDLQDeleted()
}

// StorageConfig holds configuration for the storage backend
type StorageConfig struct {
	DataDir    string // Directory for BadgerDB files
	SyncWrites bool   // Enable sync writes for durability (default: true for mail queue)
	Logger     *zap.Logger
	Metrics    MetricsRecorder // Optional metrics recorder
}

// NewStorage creates a new persistent storage backend
func NewStorage(config StorageConfig) (*Storage, error) {
	if config.DataDir == "" {
		return nil, fmt.Errorf("data_dir is required")
	}

	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	// Open BadgerDB
	// IMPORTANT: For mail queue, we MUST use sync writes to guarantee durability.
	// Messages should NEVER be lost after SMTP 250 OK is sent.
	syncWrites := true // Default to sync for mail queue safety
	if !config.SyncWrites {
		// Allow disabling for testing, but NOT recommended for production
		syncWrites = false
		config.Logger.Warn("Async writes enabled - messages may be lost on crash (NOT RECOMMENDED for production)")
	}

	opts := badger.DefaultOptions(config.DataDir).
		WithLogger(nil).            // Disable BadgerDB's own logging
		WithSyncWrites(syncWrites). // Sync writes for durability (required for mail queue)
		WithNumVersionsToKeep(1)    // We don't need versioning

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open BadgerDB: %w", err)
	}

	s := &Storage{
		db:      db,
		logger:  config.Logger,
		metrics: config.Metrics,
	}

	// Start garbage collection
	go s.runGC()

	return s, nil
}

// Close closes the storage backend
func (s *Storage) Close() error {
	return s.db.Close()
}

// SaveJob persists a delivery job and its schedule entry
// IMPORTANT: If updating an existing job, this will delete the old schedule entry
func (s *Storage) SaveJob(job *DeliveryJob) error {
	// Serialize job
	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		// Check if job already exists to get old NextRetry time
		var oldJob DeliveryJob
		jobKey := []byte("job:" + job.ID)
		oldItem, err := txn.Get(jobKey)
		if err == nil {
			// Job exists - need to delete old schedule entry
			err = oldItem.Value(func(val []byte) error {
				return json.Unmarshal(val, &oldJob)
			})
			if err == nil && !oldJob.NextRetry.Equal(job.NextRetry) {
				// Delete old schedule entry if time changed
				oldScheduleKey := s.scheduleKey(oldJob.NextRetry, job.ID)
				if err := txn.Delete(oldScheduleKey); err != nil && err != badger.ErrKeyNotFound {
					return fmt.Errorf("failed to delete old schedule entry: %w", err)
				}
			}
		}
		// If job doesn't exist (ErrKeyNotFound), that's fine - it's a new job

		// Save job data
		if err := txn.Set(jobKey, data); err != nil {
			return err
		}

		// Save new schedule index (for time-based retrieval)
		scheduleKey := s.scheduleKey(job.NextRetry, job.ID)
		if err := txn.Set(scheduleKey, []byte{}); err != nil {
			return err
		}

		return nil
	})
}

// GetJob retrieves a job by ID
func (s *Storage) GetJob(jobID string) (*DeliveryJob, error) {
	var job DeliveryJob

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("job:" + jobID))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &job)
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}
	if err != nil {
		return nil, err
	}

	return &job, nil
}

// DeleteJob removes a job and its schedule entry
func (s *Storage) DeleteJob(job *DeliveryJob) error {
	return s.db.Update(func(txn *badger.Txn) error {
		// Delete job data
		jobKey := []byte("job:" + job.ID)
		if err := txn.Delete(jobKey); err != nil && err != badger.ErrKeyNotFound {
			return err
		}

		// Delete old schedule entry
		scheduleKey := s.scheduleKey(job.NextRetry, job.ID)
		if err := txn.Delete(scheduleKey); err != nil && err != badger.ErrKeyNotFound {
			return err
		}

		return nil
	})
}

// GetDueJobs returns all jobs that are due for retry (NextRetry <= now)
func (s *Storage) GetDueJobs(limit int) ([]*DeliveryJob, error) {
	jobs := make([]*DeliveryJob, 0, limit)
	now := time.Now()

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 100
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte("schedule:")
		maxKey := s.scheduleKey(now, "\xff") // Scan up to current time

		for it.Seek(prefix); it.ValidForPrefix(prefix) && len(jobs) < limit; it.Next() {
			item := it.Item()
			key := item.Key()

			// Stop if we've passed the current time
			if string(key) > string(maxKey) {
				break
			}

			// Extract job ID from schedule key
			jobID := s.extractJobIDFromScheduleKey(string(key))
			if jobID == "" {
				continue
			}

			// Load the job
			jobItem, err := txn.Get([]byte("job:" + jobID))
			if err == badger.ErrKeyNotFound {
				// Job was deleted, clean up orphaned schedule entry
				continue
			}
			if err != nil {
				return err
			}

			var job DeliveryJob
			err = jobItem.Value(func(val []byte) error {
				return json.Unmarshal(val, &job)
			})
			if err != nil {
				s.logger.Error("Failed to unmarshal job", zap.String("job_id", jobID), zap.Error(err))
				continue
			}

			jobs = append(jobs, &job)
		}

		return nil
	})

	return jobs, err
}

// MoveToDLQ moves a job to the dead letter queue
func (s *Storage) MoveToDLQ(job *DeliveryJob, reason string) error {
	// Add DLQ metadata
	dlqEntry := &DLQEntry{
		Job:       job,
		Reason:    reason,
		MovedAt:   time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	data, err := json.Marshal(dlqEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal DLQ entry: %w", err)
	}

	err = s.db.Update(func(txn *badger.Txn) error {
		// Save to DLQ
		dlqKey := []byte("dlq:" + job.ID)
		entry := badger.NewEntry(dlqKey, data).WithTTL(7 * 24 * time.Hour)
		if err := txn.SetEntry(entry); err != nil {
			return err
		}

		// Delete from active queue
		jobKey := []byte("job:" + job.ID)
		if err := txn.Delete(jobKey); err != nil && err != badger.ErrKeyNotFound {
			return err
		}

		scheduleKey := s.scheduleKey(job.NextRetry, job.ID)
		if err := txn.Delete(scheduleKey); err != nil && err != badger.ErrKeyNotFound {
			return err
		}

		return nil
	})

	if err == nil && s.metrics != nil {
		s.metrics.RecordDLQMoved(reason)
	}

	return err
}

// GetDLQEntries returns DLQ entries with optional limit
func (s *Storage) GetDLQEntries(limit int) ([]*DLQEntry, error) {
	entries := make([]*DLQEntry, 0)

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 100
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte("dlq:")
		count := 0
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			if limit > 0 && count >= limit {
				break
			}

			item := it.Item()
			var entry DLQEntry
			err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &entry)
			})
			if err != nil {
				s.logger.Error("Failed to unmarshal DLQ entry", zap.Error(err))
				continue
			}

			entries = append(entries, &entry)
			count++
		}

		return nil
	})

	return entries, err
}

// GetDLQEntry retrieves a specific DLQ entry by job ID
func (s *Storage) GetDLQEntry(jobID string) (*DLQEntry, error) {
	var entry DLQEntry

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("dlq:" + jobID))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &entry)
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, fmt.Errorf("DLQ entry not found: %s", jobID)
	}
	if err != nil {
		return nil, err
	}

	return &entry, nil
}

// ReprocessDLQJob moves a job from DLQ back to the active queue for retry
func (s *Storage) ReprocessDLQJob(jobID string) error {
	err := s.db.Update(func(txn *badger.Txn) error {
		// Get DLQ entry
		dlqKey := []byte("dlq:" + jobID)
		item, err := txn.Get(dlqKey)
		if err == badger.ErrKeyNotFound {
			return fmt.Errorf("DLQ entry not found: %s", jobID)
		}
		if err != nil {
			return err
		}

		var dlqEntry DLQEntry
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &dlqEntry)
		})
		if err != nil {
			return fmt.Errorf("failed to unmarshal DLQ entry: %w", err)
		}

		job := dlqEntry.Job

		// Reset job for reprocessing
		job.Attempts = 0
		job.LastAttempt = time.Time{} // Zero value
		job.NextRetry = time.Now()    // Schedule for immediate retry
		job.CreatedAt = time.Now()    // Reset created time to extend retry window

		// Save job back to active queue
		jobData, err := json.Marshal(job)
		if err != nil {
			return fmt.Errorf("failed to marshal job: %w", err)
		}

		jobKey := []byte("job:" + job.ID)
		if err := txn.Set(jobKey, jobData); err != nil {
			return err
		}

		// Add schedule entry
		scheduleKey := s.scheduleKey(job.NextRetry, job.ID)
		if err := txn.Set(scheduleKey, []byte{}); err != nil {
			return err
		}

		// Delete from DLQ
		if err := txn.Delete(dlqKey); err != nil {
			return err
		}

		return nil
	})

	if err == nil && s.metrics != nil {
		s.metrics.RecordDLQReprocessed()
	}

	return err
}

// DeleteDLQEntry removes a specific entry from the DLQ
func (s *Storage) DeleteDLQEntry(jobID string) error {
	err := s.db.Update(func(txn *badger.Txn) error {
		dlqKey := []byte("dlq:" + jobID)

		// Check if entry exists first
		_, err := txn.Get(dlqKey)
		if err == badger.ErrKeyNotFound {
			return fmt.Errorf("DLQ entry not found: %s", jobID)
		}
		if err != nil {
			return err
		}

		// Delete the entry
		return txn.Delete(dlqKey)
	})

	if err == nil && s.metrics != nil {
		s.metrics.RecordDLQDeleted()
	}

	return err
}

// GetAllJobs returns all jobs in the queue (for recovery/inspection)
func (s *Storage) GetAllJobs() ([]*DeliveryJob, error) {
	jobs := make([]*DeliveryJob, 0)

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 100
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte("job:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			var job DeliveryJob
			err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &job)
			})
			if err != nil {
				s.logger.Error("Failed to unmarshal job during recovery", zap.Error(err))
				continue
			}

			jobs = append(jobs, &job)
		}

		return nil
	})

	return jobs, err
}

// GetStats returns storage statistics
func (s *Storage) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	var jobCount, scheduleCount, dlqCount int

	err := s.db.View(func(txn *badger.Txn) error {
		// Count jobs
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek([]byte("job:")); it.ValidForPrefix([]byte("job:")); it.Next() {
			jobCount++
		}

		for it.Seek([]byte("schedule:")); it.ValidForPrefix([]byte("schedule:")); it.Next() {
			scheduleCount++
		}

		for it.Seek([]byte("dlq:")); it.ValidForPrefix([]byte("dlq:")); it.Next() {
			dlqCount++
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	stats["jobs"] = jobCount
	stats["schedule_entries"] = scheduleCount
	stats["dlq_entries"] = dlqCount

	// Get BadgerDB LSM stats
	lsm, vlog := s.db.Size()
	stats["lsm_size_bytes"] = lsm
	stats["vlog_size_bytes"] = vlog

	return stats, nil
}

// scheduleKey creates a time-sortable key for the schedule index
// Format: "schedule:{unix_timestamp_ms}:{job_id}"
func (s *Storage) scheduleKey(t time.Time, jobID string) []byte {
	// Use millisecond precision for better sorting
	timestamp := t.UnixMilli()
	return []byte(fmt.Sprintf("schedule:%019d:%s", timestamp, jobID))
}

// extractJobIDFromScheduleKey extracts the job ID from a schedule key
func (s *Storage) extractJobIDFromScheduleKey(key string) string {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	return parts[2]
}

// runGC runs BadgerDB garbage collection periodically
func (s *Storage) runGC() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
	again:
		err := s.db.RunValueLogGC(0.5) // Discard 50% or more
		if err == nil {
			// GC was successful, run again
			goto again
		}
		// No more GC needed or error occurred
	}
}

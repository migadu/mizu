package queue

import (
	"fmt"
	"time"
)

// DeliveryJob represents a single email delivery task
type DeliveryJob struct {
	// Identifiers
	ID      string // Unique job ID (UUID)
	TraceID string // SMTP session trace ID for correlation

	// Email content
	EmailContent    string   // Raw email with all headers (DEPRECATED for large emails)
	EmailStorageKey string   // Storage key for email content (filesystem, empty if inline)
	Recipients      []string // Recipients for this specific job

	// Destination
	Endpoint         string // HTTP endpoint URL (delivery or forward)
	APIKey           string // API key for this endpoint
	IsForwarding     bool   // true = forwarding job, false = delivery job
	IsCustomEndpoint bool   // true = endpoint from routing response, false = default endpoint

	// Metadata from SMTP session
	From       string // MAIL FROM address
	OriginalTo string // Original RCPT TO address (before routing)
	IsJunk     bool   // Spam classification

	// Retry tracking
	Attempts    int       // Number of attempts so far
	MaxAttempts int       // Maximum allowed attempts
	LastAttempt time.Time // When last attempt was made
	NextRetry   time.Time // When to retry next (if failed)

	// Timestamps
	CreatedAt time.Time // When job was created

	// Priority
	Priority int // Job priority (higher value means higher priority)
}

// GetEmailContent retrieves the email content, from storage key or inline
func (dj *DeliveryJob) GetEmailContent(emailStorage *EmailStorage) (string, error) {
	// If storage key is set, load from filesystem
	if dj.EmailStorageKey != "" {
		if emailStorage == nil {
			return "", fmt.Errorf("email storage required but not provided")
		}
		content, err := emailStorage.Load(dj.EmailStorageKey)
		if err != nil {
			return "", fmt.Errorf("failed to load email from storage: %w", err)
		}
		return string(content), nil
	}

	// Otherwise use inline content
	return dj.EmailContent, nil
}

// SetEmailContent stores email content, using filesystem for large emails
// Threshold: emails > 1MB are stored on filesystem
func (dj *DeliveryJob) SetEmailContent(content string, emailStorage *EmailStorage) error {
	const storageThreshold = 1 << 20 // 1MB

	contentSize := len(content)

	// Small emails: store inline in BadgerDB
	if contentSize <= storageThreshold || emailStorage == nil {
		dj.EmailContent = content
		dj.EmailStorageKey = ""
		return nil
	}

	// Large emails: store on filesystem
	storageKey, err := emailStorage.Save(dj.ID, []byte(content))
	if err != nil {
		return fmt.Errorf("failed to save email to storage: %w", err)
	}

	dj.EmailContent = "" // Clear inline content to save space in BadgerDB
	dj.EmailStorageKey = storageKey

	return nil
}

// QueueStats provides metrics about the queue
type QueueStats struct {
	TotalEnqueued  int64 // Total jobs ever enqueued
	TotalDelivered int64 // Total jobs successfully delivered
	TotalFailed    int64 // Total jobs permanently failed
	TotalRetries   int64 // Total retry attempts

	CurrentSize    int // Current number of jobs in queue
	WorkersActive  int // Number of worker goroutines
	WorkersRunning int // Number of workers currently processing jobs

	// DLQ statistics
	DLQSize      int     // Current number of jobs in DLQ
	DLQOldestAge float64 // Age of oldest DLQ entry in seconds (0 if empty)
}

// QueueConfig holds configuration for the delivery queue
type QueueConfig struct {
	// Capacity
	MaxSize int // Maximum jobs in queue (0 = unlimited)
	Workers int // Number of concurrent worker goroutines

	// Priority processing
	PriorityMode bool // Enable priority-based job processing (default: false)

	// Retry behavior (in-memory queue)
	MaxRetryAttempts int           // Maximum retry attempts per job
	InitialDelay     time.Duration // Initial retry delay (default: 1s)
	MaxDelay         time.Duration // Maximum retry delay (default: 5m)
	Multiplier       float64       // Backoff multiplier (default: 2.0)
	UseJitter        bool          // Add randomness to backoff (default: true)

	// Retry behavior (persistent queue)
	MaxRetryHours   int           // Maximum hours to retry before giving up (persistent queue, default: 48)
	SchedulerTicker time.Duration // How often scheduler checks for due jobs (default: 10s, can be shortened for tests)

	// Timeouts
	DeliveryTimeout      time.Duration // HTTP request timeout per attempt
	ShutdownTimeout      time.Duration // Max time to wait for graceful shutdown
	ShutdownDrainTimeout time.Duration // Max time to drain queue on shutdown
}

// DefaultQueueConfig returns sensible defaults
func DefaultQueueConfig() QueueConfig {
	return QueueConfig{
		MaxSize:              10000,
		Workers:              10,
		MaxRetryAttempts:     5,
		InitialDelay:         1 * time.Second,
		MaxDelay:             5 * time.Minute,
		Multiplier:           2.0,
		UseJitter:            true,
		DeliveryTimeout:      30 * time.Second,
		ShutdownTimeout:      30 * time.Second,
		ShutdownDrainTimeout: 60 * time.Second,
	}
}

// DLQEntry represents a job in the dead letter queue
type DLQEntry struct {
	Job       *DeliveryJob `json:"job"`
	Reason    string       `json:"reason"`
	MovedAt   time.Time    `json:"moved_at"`
	ExpiresAt time.Time    `json:"expires_at"` // Keep DLQ entries for 7 days
}

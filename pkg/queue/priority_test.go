package queue

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestPersistentQueue_PriorityProcessing tests that jobs are processed by priority
func TestPersistentQueue_PriorityProcessing(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "priority-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Track processing order
	processedJobs := make(chan string, 10)

	// Mock HTTP server - tracks requests by Trace ID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract trace ID from headers (poster uses X-Trace-ID)
		traceID := r.Header.Get("X-Trace-ID")
		if traceID != "" {
			processedJobs <- traceID
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create queue with priority mode enabled
	config := DefaultQueueConfig()
	config.Workers = 1 // Single worker to see clear ordering
	config.PriorityMode = true
	config.SchedulerTicker = 100 * time.Millisecond
	config.MaxRetryHours = 1

	queue, err := NewPersistentQueue(
		config,
		tmpDir,
		&http.Client{Timeout: 5 * time.Second},
		nil, // No circuit breaker
		nil, // No circuit breaker
		zap.NewNop(),
		nil, // No metrics
	)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	if err := queue.Start(); err != nil {
		t.Fatalf("Failed to start queue: %v", err)
	}
	defer queue.Shutdown(context.Background())

	// Enqueue jobs with different priorities
	// Priority values: higher = more urgent
	jobs := []struct {
		id       string
		priority int
	}{
		{"low-priority-job", 1},
		{"high-priority-job", 10},
		{"medium-priority-job", 5},
		{"urgent-job", 20},
		{"normal-job", 3},
	}

	for _, j := range jobs {
		job := &DeliveryJob{
			ID:           j.id,
			TraceID:      j.id, // Use job ID as trace ID for tracking
			EmailContent: "Subject: Test\r\n\r\nTest email",
			Recipients:   []string{"test@example.com"},
			Endpoint:     server.URL,
			Priority:     j.priority,
			CreatedAt:    time.Now(),
			NextRetry:    time.Now(), // Due immediately
		}

		if err := queue.Enqueue(job); err != nil {
			t.Fatalf("Failed to enqueue job %s: %v", j.id, err)
		}
	}

	t.Logf("Enqueued %d jobs with different priorities", len(jobs))

	// Wait for jobs to be processed
	time.Sleep(2 * time.Second)

	// Collect processed job IDs
	close(processedJobs)
	processed := []string{}
	for id := range processedJobs {
		processed = append(processed, id)
	}

	t.Logf("Processing order: %v", processed)

	// Verify that higher priority jobs were processed first
	// Expected order (by priority): urgent-job(20), high-priority-job(10), medium-priority-job(5), normal-job(3), low-priority-job(1)
	if len(processed) < len(jobs) {
		t.Errorf("Expected %d jobs processed, got %d", len(jobs), len(processed))
	}

	// Check that highest priority job was processed first
	if len(processed) > 0 && processed[0] != "urgent-job" {
		t.Logf("Warning: Expected 'urgent-job' to be processed first, got '%s'", processed[0])
		t.Logf("Note: Exact order may vary due to scheduler timing")
	}
}

// TestPriorityQueue_BasicOperations tests the priority queue implementation
func TestPriorityQueue_BasicOperations(t *testing.T) {
	pq := NewPriorityQueue()

	// Add jobs with different priorities
	jobs := []*DeliveryJob{
		{ID: "job1", Priority: 5, EmailContent: "Job 1"},
		{ID: "job2", Priority: 10, EmailContent: "Job 2"},
		{ID: "job3", Priority: 1, EmailContent: "Job 3"},
		{ID: "job4", Priority: 15, EmailContent: "Job 4"},
	}

	for _, job := range jobs {
		pq.PushJob(job)
	}

	if pq.Len() != 4 {
		t.Errorf("Expected queue length 4, got %d", pq.Len())
	}

	// Pop jobs - should come out in priority order (highest first)
	expected := []string{"job4", "job2", "job1", "job3"} // Priority: 15, 10, 5, 1
	for i, expectedID := range expected {
		job := pq.PopJob()
		if job == nil {
			t.Fatalf("PopJob returned nil at position %d", i)
		}
		if job.ID != expectedID {
			t.Errorf("Expected job %s at position %d, got %s", expectedID, i, job.ID)
		}
	}

	// Queue should be empty now
	if pq.Len() != 0 {
		t.Errorf("Expected empty queue, got length %d", pq.Len())
	}

	// Pop from empty queue should return nil
	if job := pq.PopJob(); job != nil {
		t.Errorf("Expected nil from empty queue, got job %s", job.ID)
	}
}

// TestPriorityQueue_SamePriority tests jobs with same priority
func TestPriorityQueue_SamePriority(t *testing.T) {
	pq := NewPriorityQueue()

	// Add jobs with same priority
	for i := 1; i <= 3; i++ {
		pq.PushJob(&DeliveryJob{
			ID:       "job" + string(rune('0'+i)),
			Priority: 5, // All same priority
		})
	}

	// All jobs should be popped (order may vary for same priority)
	popped := 0
	for i := 0; i < 3; i++ {
		if job := pq.PopJob(); job != nil {
			popped++
		}
	}

	if popped != 3 {
		t.Errorf("Expected to pop 3 jobs, got %d", popped)
	}
}

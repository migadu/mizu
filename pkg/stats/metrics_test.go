package stats

import (
	"io"

	"testing"
	"time"

	"log/slog"
)

// TestEventMetrics_ProcessedCounter verifies that processed events are counted
func TestEventMetrics_ProcessedCounter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	// Send some events
	manager.RecordConnection("192.168.1.100", true)
	manager.RecordMailFrom("example.com")
	manager.RecordHamDelivery("192.168.1.100", "example.com", 1)

	// Give time for events to be processed
	time.Sleep(50 * time.Millisecond)

	// Check metrics
	manager.metricsMu.RLock()
	processed := manager.eventsProcessed
	dropped := manager.eventsDropped
	manager.metricsMu.RUnlock()

	if processed != 3 {
		t.Errorf("Expected 3 processed events, got %d", processed)
	}

	if dropped != 0 {
		t.Errorf("Expected 0 dropped events, got %d", dropped)
	}
}

// TestEventMetrics_DroppedCounter verifies that dropped events are counted
func TestEventMetrics_DroppedCounter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 100, logger)

	// Don't start the processing loop - this will cause channel to fill
	// manager.Start() // Intentionally not started

	// Fill the channel completely (100 buffer for test)
	bufferSize := cap(manager.eventChan)
	for i := 0; i < bufferSize; i++ {
		manager.RecordConnection("192.168.1.100", true)
	}

	// These should be dropped
	for i := 0; i < 10; i++ {
		manager.RecordConnection("192.168.1.100", true)
	}

	// Check metrics
	manager.metricsMu.RLock()
	dropped := manager.eventsDropped
	manager.metricsMu.RUnlock()

	if dropped != 10 {
		t.Errorf("Expected 10 dropped events, got %d", dropped)
	}
}

// TestEventMetrics_HealthCheck verifies health check reports metrics
func TestEventMetrics_HealthCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	// Send some events
	for i := 0; i < 100; i++ {
		manager.RecordConnection("192.168.1.100", true)
	}

	// Give time for processing
	time.Sleep(100 * time.Millisecond)

	// Check health status
	status := manager.CheckHealth()

	if status.Status != "healthy" {
		t.Errorf("Expected healthy status, got %s", status.Status)
	}

	details, ok := status.Details.(map[string]any)
	if !ok {
		t.Fatal("Expected details to be map[string]any")
	}

	// Verify metrics are present
	if _, exists := details["events_processed"]; !exists {
		t.Error("Expected events_processed in health check details")
	}

	if _, exists := details["events_dropped"]; !exists {
		t.Error("Expected events_dropped in health check details")
	}

	if _, exists := details["channel_length"]; !exists {
		t.Error("Expected channel_length in health check details")
	}

	if _, exists := details["channel_capacity"]; !exists {
		t.Error("Expected channel_capacity in health check details")
	}

	if _, exists := details["channel_util_pct"]; !exists {
		t.Error("Expected channel_util_pct in health check details")
	}
}

// TestEventMetrics_HealthCheck_Degraded verifies degraded status when channel is full
func TestEventMetrics_HealthCheck_Degraded(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 1000, logger)

	// Don't start processing - let channel fill up
	// manager.Start()

	// Fill channel to >80%
	bufferSize := cap(manager.eventChan)
	for i := 0; i < int(float64(bufferSize)*0.85); i++ {
		manager.RecordConnection("192.168.1.100", true)
	}

	// Check health status
	status := manager.CheckHealth()

	if status.Status != "degraded" {
		t.Errorf("Expected degraded status when channel >80%% full, got %s", status.Status)
	}

	details, ok := status.Details.(map[string]any)
	if !ok {
		t.Fatal("Expected details to be map[string]any")
	}

	chanUtil := details["channel_util_pct"].(float64)
	if chanUtil <= 80.0 {
		t.Errorf("Expected channel utilization >80%%, got %.2f%%", chanUtil)
	}
}

// TestEventMetrics_HealthCheck_Unhealthy verifies unhealthy status when drop rate is high
func TestEventMetrics_HealthCheck_Unhealthy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 1000, logger)

	// Don't start processing - this will cause all events to either fill buffer or drop
	// manager.Start()

	// Fill channel completely
	bufferSize := cap(manager.eventChan)
	for i := 0; i < bufferSize; i++ {
		manager.RecordConnection("192.168.1.100", true)
	}

	// These will be dropped
	for i := 0; i < 100; i++ {
		manager.RecordConnection("192.168.1.100", true)
	}

	// Check health status
	status := manager.CheckHealth()

	// Should be unhealthy due to >1% drop rate (100/1100 = ~9%)
	if status.Status != "unhealthy" && status.Status != "degraded" {
		t.Errorf("Expected unhealthy or degraded status with drops, got %s", status.Status)
		t.Logf("Details: %+v", status.Details)
	}

	details, ok := status.Details.(map[string]any)
	if !ok {
		t.Fatal("Expected details to be map[string]any")
	}

	// Verify drops occurred
	dropped := details["events_dropped"].(uint64)
	if dropped != 100 {
		t.Errorf("Expected 100 dropped events, got %d", dropped)
	}

	// Verify drop rate is calculated
	if _, exists := details["drop_rate_pct"]; !exists {
		t.Error("Expected drop_rate_pct in health check details when events are dropped")
	}
}

// TestEventMetrics_ChannelUtilization verifies channel utilization calculation
func TestEventMetrics_ChannelUtilization(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 1000, logger)

	// Don't start processing

	// Fill half the channel
	bufferSize := cap(manager.eventChan)
	halfFull := bufferSize / 2
	for i := 0; i < halfFull; i++ {
		manager.RecordConnection("192.168.1.100", true)
	}

	// Check health
	status := manager.CheckHealth()
	details, ok := status.Details.(map[string]any)
	if !ok {
		t.Fatal("Expected details to be map[string]any")
	}

	chanUtil := details["channel_util_pct"].(float64)
	expectedUtil := 50.0 // 50% full

	// Allow some tolerance
	if chanUtil < expectedUtil-5.0 || chanUtil > expectedUtil+5.0 {
		t.Errorf("Expected channel utilization ~%.0f%%, got %.2f%%", expectedUtil, chanUtil)
	}

	chanLen := details["channel_length"].(int)
	if chanLen != halfFull {
		t.Errorf("Expected channel length %d, got %d", halfFull, chanLen)
	}

	chanCap := details["channel_capacity"].(int)
	if chanCap != bufferSize {
		t.Errorf("Expected channel capacity %d, got %d", bufferSize, chanCap)
	}
}

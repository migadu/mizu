package stats

import (
	"io"

	"testing"
	"time"

	"log/slog"
)

func TestMergeIPEntry(t *testing.T) {
	now := time.Now()

	// --- Test Case 1: Merging into an empty manager (new entry) ---
	t.Run("New IP Entry", func(t *testing.T) {
		manager := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
		remoteIP := "1.1.1.1"
		remoteEntry := &IPExport{
			FirstSeen:   now.Add(-1 * time.Hour),
			LastSeen:    now,
			Connections: 10,
			Positive:    5,
			Negative:    2,
			IsDenied:    false,
		}

		manager.mergeIPEntry(remoteIP, remoteEntry)

		localEntry, exists := manager.ips[remoteIP]
		if !exists {
			t.Fatal("Expected entry to be created, but it was not")
		}

		if localEntry.Connections != 10 {
			t.Errorf("Expected connections to be 10, got %d", localEntry.Connections)
		}
		if localEntry.Positive != 5 {
			t.Errorf("Expected positive to be 5, got %d", localEntry.Positive)
		}
		if localEntry.Negative != 2 {
			t.Errorf("Expected negative to be 2, got %d", localEntry.Negative)
		}
	})

	// --- Test Case 2: Merging an existing entry ---
	t.Run("Existing IP Entry", func(t *testing.T) {
		manager := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
		ip := "2.2.2.2"

		// Setup initial local entry
		manager.ips[ip] = &IPEntry{
			FirstSeen:   now.Add(-2 * time.Hour),
			LastSeen:    now.Add(-1 * time.Hour),
			Connections: 5,
			Positive:    10,
			Negative:    3,
			IsDenied:    false,
		}

		// Create remote entry to merge
		remoteEntry := &IPExport{
			FirstSeen:   now.Add(-3 * time.Hour), // Earlier FirstSeen
			LastSeen:    now,                     // Later LastSeen
			Connections: 8,
			Positive:    12,
			Negative:    4,
			IsDenied:    true, // IsDenied should propagate
		}

		manager.mergeIPEntry(ip, remoteEntry)

		localEntry := manager.ips[ip]

		// Check summed values
		if localEntry.Connections != 13 { // 5 + 8
			t.Errorf("Expected connections to be 13, got %d", localEntry.Connections)
		}
		if localEntry.Positive != 22 { // 10 + 12
			t.Errorf("Expected positive to be 22, got %d", localEntry.Positive)
		}
		if localEntry.Negative != 7 { // 3 + 4
			t.Errorf("Expected negative to be 7, got %d", localEntry.Negative)
		}

		// Check other fields
		if !localEntry.FirstSeen.Equal(now.Add(-3 * time.Hour)) {
			t.Errorf("Expected FirstSeen to be the earliest time")
		}
		if !localEntry.LastSeen.Equal(now) {
			t.Errorf("Expected LastSeen to be the latest time")
		}
		if !localEntry.IsDenied {
			t.Error("Expected IsDenied to be true after merge")
		}
	})
}

func TestMergeDomainEntry(t *testing.T) {
	now := time.Now()

	// --- Test Case 1: New domain entry ---
	t.Run("New Domain Entry", func(t *testing.T) {
		manager := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
		domain := "newdomain.com"
		remoteEntry := &DomainExport{
			FirstSeen: now.Add(-1 * time.Hour),
			LastSeen:  now,
			Messages:  5,
			Positive:  3,
			Negative:  1,
		}

		manager.mergeDomainEntry(domain, remoteEntry)

		localEntry, exists := manager.domains[domain]
		if !exists {
			t.Fatal("Expected domain entry to be created, but it was not")
		}
		if localEntry.Messages != 5 {
			t.Errorf("Expected messages to be 5, got %d", localEntry.Messages)
		}
	})

	// --- Test Case 2: Existing domain entry ---
	t.Run("Existing Domain Entry", func(t *testing.T) {
		manager := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
		domain := "existing.com"

		manager.domains[domain] = &DomainEntry{
			FirstSeen: now.Add(-2 * time.Hour),
			LastSeen:  now.Add(-1 * time.Hour),
			Messages:  10,
			Positive:  8,
			Negative:  2,
		}

		remoteEntry := &DomainExport{
			FirstSeen: now.Add(-3 * time.Hour),
			LastSeen:  now,
			Messages:  15,
			Positive:  10,
			Negative:  5,
		}

		manager.mergeDomainEntry(domain, remoteEntry)
		localEntry := manager.domains[domain]

		if localEntry.Messages != 25 { // 10 + 15
			t.Errorf("Expected messages to be 25, got %d", localEntry.Messages)
		}
		if localEntry.Positive != 18 { // 8 + 10
			t.Errorf("Expected positive to be 18, got %d", localEntry.Positive)
		}
		if localEntry.Negative != 7 { // 2 + 5
			t.Errorf("Expected negative to be 7, got %d", localEntry.Negative)
		}
	})
}

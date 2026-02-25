package stats

import (
	"math"
	"testing"
	"time"
)

const float64EqualityThreshold = 1e-3

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) <= float64EqualityThreshold
}

func TestIPEntry_GetReputation_TimeDecay(t *testing.T) {
	tests := []struct {
		name          string
		positive      int64
		negative      int64
		lastSeen      time.Time
		connections   int64
		expectedScore float64
	}{
		{
			name:          "No decay - recent event",
			positive:      10,
			negative:      10,
			lastSeen:      time.Now(),
			connections:   MinDataThreshold,
			expectedScore: 0.0, // decayedNegative = 10. (10 - 10) / (10 + 10) = 0
		},
		{
			name:          "Half decay - 12 hours ago",
			positive:      10,
			negative:      10,
			lastSeen:      time.Now().Add(-12 * time.Hour),
			connections:   MinDataThreshold,
			expectedScore: 0.333, // decayedNegative = 10 * 0.5 = 5. (10 - 5) / (10 + 5) = 5 / 15
		},
		{
			name:          "Full decay - 24 hours ago",
			positive:      10,
			negative:      10,
			lastSeen:      time.Now().Add(-24 * time.Hour),
			connections:   MinDataThreshold,
			expectedScore: 1.0, // decayedNegative = 0. (10 - 0) / (10 + 0) = 1
		},
		{
			name:          "Full decay - more than 24 hours ago",
			positive:      10,
			negative:      10,
			lastSeen:      time.Now().Add(-48 * time.Hour),
			connections:   MinDataThreshold,
			expectedScore: 1.0, // decayedNegative = 0. (10 - 0) / (10 + 0) = 1
		},
		{
			name:          "No positive score, half decay",
			positive:      0,
			negative:      10,
			lastSeen:      time.Now().Add(-12 * time.Hour),
			connections:   MinDataThreshold,
			expectedScore: -1.0, // decayedNegative = 5. (0 - 5) / (0 + 5) = -1
		},
		{
			name:          "No positive score, full decay",
			positive:      0,
			negative:      10,
			lastSeen:      time.Now().Add(-24 * time.Hour),
			connections:   MinDataThreshold,
			expectedScore: 0.0, // decayedNegative = 0. total = 0.
		},
		{
			name:          "Not enough data",
			positive:      10,
			negative:      10,
			lastSeen:      time.Now(),
			connections:   MinDataThreshold - 1,
			expectedScore: 0.0, // Should return neutral score
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &IPEntry{
				Positive:    tt.positive,
				Negative:    tt.negative,
				LastSeen:    tt.lastSeen,
				Connections: tt.connections,
			}

			score := entry.GetReputation()
			if !almostEqual(score, tt.expectedScore) {
				t.Errorf("IPEntry.GetReputation() = %v, want %v", score, tt.expectedScore)
			}
		})
	}
}

// =============================================================================
// Per-Recipient Reputation Scoring Tests
// =============================================================================

// TestIPEntry_SingleRecipientHamDelivery verifies that a single-recipient
// delivery awards exactly WeightHamDelivery positive score.
func TestIPEntry_SingleRecipientHamDelivery(t *testing.T) {
	entry := &IPEntry{LastSeen: time.Now()}
	entry.AddPositive(WeightHamDelivery * 1) // 1 recipient

	if entry.Positive != WeightHamDelivery {
		t.Errorf("Positive = %d; want %d", entry.Positive, WeightHamDelivery)
	}
}

// TestIPEntry_MultiRecipientHamDelivery verifies that a multi-recipient
// delivery awards weight proportional to recipient count.
func TestIPEntry_MultiRecipientHamDelivery(t *testing.T) {
	entry := &IPEntry{LastSeen: time.Now()}
	recipientCount := 100
	entry.AddPositive(WeightHamDelivery * int64(recipientCount))

	expected := WeightHamDelivery * int64(recipientCount) // 100
	if entry.Positive != expected {
		t.Errorf("Positive = %d; want %d", entry.Positive, expected)
	}
}

// TestIPEntry_MailingListScenario tests the exact bug scenario:
// Google Groups sends to 100 recipients, 1 is invalid, 99 delivered.
//
// OLD behavior (per-message): +1 positive, -2 negative → net -1 ❌
// NEW behavior (per-recipient): +99 positive, -2 negative → net +97 ✅
//
// Due to the redemption mechanism in AddPositive, the final state is:
// Positive=99, Negative=max(2-99, 0)=0, net=99
func TestIPEntry_MailingListScenario(t *testing.T) {
	entry := &IPEntry{
		Connections: MinDataThreshold, // Enough data for reputation calculation
		LastSeen:    time.Now(),
	}

	// 1 invalid recipient during RCPT TO phase
	entry.AddNegative(WeightInvalidRecipient) // -2

	if entry.Negative != WeightInvalidRecipient {
		t.Errorf("After invalid recipient: Negative = %d; want %d", entry.Negative, WeightInvalidRecipient)
	}

	// 99 successful deliveries
	entry.AddPositive(WeightHamDelivery * 99) // +99

	if entry.Positive != 99 {
		t.Errorf("After delivery: Positive = %d; want 99", entry.Positive)
	}

	// Redemption reduces negative: 2 - 99 → clamped to 0
	if entry.Negative != 0 {
		t.Errorf("After delivery redemption: Negative = %d; want 0", entry.Negative)
	}

	// Reputation should be strongly positive
	rep := entry.GetReputation()
	if rep <= 0 {
		t.Errorf("Reputation = %f; should be positive for legitimate mailing list", rep)
	}
	if rep != 1.0 {
		t.Errorf("Reputation = %f; want 1.0 (all positive, zero negative)", rep)
	}

	// Should NOT be denied
	if entry.ShouldDeny() {
		t.Error("Legitimate mailing list should not be denied")
	}
}

// TestIPEntry_OldBehaviorWouldFail demonstrates that the old per-message
// scoring would have produced a negative reputation.
func TestIPEntry_OldBehaviorWouldFail(t *testing.T) {
	entry := &IPEntry{
		Connections: MinDataThreshold,
		LastSeen:    time.Now(),
	}

	// Old behavior: 1 invalid recipient
	entry.AddNegative(WeightInvalidRecipient) // -2

	// Old behavior: only +1 per message (not per recipient!)
	entry.AddPositive(WeightHamDelivery * 1) // +1

	// With old per-message scoring:
	// Positive = 1, Negative = max(2-1, 0) = 1
	// Net reputation = (1 - 1) / (1 + 1) = 0
	// This is neutral at best, which is wrong for 99% successful delivery
	if entry.Positive != 1 {
		t.Errorf("Old behavior Positive = %d; want 1", entry.Positive)
	}
	if entry.Negative != 1 {
		t.Errorf("Old behavior Negative = %d; want 1 (2 reduced by redemption of 1)", entry.Negative)
	}

	rep := entry.GetReputation()
	t.Logf("Old per-message behavior: positive=%d, negative=%d, reputation=%f (would be unfair to mailing lists)",
		entry.Positive, entry.Negative, rep)

	// The reputation is 0 or very low - this is the bug we fixed
	if rep > 0.5 {
		t.Errorf("Old behavior should NOT produce a strong positive reputation, got %f", rep)
	}
}

// TestIPEntry_BulkSpammerStillDenied verifies that a bulk spammer sending
// to many invalid recipients still gets negative reputation.
func TestIPEntry_BulkSpammerStillDenied(t *testing.T) {
	entry := &IPEntry{
		Connections: MinDataThreshold,
		LastSeen:    time.Now(),
	}

	// Spammer: 50 invalid recipients
	for i := 0; i < 50; i++ {
		entry.AddNegative(WeightInvalidRecipient) // -2 each = -100 total
	}

	// Only 5 successful deliveries
	entry.AddPositive(WeightHamDelivery * 5) // +5

	// Negative should still be dominant
	// After penalty: Positive = max(0-100+5, ...) complex redemption
	// Negative dominates significantly
	rep := entry.GetReputation()
	if rep >= 0 {
		t.Errorf("Spammer reputation = %f; should be negative", rep)
	}

	// Should be denied
	if !entry.ShouldDeny() {
		t.Error("Bulk spammer should be denied")
	}

	t.Logf("Bulk spammer: positive=%d, negative=%d, reputation=%f ✓",
		entry.Positive, entry.Negative, rep)
}

// TestIPEntry_RedemptionMechanicsWithMultiRecipient tests that the
// redemption mechanism works correctly with large positive weights.
func TestIPEntry_RedemptionMechanicsWithMultiRecipient(t *testing.T) {
	tests := []struct {
		name             string
		negativeFirst    int64 // applied first via AddNegative
		positiveWeight   int64 // applied second via AddPositive
		expectedPositive int64
		expectedNegative int64
	}{
		{
			name:             "Small negative, large positive",
			negativeFirst:    2,  // 1 invalid recipient
			positiveWeight:   99, // 99 successful deliveries
			expectedPositive: 99, // 99 added
			expectedNegative: 0,  // 2 - 99 → clamped to 0
		},
		{
			name:             "Equal negative and positive",
			negativeFirst:    10,
			positiveWeight:   10,
			expectedPositive: 10,
			expectedNegative: 0, // 10 - 10 = 0
		},
		{
			name:             "Large negative, small positive",
			negativeFirst:    100,
			positiveWeight:   5,
			expectedPositive: 5,
			expectedNegative: 95, // 100 - 5 = 95
		},
		{
			name:             "Zero positive after negative",
			negativeFirst:    10,
			positiveWeight:   0,
			expectedPositive: 0,
			expectedNegative: 10, // unchanged
		},
		{
			name:             "No negative, large positive",
			negativeFirst:    0,
			positiveWeight:   100,
			expectedPositive: 100,
			expectedNegative: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &IPEntry{LastSeen: time.Now()}

			if tt.negativeFirst > 0 {
				entry.AddNegative(tt.negativeFirst)
			}
			if tt.positiveWeight > 0 {
				entry.AddPositive(tt.positiveWeight)
			}

			if entry.Positive != tt.expectedPositive {
				t.Errorf("Positive = %d; want %d", entry.Positive, tt.expectedPositive)
			}
			if entry.Negative != tt.expectedNegative {
				t.Errorf("Negative = %d; want %d", entry.Negative, tt.expectedNegative)
			}
		})
	}
}

// TestIPEntry_PenaltyMechanicsWithMultiRecipient tests that the penalty
// mechanism (AddNegative reduces Positive) works with prior multi-recipient credit.
func TestIPEntry_PenaltyMechanicsWithMultiRecipient(t *testing.T) {
	tests := []struct {
		name             string
		positiveFirst    int64 // applied first via AddPositive
		negativeWeight   int64 // applied second via AddNegative
		expectedPositive int64
		expectedNegative int64
	}{
		{
			name:             "100 deliveries then 1 invalid",
			positiveFirst:    100,
			negativeWeight:   WeightInvalidRecipient, // 2
			expectedPositive: 98,                     // 100 - 2 = 98
			expectedNegative: 2,
		},
		{
			name:             "100 deliveries then spoofing attempt",
			positiveFirst:    100,
			negativeWeight:   WeightSpoofingAttempt, // 10
			expectedPositive: 90,                    // 100 - 10 = 90
			expectedNegative: 10,
		},
		{
			name:             "5 deliveries then DMARC failure",
			positiveFirst:    5,
			negativeWeight:   WeightDMARCFailure, // 10
			expectedPositive: 0,                  // 5 - 10 → clamped to 0
			expectedNegative: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &IPEntry{LastSeen: time.Now()}

			entry.AddPositive(tt.positiveFirst)
			entry.AddNegative(tt.negativeWeight)

			if entry.Positive != tt.expectedPositive {
				t.Errorf("Positive = %d; want %d", entry.Positive, tt.expectedPositive)
			}
			if entry.Negative != tt.expectedNegative {
				t.Errorf("Negative = %d; want %d", entry.Negative, tt.expectedNegative)
			}
		})
	}
}

// TestIPEntry_ReputationScoreWithMultiRecipient tests the computed reputation
// score for various mailing list scenarios.
func TestIPEntry_ReputationScoreWithMultiRecipient(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(e *IPEntry)
		wantDeny    bool
		wantRepSign int // -1 negative, 0 neutral, +1 positive
	}{
		{
			name: "Perfect mailing list: 100 recipients, 0 failures",
			setup: func(e *IPEntry) {
				e.Connections = MinDataThreshold
				e.AddPositive(100) // 100 successful recipients
			},
			wantDeny:    false,
			wantRepSign: +1,
		},
		{
			name: "Good mailing list: 100 recipients, 1 invalid",
			setup: func(e *IPEntry) {
				e.Connections = MinDataThreshold
				e.AddNegative(WeightInvalidRecipient) // -2 for 1 invalid
				e.AddPositive(99)                     // 99 successful
			},
			wantDeny:    false,
			wantRepSign: +1,
		},
		{
			name: "Good mailing list: 100 recipients, 5 invalid",
			setup: func(e *IPEntry) {
				e.Connections = MinDataThreshold
				for i := 0; i < 5; i++ {
					e.AddNegative(WeightInvalidRecipient) // 5 × -2 = -10
				}
				e.AddPositive(95) // 95 successful
			},
			wantDeny:    false,
			wantRepSign: +1,
		},
		{
			name: "Bad sender: 10 recipients, 8 invalid",
			setup: func(e *IPEntry) {
				e.Connections = MinDataThreshold
				for i := 0; i < 8; i++ {
					e.AddNegative(WeightInvalidRecipient) // 8 × -2 = -16
				}
				e.AddPositive(2) // only 2 successful
			},
			wantDeny:    true,
			wantRepSign: -1,
		},
		{
			name: "Spammer: 50 recipients, all junk",
			setup: func(e *IPEntry) {
				e.Connections = MinDataThreshold
				for i := 0; i < 50; i++ {
					e.AddNegative(WeightJunkMessage) // 50 × -1 = -50
				}
			},
			wantDeny:    true,
			wantRepSign: -1,
		},
		{
			name: "Mixed: 200 good deliveries, 10 junk, 5 invalid",
			setup: func(e *IPEntry) {
				e.Connections = MinDataThreshold
				e.AddPositive(200) // 200 good recipients
				for i := 0; i < 10; i++ {
					e.AddNegative(WeightJunkMessage) // 10 junk
				}
				for i := 0; i < 5; i++ {
					e.AddNegative(WeightInvalidRecipient) // 5 invalid
				}
			},
			wantDeny:    false,
			wantRepSign: +1,
		},
		{
			name: "Not enough data: should be neutral",
			setup: func(e *IPEntry) {
				e.Connections = MinDataThreshold - 1
				e.AddPositive(100)
			},
			wantDeny:    false,
			wantRepSign: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &IPEntry{LastSeen: time.Now()}
			tt.setup(entry)

			rep := entry.GetReputation()
			deny := entry.ShouldDeny()

			if deny != tt.wantDeny {
				t.Errorf("ShouldDeny() = %v; want %v (reputation=%f)", deny, tt.wantDeny, rep)
			}

			switch tt.wantRepSign {
			case +1:
				if rep <= 0 {
					t.Errorf("Reputation = %f; want positive", rep)
				}
			case -1:
				if rep >= 0 {
					t.Errorf("Reputation = %f; want negative", rep)
				}
			case 0:
				if rep != 0 {
					t.Errorf("Reputation = %f; want 0 (neutral)", rep)
				}
			}

			t.Logf("positive=%d, negative=%d, reputation=%.3f, deny=%v",
				entry.Positive, entry.Negative, rep, deny)
		})
	}
}

// TestDomainEntry_MultiRecipientReputation mirrors the IP tests for domain entries.
func TestDomainEntry_MultiRecipientReputation(t *testing.T) {
	t.Run("Mailing list: 100 recipients, 1 invalid", func(t *testing.T) {
		entry := &DomainEntry{
			Messages: MinDataThreshold,
			LastSeen: time.Now(),
		}

		entry.AddNegative(WeightInvalidRecipient) // -2
		entry.AddPositive(99)                     // 99 delivered

		if entry.Positive != 99 {
			t.Errorf("Positive = %d; want 99", entry.Positive)
		}
		if entry.Negative != 0 {
			t.Errorf("Negative = %d; want 0 (redeemed)", entry.Negative)
		}

		rep := entry.GetReputation()
		if rep <= 0 {
			t.Errorf("Domain reputation = %f; should be positive", rep)
		}
		if entry.ShouldDeny() {
			t.Error("Legitimate mailing list domain should not be denied")
		}
	})

	t.Run("Bulk spammer: many invalid recipients", func(t *testing.T) {
		entry := &DomainEntry{
			Messages: MinDataThreshold,
			LastSeen: time.Now(),
		}

		for i := 0; i < 50; i++ {
			entry.AddNegative(WeightInvalidRecipient) // 50 × -2 = -100
		}
		entry.AddPositive(2) // only 2 delivered

		rep := entry.GetReputation()
		if rep >= 0 {
			t.Errorf("Domain reputation = %f; should be negative for spammer", rep)
		}
		if !entry.ShouldDeny() {
			t.Error("Spammer domain should be denied")
		}

		t.Logf("Spammer domain: positive=%d, negative=%d, reputation=%.3f",
			entry.Positive, entry.Negative, rep)
	})

	t.Run("Redemption and penalty symmetry", func(t *testing.T) {
		entry := &DomainEntry{LastSeen: time.Now()}

		// First: large positive (100 recipients delivered)
		entry.AddPositive(100)
		if entry.Positive != 100 || entry.Negative != 0 {
			t.Errorf("After positive: pos=%d neg=%d; want pos=100 neg=0", entry.Positive, entry.Negative)
		}

		// Then: small negative (2 invalid recipients)
		entry.AddNegative(WeightInvalidRecipient)
		if entry.Positive != 98 || entry.Negative != 2 {
			t.Errorf("After negative: pos=%d neg=%d; want pos=98 neg=2", entry.Positive, entry.Negative)
		}

		// Then: another large positive (50 more recipients)
		entry.AddPositive(50)
		if entry.Positive != 148 || entry.Negative != 0 {
			t.Errorf("After 2nd positive: pos=%d neg=%d; want pos=148 neg=0", entry.Positive, entry.Negative)
		}
	})
}

// TestIPEntry_MultipleTransactions simulates multiple SMTP transactions from
// the same IP, each with different recipient counts.
func TestIPEntry_MultipleTransactions(t *testing.T) {
	entry := &IPEntry{
		Connections: MinDataThreshold,
		LastSeen:    time.Now(),
	}

	// Transaction 1: Newsletter to 50 recipients, all valid
	entry.AddPositive(WeightHamDelivery * 50) // +50

	// Transaction 2: Newsletter to 30 recipients, 2 invalid
	entry.AddNegative(WeightInvalidRecipient) // -2
	entry.AddNegative(WeightInvalidRecipient) // -2
	entry.AddPositive(WeightHamDelivery * 28) // +28

	// Transaction 3: Single email
	entry.AddPositive(WeightHamDelivery * 1) // +1

	// Total positive contributions: 50 + 28 + 1 = 79
	// But redemption reduces negative along the way
	// Net should be strongly positive
	rep := entry.GetReputation()
	if rep <= 0 {
		t.Errorf("Reputation after multiple transactions = %f; should be positive", rep)
	}
	if entry.ShouldDeny() {
		t.Error("IP with mostly good transactions should not be denied")
	}

	t.Logf("Multiple transactions: positive=%d, negative=%d, reputation=%.3f",
		entry.Positive, entry.Negative, rep)
}

func TestDomainEntry_GetReputation_TimeDecay(t *testing.T) {
	tests := []struct {
		name          string
		positive      int64
		negative      int64
		lastSeen      time.Time
		messages      int64
		expectedScore float64
	}{
		{
			name:          "No decay - recent event",
			positive:      10,
			negative:      10,
			lastSeen:      time.Now(),
			messages:      MinDataThreshold,
			expectedScore: 0.0, // (10 - 10) / (10 + 10) = 0
		},
		{
			name:          "Half decay - 12 hours ago",
			positive:      10,
			negative:      10,
			lastSeen:      time.Now().Add(-12 * time.Hour),
			messages:      MinDataThreshold,
			expectedScore: 0.333, // decayedNegative = 5. (10 - 5) / (10 + 5) = 5 / 15
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &DomainEntry{
				Positive: tt.positive,
				Negative: tt.negative,
				LastSeen: tt.lastSeen,
				Messages: tt.messages,
			}

			score := entry.GetReputation()
			if !almostEqual(score, tt.expectedScore) {
				t.Errorf("DomainEntry.GetReputation() = %v, want %v", score, tt.expectedScore)
			}
		})
	}
}

package smtp

import (
	"testing"
	"time"
)

// Audit A7 (docs/security-audit-todo.md): the reaper force-released slots of
// connections older than max_connection_duration, and the later, real Release
// of those same connections decremented the counters a second time - taking
// the slot of some other, still-open connection. Counters drifted below the
// number of live connections, so the limits stopped limiting.
//
// A slot is now a lease: releasing one that the reaper already took is a no-op.

func TestAudit_ReleaseAfterReapDoesNotFreeSomeoneElsesSlot(t *testing.T) {
	ct := NewConnectionTracker(100, 2, 20*time.Millisecond, nil)

	a1, err := ct.Acquire("192.0.2.1")
	if err != nil {
		t.Fatalf("a1: %v", err)
	}
	a2, err := ct.Acquire("192.0.2.1")
	if err != nil {
		t.Fatalf("a2: %v", err)
	}

	time.Sleep(40 * time.Millisecond)
	if reaped := ct.reapExpired(); reaped != 2 {
		t.Fatalf("reaped = %d, want 2", reaped)
	}

	// Two new connections from the same address, and one from another.
	a3, err := ct.Acquire("192.0.2.1")
	if err != nil {
		t.Fatalf("a3: %v", err)
	}
	if _, err := ct.Acquire("192.0.2.1"); err != nil {
		t.Fatalf("a4: %v", err)
	}
	if _, err := ct.Acquire("198.51.100.7"); err != nil {
		t.Fatalf("b1: %v", err)
	}

	// The reaped connections finally close.
	a1.Release()
	a2.Release()
	a1.Release() // and a double release is still a no-op

	if got := ct.GetCountForIP("192.0.2.1"); got != 2 {
		t.Errorf("per-IP count = %d, want 2 (a3 and a4 are still open)", got)
	}
	if total, _, _ := ct.GetStats(); total != 3 {
		t.Errorf("total = %d, want 3 (a3, a4, b1 are still open)", total)
	}
	if _, err := ct.Acquire("192.0.2.1"); err == nil {
		t.Error("the per-IP limit of 2 must still hold")
	}

	a3.Release()
	if got := ct.GetCountForIP("192.0.2.1"); got != 1 {
		t.Errorf("per-IP count after releasing a3 = %d, want 1", got)
	}
}

// Releasing a reaped lease must not touch the global count when its address
// holds no slot any more - the release used to decrement the total
// unconditionally, charging it to an unrelated connection.
func TestAudit_ReleaseOfReapedLeaseWithoutSlotIsNoOp(t *testing.T) {
	ct := NewConnectionTracker(100, 2, 20*time.Millisecond, nil)

	a, err := ct.Acquire("192.0.2.1")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	if reaped := ct.reapExpired(); reaped != 1 {
		t.Fatalf("reaped = %d, want 1", reaped)
	}

	if _, err := ct.Acquire("198.51.100.7"); err != nil {
		t.Fatalf("acquire b: %v", err)
	}
	a.Release() // the reaped connection closes

	if total, _, _ := ct.GetStats(); total != 1 {
		t.Errorf("total = %d, want 1 (198.51.100.7 is still open)", total)
	}
	if got := ct.GetCountForIP("198.51.100.7"); got != 1 {
		t.Errorf("count for the live address = %d, want 1", got)
	}
	if got := ct.GetCountForIP("192.0.2.1"); got != 0 {
		t.Errorf("count for the reaped address = %d, want 0", got)
	}
}

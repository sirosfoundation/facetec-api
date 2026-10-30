package session

import (
	"testing"
	"time"
)

// TestPutTakeOffer_HappyPath verifies the basic offer round-trip.
func TestPutTakeOffer_HappyPath(t *testing.T) {
	m := New(5*time.Minute, 15*time.Minute)

	creds := []string{"cred1", "cred2"}
	id, err := m.PutOffer(creds, "photo-id")
	if err != nil {
		t.Fatalf("PutOffer: %v", err)
	}

	e, err := m.TakeOffer(id)
	if err != nil {
		t.Fatalf("TakeOffer: %v", err)
	}
	if len(e.Credentials) != 2 {
		t.Errorf("Credentials len: got %d, want 2", len(e.Credentials))
	}
	if e.Scope != "photo-id" {
		t.Errorf("Scope: got %q, want %q", e.Scope, "photo-id")
	}
}

// TestTakeOffer_OneTimeUse verifies that an offer entry is deleted on first read.
func TestTakeOffer_OneTimeUse(t *testing.T) {
	m := New(5*time.Minute, 15*time.Minute)

	id, err := m.PutOffer([]string{"cred"}, "scope")
	if err != nil {
		t.Fatalf("PutOffer: %v", err)
	}

	if _, err := m.TakeOffer(id); err != nil {
		t.Fatalf("first TakeOffer: %v", err)
	}
	if _, err := m.TakeOffer(id); err == nil {
		t.Fatal("second TakeOffer should fail, but succeeded")
	}
}

// TestTakeOffer_Unknown verifies that querying a non-existent offer ID returns an error.
func TestTakeOffer_Unknown(t *testing.T) {
	m := New(5*time.Minute, 15*time.Minute)

	if _, err := m.TakeOffer("no-such-id"); err == nil {
		t.Fatal("expected error for unknown ID, got nil")
	}
}

// TestTakeOffer_Expired verifies that offers with a past expiry are rejected.
func TestTakeOffer_Expired(t *testing.T) {
	m := New(-1*time.Millisecond, 15*time.Minute)

	id, err := m.PutOffer([]string{"c"}, "s")
	if err != nil {
		t.Fatalf("PutOffer: %v", err)
	}

	if _, err := m.TakeOffer(id); err == nil {
		t.Fatal("expected error for expired offer, got nil")
	}
}

// TestIDsAreUnique verifies that successive calls to PutOffer yield different IDs.
func TestIDsAreUnique(t *testing.T) {
	m := New(5*time.Minute, 15*time.Minute)
	defer m.Close()

	id1, _ := m.PutOffer([]string{"a"}, "s")
	id2, _ := m.PutOffer([]string{"b"}, "s")

	if id1 == id2 {
		t.Errorf("expected unique IDs, got %q == %q", id1, id2)
	}
}

// TestClose_NoEntries verifies that Close succeeds when there are no live entries.
func TestClose_NoEntries(t *testing.T) {
	m := New(5*time.Minute, 15*time.Minute)
	// Just ensure it doesn't panic or deadlock.
	done := make(chan struct{})
	go func() {
		m.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked for more than 1 second")
	}
}

func TestLivenessProof_ProvenIsTakenOnce(t *testing.T) {
	m := New(5*time.Minute, 15*time.Minute)
	defer m.Close()

	m.RecordLivenessProof("tenant\x00ref-1", true)

	if !m.TakeLivenessProof("tenant\x00ref-1") {
		t.Fatal("a recorded, proven session must report true")
	}
	if m.TakeLivenessProof("tenant\x00ref-1") {
		t.Fatal("a liveness proof must be one-time use")
	}
}

func TestLivenessProof_UnknownOrUnprovenIsFalse(t *testing.T) {
	m := New(5*time.Minute, 15*time.Minute)
	defer m.Close()

	if m.TakeLivenessProof("never-recorded") {
		t.Fatal("an unknown session must report false")
	}
	m.RecordLivenessProof("failed", false)
	if m.TakeLivenessProof("failed") {
		t.Fatal("a session whose liveness was not proven must report false")
	}
}

func TestLivenessProof_LatestVerdictWins(t *testing.T) {
	m := New(5*time.Minute, 15*time.Minute)
	defer m.Close()

	// A retried liveness step: first not proven, then proven.
	m.RecordLivenessProof("retried", false)
	m.RecordLivenessProof("retried", true)
	if !m.TakeLivenessProof("retried") {
		t.Fatal("a retry that proved liveness must count")
	}

	m.RecordLivenessProof("regressed", true)
	m.RecordLivenessProof("regressed", false)
	if m.TakeLivenessProof("regressed") {
		t.Fatal("a later unproven verdict must override an earlier proven one")
	}
}

func TestLivenessProof_Expired(t *testing.T) {
	m := New(5*time.Minute, -1*time.Millisecond) // negative TTL → already expired
	defer m.Close()

	m.RecordLivenessProof("stale", true)
	if m.TakeLivenessProof("stale") {
		t.Fatal("an expired liveness proof must report false")
	}
}

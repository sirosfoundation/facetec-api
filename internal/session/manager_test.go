package session

import (
	"testing"
	"time"
)

// TestPutTakeLiveness_HappyPath verifies the basic round-trip.
func TestPutTakeLiveness_HappyPath(t *testing.T) {
	m := New(2*time.Minute, 5*time.Minute)

	id, err := m.PutLiveness([]byte("fakemap"), 0.95)
	if err != nil {
		t.Fatalf("PutLiveness: %v", err)
	}
	if id == "" {
		t.Fatal("PutLiveness returned empty ID")
	}

	e, err := m.TakeLiveness(id)
	if err != nil {
		t.Fatalf("TakeLiveness: %v", err)
	}
	if string(e.FaceMap) != "fakemap" {
		t.Errorf("FaceMap: got %q, want %q", string(e.FaceMap), "fakemap")
	}
	if e.LivenessScore != 0.95 {
		t.Errorf("LivenessScore: got %v, want 0.95", e.LivenessScore)
	}
}

// TestTakeLiveness_OneTimeUse verifies that a liveness entry is deleted on first read.
func TestTakeLiveness_OneTimeUse(t *testing.T) {
	m := New(2*time.Minute, 5*time.Minute)

	id, err := m.PutLiveness([]byte("fm"), 1.0)
	if err != nil {
		t.Fatalf("PutLiveness: %v", err)
	}

	if _, err := m.TakeLiveness(id); err != nil {
		t.Fatalf("first TakeLiveness: %v", err)
	}
	if _, err := m.TakeLiveness(id); err == nil {
		t.Fatal("second TakeLiveness should fail, but succeeded")
	}
}

// TestTakeLiveness_Unknown verifies that querying a non-existent ID returns an error.
func TestTakeLiveness_Unknown(t *testing.T) {
	m := New(2*time.Minute, 5*time.Minute)

	if _, err := m.TakeLiveness("no-such-id"); err == nil {
		t.Fatal("expected error for unknown ID, got nil")
	}
}

// TestTakeLiveness_Expired verifies that entries with a past expiry are rejected.
func TestTakeLiveness_Expired(t *testing.T) {
	m := New(-1*time.Millisecond, 5*time.Minute) // negative TTL → already expired

	id, err := m.PutLiveness([]byte("fm"), 0.5)
	if err != nil {
		t.Fatalf("PutLiveness: %v", err)
	}

	if _, err := m.TakeLiveness(id); err == nil {
		t.Fatal("expected error for expired entry, got nil")
	}
}

// TestPutTakeOffer_HappyPath verifies the basic offer round-trip.
func TestPutTakeOffer_HappyPath(t *testing.T) {
	m := New(2*time.Minute, 5*time.Minute)

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
	m := New(2*time.Minute, 5*time.Minute)

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
	m := New(2*time.Minute, 5*time.Minute)

	if _, err := m.TakeOffer("no-such-id"); err == nil {
		t.Fatal("expected error for unknown ID, got nil")
	}
}

// TestTakeOffer_Expired verifies that offers with a past expiry are rejected.
func TestTakeOffer_Expired(t *testing.T) {
	m := New(2*time.Minute, -1*time.Millisecond)

	id, err := m.PutOffer([]string{"c"}, "s")
	if err != nil {
		t.Fatalf("PutOffer: %v", err)
	}

	if _, err := m.TakeOffer(id); err == nil {
		t.Fatal("expected error for expired offer, got nil")
	}
}

// TestIDsAreUnique verifies that successive calls to PutLiveness yield different IDs.
func TestIDsAreUnique(t *testing.T) {
	m := New(5*time.Minute, 5*time.Minute)

	id1, _ := m.PutLiveness([]byte("a"), 1.0)
	id2, _ := m.PutLiveness([]byte("b"), 1.0)

	if id1 == id2 {
		t.Errorf("expected unique IDs, got %q == %q", id1, id2)
	}
}

// TestClose_ZeroesBiometrics verifies that Close stops the reaper and zeroes
// any in-memory FaceMap bytes before returning.
func TestClose_ZeroesBiometrics(t *testing.T) {
	m := New(2*time.Minute, 5*time.Minute)

	// Store an entry with easily recognisable non-zero bytes.
	data := []byte{1, 2, 3, 4, 5}
	id, err := m.PutLiveness(data, 0.9)
	if err != nil {
		t.Fatalf("PutLiveness: %v", err)
	}

	// Capture a reference to the entry *before* Close so we can inspect the
	// FaceMap backing array after the reaper goroutine runs.
	m.mu.Lock()
	e := m.liveness[id]
	m.mu.Unlock()

	// Close signals the reaper via the done channel.
	m.Close()

	// Give the goroutine time to reach and execute the case <-m.done branch.
	time.Sleep(50 * time.Millisecond)

	// clear(e.FaceMap) zeroes the underlying bytes; the slice header is preserved.
	for i, b := range e.FaceMap {
		if b != 0 {
			t.Errorf("FaceMap[%d] = %d after Close, want 0", i, b)
		}
	}
}

// TestClose_NoEntries verifies that Close succeeds when there are no live entries.
func TestClose_NoEntries(t *testing.T) {
	m := New(2*time.Minute, 5*time.Minute)
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

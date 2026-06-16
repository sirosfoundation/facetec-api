package review

import (
	"testing"
	"time"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
)

func testScanResult() facetec.ScanResult {
	return facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{
			Success:       true,
			LivenessScore: 0.72,
		},
		IDScan: facetec.IDScanResult{
			Success:        true,
			FaceMatchLevel: 5,
			DocumentData: facetec.DocumentData{
				GivenName:      "Jesse",
				FamilyName:     "Test",
				DateOfBirth:    "1990-01-15",
				Nationality:    "NL",
				DocumentNumber: "AB1234567",
				DocumentType:   "passport",
			},
			MRZVerified: true,
		},
	}
}

func TestSubmitAndPending(t *testing.T) {
	q := NewQueue(5 * time.Minute)
	defer q.Close()

	q.Submit("sess-001", "tenant-a", testScanResult())

	pending := q.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	if pending[0].SessionID != "sess-001" {
		t.Errorf("session_id = %q, want sess-001", pending[0].SessionID)
	}
	if pending[0].LivenessScore != 0.72 {
		t.Errorf("liveness = %f, want 0.72", pending[0].LivenessScore)
	}
}

func TestGetEvidence(t *testing.T) {
	q := NewQueue(5 * time.Minute)
	defer q.Close()

	q.Submit("sess-002", "tenant-a", testScanResult())

	ev, err := q.GetEvidence("sess-002")
	if err != nil {
		t.Fatal(err)
	}
	if ev.GivenName != "Jesse" {
		t.Errorf("given_name = %q, want Jesse", ev.GivenName)
	}
	if ev.DocumentNumber != "AB1234567" {
		t.Errorf("doc_number = %q, want AB1234567", ev.DocumentNumber)
	}
}

func TestDecide(t *testing.T) {
	q := NewQueue(5 * time.Minute)
	defer q.Close()

	q.Submit("sess-003", "tenant-a", testScanResult())

	entry, err := q.Decide("sess-003", DecisionAccept, "operator@example.com", "Document matches applicant")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Decision != DecisionAccept {
		t.Errorf("decision = %q, want accept", entry.Decision)
	}
	if entry.DecidedBy != "operator@example.com" {
		t.Errorf("decided_by = %q", entry.DecidedBy)
	}

	// Should not appear in pending anymore
	pending := q.Pending()
	if len(pending) != 0 {
		t.Errorf("pending = %d after decision, want 0", len(pending))
	}
}

func TestDecide_AlreadyDecided(t *testing.T) {
	q := NewQueue(5 * time.Minute)
	defer q.Close()

	q.Submit("sess-004", "tenant-a", testScanResult())
	_, _ = q.Decide("sess-004", DecisionReject, "op", "test")
	_, err := q.Decide("sess-004", DecisionAccept, "op2", "re-decide")
	if err == nil {
		t.Error("expected error for double decision")
	}
}

func TestDecide_Expired(t *testing.T) {
	q := NewQueue(1 * time.Millisecond)
	defer q.Close()

	q.Submit("sess-005", "tenant-a", testScanResult())
	time.Sleep(5 * time.Millisecond)

	_, err := q.Decide("sess-005", DecisionAccept, "op", "late")
	if err == nil {
		t.Error("expected error for expired session")
	}
}

func TestGetEvidence_NotFound(t *testing.T) {
	q := NewQueue(5 * time.Minute)
	defer q.Close()

	_, err := q.GetEvidence("nonexistent")
	if err == nil {
		t.Error("expected error for missing session")
	}
}

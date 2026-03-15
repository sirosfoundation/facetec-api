package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
)

// writeRule writes a SPOCP rule file to dir and returns the dir path.
// Rules are written in SPOCP advanced format: one rule per line, no quotes.
func writeRules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.spoc")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeRules: %v", err)
	}
	return dir
}

// TestNew_EmptyDir verifies that an engine with no rules rejects every scan.
func TestNew_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	e, err := New(dir, 80, 6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", e.RuleCount())
	}
	// Every scan must be rejected when there are no rules (numeric thresholds aside).
	if err := e.EvaluateScan(facetec.ScanResult{}); err == nil {
		t.Fatal("expected rejection with no rules, got nil error")
	}
}

// TestNew_NoDir verifies that an empty rules dir ("") starts with no rules.
func TestNew_NoDir(t *testing.T) {
	e, err := New("", 80, 6)
	if err != nil {
		t.Fatalf("New with empty dir: %v", err)
	}
	if e.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", e.RuleCount())
	}
}

// TestNew_NonExistentDir verifies that a missing rules directory returns an error.
func TestNew_NonExistentDir(t *testing.T) {
	if _, err := New("/no/such/directory", 80, 6); err == nil {
		t.Fatal("expected error for non-existent rules dir, got nil")
	}
}

// TestEvaluateScan_Accept verifies that a scan passing numeric thresholds and
// matching a categorical SPOCP rule is accepted.
func TestEvaluateScan_Accept(t *testing.T) {
	dir := writeRules(t,
		"(facetec-scan (doc-type passport) (mrz-verified true))\n",
	)
	e, err := New(dir, 80, 6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 1.0}, // score=100 >= 80
		IDScan: facetec.IDScanResult{
			FaceMatchLevel: 10,                                       // 10 >= 6
			DocumentData:   facetec.DocumentData{DocumentType: "passport"},
			MRZVerified:    true,
		},
	}
	if err := e.EvaluateScan(result); err != nil {
		t.Errorf("expected acceptance, got: %v", err)
	}
}

// TestEvaluateScan_Reject_LowLiveness verifies rejection when liveness score is below threshold.
func TestEvaluateScan_Reject_LowLiveness(t *testing.T) {
	dir := writeRules(t,
		"(facetec-scan (doc-type passport) (mrz-verified true))\n",
	)
	e, err := New(dir, 80, 6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// LivenessScore 0.5 → score=50 < minLivenessScore=80 → rejected at threshold stage.
	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 0.5},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel: 10,
			DocumentData:   facetec.DocumentData{DocumentType: "passport"},
			MRZVerified:    true,
		},
	}
	if err := e.EvaluateScan(result); err == nil {
		t.Error("expected rejection for low liveness score, got nil error")
	}
}

// TestEvaluateScan_Reject_NoRule verifies rejection when the SPOCP rule set has no match.
func TestEvaluateScan_Reject_NoRule(t *testing.T) {
	dir := writeRules(t,
		"(facetec-scan (doc-type passport) (mrz-verified true))\n",
	)
	e, err := New(dir, 80, 6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Driving licence scanned but only passport rule exists → SPOCP rejects.
	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 1.0},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel:  10,
			DocumentData:    facetec.DocumentData{DocumentType: "dl"},
			BarcodeVerified: true,
		},
	}
	if err := e.EvaluateScan(result); err == nil {
		t.Error("expected SPOCP rejection for dl with passport-only rule, got nil error")
	}
}

// TestEvaluateScan_MultipleRules verifies that a scan matching one of several rules is accepted.
func TestEvaluateScan_MultipleRules(t *testing.T) {
	dir := writeRules(t, `
(facetec-scan (doc-type passport) (mrz-verified true))
(facetec-scan (doc-type dl) (mrz-verified false) (nfc-verified false) (barcode-verified true))
`)
	e, err := New(dir, 80, 6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", e.RuleCount())
	}

	// Driver's licence scan should match the second rule.
	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 1.0},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel:  10,
			DocumentData:    facetec.DocumentData{DocumentType: "dl"},
			BarcodeVerified: true,
		},
	}
	if err := e.EvaluateScan(result); err != nil {
		t.Errorf("expected acceptance for dl scan, got: %v", err)
	}
}

// TestBuildQueryElement_DocTypeFallback verifies the "unknown" fallback for empty DocumentType.
// Thresholds are set to 0 so the test focuses on SPOCP matching only.
func TestBuildQueryElement_DocTypeFallback(t *testing.T) {
	dir := writeRules(t,
		"(facetec-scan (doc-type unknown))\n",
	)
	e, err := New(dir, 0, 0) // thresholds=0 so ScanResult{} passes numeric check
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := facetec.ScanResult{} // DocumentType is empty → "unknown"
	if err := e.EvaluateScan(result); err != nil {
		t.Errorf("expected acceptance for unknown doc type, got: %v", err)
	}
}




package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
)

// passportRule is a well-formed rule encoding the standard thresholds for passports.
const passportRule = "(facetec-scan (liveness-score (* range numeric ge 080)) (face-match-level (* range numeric ge 06)) (doc-type passport) (mrz-verified true))\n"

// writeRules writes a SPOCP rule file to a temp dir and returns the dir path.
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
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", e.RuleCount())
	}
	if err := e.EvaluateScan(facetec.ScanResult{}); err == nil {
		t.Fatal("expected rejection with no rules, got nil error")
	}
}

// TestNew_NoDir verifies that an empty rules dir ("") starts with no rules.
func TestNew_NoDir(t *testing.T) {
	e, err := New("")
	if err != nil {
		t.Fatalf("New with empty dir: %v", err)
	}
	if e.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", e.RuleCount())
	}
}

// TestNew_NonExistentDir verifies that a missing rules directory returns an error.
func TestNew_NonExistentDir(t *testing.T) {
	if _, err := New("/no/such/directory"); err == nil {
		t.Fatal("expected error for non-existent rules dir, got nil")
	}
}

// TestEvaluateScan_Accept verifies that a scan passing range thresholds and
// matching the categorical part of a rule is accepted.
func TestEvaluateScan_Accept(t *testing.T) {
	dir := writeRules(t, passportRule)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 1.0}, // 100 >= 080
		IDScan: facetec.IDScanResult{
			FaceMatchLevel: 10, // 10 >= 06
			DocumentData:   facetec.DocumentData{DocumentType: "passport"},
			MRZVerified:    true,
		},
	}
	if err := e.EvaluateScan(result); err != nil {
		t.Errorf("expected acceptance, got: %v", err)
	}
}

// TestEvaluateScan_Reject_LowLiveness verifies that a scan with liveness score
// below the range predicate threshold is rejected.
func TestEvaluateScan_Reject_LowLiveness(t *testing.T) {
	dir := writeRules(t, passportRule)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// LivenessScore 0.5 → formatted as "050" < "080" → rejected by range rule.
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

// TestEvaluateScan_Reject_LowFaceMatch verifies that a scan with face match
// level below the range predicate threshold is rejected.
func TestEvaluateScan_Reject_LowFaceMatch(t *testing.T) {
	dir := writeRules(t, passportRule)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// FaceMatchLevel 3 → formatted as "03" < "06" → rejected by range rule.
	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 1.0},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel: 3,
			DocumentData:   facetec.DocumentData{DocumentType: "passport"},
			MRZVerified:    true,
		},
	}
	if err := e.EvaluateScan(result); err == nil {
		t.Error("expected rejection for low face match level, got nil error")
	}
}

// TestEvaluateScan_Reject_NoRule verifies rejection when no rule matches the
// categorical fields (document type).
func TestEvaluateScan_Reject_NoRule(t *testing.T) {
	// Only passport rule — driving licence scan must be rejected.
	dir := writeRules(t, passportRule)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

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

// TestEvaluateScan_MultipleRules verifies that a scan matching one of several
// rules is accepted.
func TestEvaluateScan_MultipleRules(t *testing.T) {
	rules := passportRule +
		"(facetec-scan (liveness-score (* range numeric ge 080)) (face-match-level (* range numeric ge 06)) (doc-type dl) (mrz-verified false) (nfc-verified false) (barcode-verified true))\n"
	dir := writeRules(t, rules)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", e.RuleCount())
	}

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

// TestBuildQueryElement_DocTypeFallback verifies the "unknown" fallback for empty
// DocumentType. Uses a rule that accepts any liveness/face-match and doc-type unknown.
func TestBuildQueryElement_DocTypeFallback(t *testing.T) {
	// Range ge 000 accepts all scores; ge 00 accepts all face-match levels.
	dir := writeRules(t,
		"(facetec-scan (liveness-score (* range numeric ge 000)) (face-match-level (* range numeric ge 00)) (doc-type unknown))\n",
	)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := facetec.ScanResult{} // DocumentType empty → "unknown"
	if err := e.EvaluateScan(result); err != nil {
		t.Errorf("expected acceptance for unknown doc type, got: %v", err)
	}
}

// TestEvaluateScan_BoundaryLiveness_ExactThreshold verifies that a score exactly
// at the threshold is accepted (>= semantics).
func TestEvaluateScan_BoundaryLiveness_ExactThreshold(t *testing.T) {
	dir := writeRules(t, passportRule)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// LivenessScore 0.8 → formatted as "080" == "080" → meets ge threshold.
	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 0.8},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel: 6,
			DocumentData:   facetec.DocumentData{DocumentType: "passport"},
			MRZVerified:    true,
		},
	}
	if err := e.EvaluateScan(result); err != nil {
		t.Errorf("expected acceptance at exact threshold, got: %v", err)
	}
}

// scan builds a scan; chipTrusted is the PDP-backed passive authentication
// result, nfc is FaceTec's own chip authentication (status 4).
func scan(docType string, mrz, nfc, barcode, chipTrusted bool) facetec.ScanResult {
	return facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 0.95},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel:  8,
			DocumentData:    facetec.DocumentData{DocumentType: docType},
			MRZVerified:     mrz,
			NFCVerified:     nfc,
			BarcodeVerified: barcode,
			ChipTrusted:     chipTrusted,
		},
	}
}

// TestDefaultRules_AcceptRequireAuthenticatedChip loads the shipped
// rules/default.spoc: no document is accepted without an authenticated NFC
// chip (#65), and passports additionally need a PDP-trusted chip, so
// passports need BOTH nfc-verified and chip-trusted while ID cards and
// driving licences need nfc-verified only.
func TestDefaultRules_AcceptRequireAuthenticatedChip(t *testing.T) {
	e, err := New(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	accepted := map[string]facetec.ScanResult{
		"passport with MRZ, chip authenticated and trusted": scan("passport", true, true, false, true),
		"passport, barcode also verified":                   scan("passport", true, true, true, true),
		"ID card with chip":                                 scan("id_card", true, true, false, false),
		"ID card with chip, MRZ not verified":               scan("id_card", false, true, false, false),
		"ID card with chip, trusted too":                    scan("id_card", true, true, false, true),
		"driving licence with chip":                         scan("dl", false, true, false, false),
	}
	for name, r := range accepted {
		if err := e.EvaluateScan(r); err != nil {
			t.Errorf("%s: want accepted, got %v", name, err)
		}
	}

	rejected := map[string]facetec.ScanResult{
		"passport authenticated but chip not trusted":   scan("passport", true, true, false, false),
		"passport trusted but chip not authenticated":   scan("passport", true, false, false, true),
		"passport without chip":                         scan("passport", true, false, false, false),
		"passport with both, MRZ not verified":          scan("passport", false, true, false, true),
		"ID card without chip":                          scan("id_card", true, false, false, false),
		"ID card trusted but not authenticated":         scan("id_card", true, false, false, true),
		"driving licence with barcode, no chip":         scan("dl", false, false, true, false),
		"driving licence trusted but not authenticated": scan("dl", false, false, false, true),
		"unknown document with chip":                    scan("", true, true, true, true),
	}
	for name, r := range rejected {
		if err := e.EvaluateScan(r); err == nil {
			t.Errorf("%s: want rejected, got accepted", name)
		}
	}
}

// TestDefaultRules_ReviewMirrorsAcceptRules queries the shipped
// facetec-scan-review rules directly (EvaluateScan only asks the accept
// head): a borderline scan -- below the accept thresholds, within review's --
// is escalated under exactly the same chip conditions as acceptance.
func TestDefaultRules_ReviewMirrorsAcceptRules(t *testing.T) {
	e, err := New(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	borderline := func(docType string, mrz, nfc, barcode, trusted bool) facetec.ScanResult {
		r := scan(docType, mrz, nfc, barcode, trusted)
		r.Liveness.LivenessScore = 0.70
		r.IDScan.FaceMatchLevel = 5
		return r
	}
	review := func(r facetec.ScanResult) bool {
		return e.engine.QueryElement(buildQuery(reviewHead, r))
	}

	if err := e.EvaluateScan(borderline("passport", true, true, false, true)); err == nil {
		t.Fatal("a borderline scan must not pass the accept rules, or this test proves nothing")
	}

	escalated := map[string]facetec.ScanResult{
		"passport with MRZ, chip authenticated and trusted": borderline("passport", true, true, false, true),
		"ID card with chip":         borderline("id_card", false, true, false, false),
		"driving licence with chip": borderline("dl", false, true, false, false),
	}
	for name, r := range escalated {
		if !review(r) {
			t.Errorf("%s: want escalated for review", name)
		}
	}

	notEscalated := map[string]facetec.ScanResult{
		"passport authenticated but not trusted": borderline("passport", true, true, false, false),
		"passport trusted but not authenticated": borderline("passport", true, false, false, true),
		"passport without chip":                  borderline("passport", true, false, false, false),
		"ID card without chip":                   borderline("id_card", true, false, false, false),
		"driving licence with barcode, no chip":  borderline("dl", false, false, true, false),
	}
	for name, r := range notEscalated {
		if review(r) {
			t.Errorf("%s: want not escalated", name)
		}
	}
}

func TestBuildQuery_ChipTrustedIsLastField(t *testing.T) {
	dir := writeRules(t, "(facetec-scan (liveness-score (* range numeric ge 000)) (face-match-level (* range numeric ge 00)) (doc-type passport) (mrz-verified false) (nfc-verified false) (barcode-verified false) (chip-trusted false))\n")
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.EvaluateScan(scan("passport", true, true, false, false)); err == nil {
		t.Error("mrz/nfc true must NOT match the all-false rule")
	}
	s := scan("passport", false, false, false, false)
	if err := e.EvaluateScan(s); err != nil {
		t.Errorf("all-false scan should match: %v", err)
	}
	s.IDScan.ChipTrusted = true
	if err := e.EvaluateScan(s); err == nil {
		t.Error("chip-trusted true must not match a chip-trusted false rule")
	}
}

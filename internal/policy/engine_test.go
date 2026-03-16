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

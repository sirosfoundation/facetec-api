package facetec

import (
	"testing"
)

// faceTecDocumentDataJSON is a realistic FaceTec Server v10 documentData JSON
// string as it appears inside idScanResultsSoFar.
const faceTecDocumentDataJSON = `{
  "mrzValues": {
    "groups": [{
      "fields": [
        {"fieldKey": "firstName", "value": "ANNA"},
        {"fieldKey": "lastName", "value": "SVENSSON"},
        {"fieldKey": "idNumber", "value": "P1234567"},
        {"fieldKey": "dateOfBirth", "uiFieldType": "dd MMM/MMM yyyy", "value": "15 JAN/JAN 1990"},
        {"fieldKey": "dateOfExpiration", "uiFieldType": "dd MMM/MMM yyyy", "value": "20 MAY/MAY 2030"},
        {"fieldKey": "nationality", "value": "SWE"},
        {"fieldKey": "sex", "value": "F"},
        {"fieldKey": "countryCode", "value": "SWE"},
        {"fieldKey": "mrzLine1", "value": "P<SWESVENSSON<<ANNA<<<<<<<<<<<<<<<<<<<<<<<<<<<"},
        {"fieldKey": "mrzLine2", "value": "P12345670SWE9001155F3005201<<<<<<<<<<<<<<02"}
      ]
    }]
  },
  "scannedValues": {
    "groups": [{
      "fields": [
        {"fieldKey": "firstName", "value": "ANNA"},
        {"fieldKey": "lastName", "value": "SVENSSON"}
      ]
    }]
  },
  "templateInfo": {
    "templateType": "Passport",
    "documentCountry": "Sweden"
  }
}`

// realPayload returns a payload shaped like a real, successful FaceTec Server
// v10 /process-request response captured from a live device scan.
//
// Notably, top-level "success" is false here — matching the real captured
// payload — because FaceTec does not use it to signal a completed photo-ID
// match. The only reliable completion signal is
// idScanResultsSoFar.photoIDNextStepEnumInt == 4 (COMPLETE). NFC and barcode
// default to "not verified" (0) here; individual tests flip them to their
// passing values (4 and 3 respectively).
func realPayload() map[string]any {
	return map[string]any{
		"success": false,
		"idScanResultsSoFar": map[string]any{
			"matchLevel":                        float64(7),
			"mrzStatusEnumInt":                  float64(2),
			"nfcAuthenticationStatusEnumInt":    float64(0),
			"barcodeStatusEnumInt":              float64(0),
			"faceOnDocumentStatusEnumInt":       float64(1),
			"fullIDStatusEnumInt":               float64(0),
			"photoIDNextStepEnumInt":            float64(4),
			"nfcStatusEnumInt":                  float64(6),
			"watermarkAndHologramStatusEnumInt": float64(0),
			"documentData":                      faceTecDocumentDataJSON,
		},
		"serverInfo": map[string]any{
			"facetecServerWebserviceVersion": "10.0.48",
		},
		"didError": false,
	}
}

func TestExtractScanResult_RealPayload(t *testing.T) {
	result, ok, err := ExtractScanResult(realPayload())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true for a complete scan (photoIDNextStepEnumInt=4), regardless of top-level success")
	}
	if result.IDScan.FaceMatchLevel != 7 {
		t.Errorf("FaceMatchLevel: got %d, want 7", result.IDScan.FaceMatchLevel)
	}
	if result.IDScan.DocumentData.GivenName != "ANNA" {
		t.Errorf("GivenName: got %q, want ANNA", result.IDScan.DocumentData.GivenName)
	}
	if result.IDScan.DocumentData.FamilyName != "SVENSSON" {
		t.Errorf("FamilyName: got %q, want SVENSSON", result.IDScan.DocumentData.FamilyName)
	}
	if result.IDScan.DocumentData.DocumentNumber != "P1234567" {
		t.Errorf("DocumentNumber: got %q, want P1234567", result.IDScan.DocumentData.DocumentNumber)
	}
	if result.IDScan.DocumentData.DateOfBirth != "1990-01-15" {
		t.Errorf("DateOfBirth: got %q, want 1990-01-15", result.IDScan.DocumentData.DateOfBirth)
	}
	if result.IDScan.DocumentData.DateOfExpiry != "2030-05-20" {
		t.Errorf("DateOfExpiry: got %q, want 2030-05-20", result.IDScan.DocumentData.DateOfExpiry)
	}
	if result.IDScan.DocumentData.DocumentType != "passport" {
		t.Errorf("DocumentType: got %q, want passport", result.IDScan.DocumentData.DocumentType)
	}
	if result.IDScan.DocumentData.Nationality != "SWE" {
		t.Errorf("Nationality: got %q, want SWE", result.IDScan.DocumentData.Nationality)
	}
	if result.IDScan.DocumentData.Sex != "F" {
		t.Errorf("Sex: got %q, want F", result.IDScan.DocumentData.Sex)
	}
	if result.IDScan.DocumentData.IssuingCountry != "SWE" {
		t.Errorf("IssuingCountry: got %q, want SWE", result.IDScan.DocumentData.IssuingCountry)
	}
	if !result.IDScan.MRZVerified {
		t.Error("MRZVerified: want true (mrzStatusEnumInt=2)")
	}
	if result.IDScan.NFCVerified {
		t.Error("NFCVerified: want false (nfcAuthenticationStatusEnumInt=0)")
	}
	if result.IDScan.BarcodeVerified {
		t.Error("BarcodeVerified: want false (barcodeStatusEnumInt=0)")
	}
	if !result.Liveness.Success || result.Liveness.LivenessScore != 1.0 {
		t.Errorf("Liveness: got success=%v score=%v, want true/1.0",
			result.Liveness.Success, result.Liveness.LivenessScore)
	}
}

func TestExtractScanResult_NFC_Passed(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	results["nfcAuthenticationStatusEnumInt"] = float64(4)
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if !result.IDScan.NFCVerified {
		t.Error("NFCVerified: want true (nfcAuthenticationStatusEnumInt=4, AUTHENTICATED)")
	}
}

func TestExtractScanResult_Barcode_Passed(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	results["barcodeStatusEnumInt"] = float64(3)
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if !result.IDScan.BarcodeVerified {
		t.Error("BarcodeVerified: want true (barcodeStatusEnumInt=3, SUCCESS)")
	}
}

// TestExtractScanResult_TopLevelSuccessDoesNotGate proves that a fully
// complete, successful scan is still recognized even when the top-level
// "success" field is true — i.e. that field is simply ignored either way,
// only photoIDNextStepEnumInt matters.
func TestExtractScanResult_TopLevelSuccessDoesNotGate(t *testing.T) {
	p := realPayload()
	p["success"] = true
	_, ok, err := ExtractScanResult(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true regardless of top-level success value")
	}
}

// TestExtractScanResult_NoTopLevelSuccessKey proves the absence of a
// top-level "success" key entirely doesn't affect the result — it's not
// consulted at all.
func TestExtractScanResult_NoTopLevelSuccessKey(t *testing.T) {
	p := realPayload()
	delete(p, "success")
	_, ok, err := ExtractScanResult(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true when success key is missing entirely")
	}
}

// TestExtractScanResult_NotCompleteYet verifies that any photoIDNextStepEnumInt
// value other than COMPLETE (4) — e.g. 3 = USER_CONFIRM — is treated as "not
// ready to evaluate yet", not as a failure.
func TestExtractScanResult_NotCompleteYet(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	results["photoIDNextStepEnumInt"] = float64(3) // USER_CONFIRM
	_, ok, err := ExtractScanResult(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when photoIDNextStepEnumInt != COMPLETE")
	}
}

func TestExtractScanResult_NoNextStepField(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	delete(results, "photoIDNextStepEnumInt")
	_, ok, err := ExtractScanResult(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when photoIDNextStepEnumInt is missing")
	}
}

func TestExtractScanResult_NoIDScanResults(t *testing.T) {
	p := realPayload()
	delete(p, "idScanResultsSoFar")
	_, ok, err := ExtractScanResult(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when idScanResultsSoFar missing")
	}
}

func TestExtractScanResult_NoDocumentData(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	delete(results, "documentData")
	_, ok, err := ExtractScanResult(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when documentData missing")
	}
}

func TestExtractScanResult_DocumentDataAsString(t *testing.T) {
	p := realPayload()
	// Replace with a different person in grouped-fields JSON string format.
	results := p["idScanResultsSoFar"].(map[string]any)
	results["documentData"] = `{
		"mrzValues": {"groups": [{"fields": [
			{"fieldKey": "firstName", "value": "ERIK"},
			{"fieldKey": "lastName", "value": "LARSSON"}
		]}]},
		"templateInfo": {"templateType": "Driver's License"}
	}`
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if result.IDScan.DocumentData.GivenName != "ERIK" {
		t.Errorf("GivenName: got %q, want ERIK", result.IDScan.DocumentData.GivenName)
	}
	if result.IDScan.DocumentData.DocumentType != "dl" {
		t.Errorf("DocumentType: got %q, want dl", result.IDScan.DocumentData.DocumentType)
	}
}

func TestExtractScanResult_DocumentDataAsMap(t *testing.T) {
	p := realPayload()
	// Replace the string with an already-decoded map (grouped-fields format).
	results := p["idScanResultsSoFar"].(map[string]any)
	results["documentData"] = map[string]any{
		"mrzValues": map[string]any{
			"groups": []any{
				map[string]any{
					"fields": []any{
						map[string]any{"fieldKey": "firstName", "value": "KARIN"},
						map[string]any{"fieldKey": "lastName", "value": "BERG"},
					},
				},
			},
		},
		"templateInfo": map[string]any{"templateType": "ID Card"},
	}
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if result.IDScan.DocumentData.GivenName != "KARIN" {
		t.Errorf("GivenName: got %q, want KARIN", result.IDScan.DocumentData.GivenName)
	}
	if result.IDScan.DocumentData.DocumentType != "id_card" {
		t.Errorf("DocumentType: got %q, want id_card", result.IDScan.DocumentData.DocumentType)
	}
}

func TestExtractScanResult_FlatDocumentDataBackwardCompat(t *testing.T) {
	// Verify that flat DocumentData maps still work for backward compatibility.
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	results["documentData"] = map[string]any{
		"givenName":      "TEST",
		"familyName":     "USER",
		"documentType":   "passport",
		"documentNumber": "X999",
	}
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if result.IDScan.DocumentData.GivenName != "TEST" {
		t.Errorf("GivenName: got %q, want TEST", result.IDScan.DocumentData.GivenName)
	}
	if result.IDScan.DocumentData.DocumentNumber != "X999" {
		t.Errorf("DocumentNumber: got %q, want X999", result.IDScan.DocumentData.DocumentNumber)
	}
}

func TestNormalizeFaceTecDate(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"1990-01-15", "1990-01-15"},
		{"18 FEB/FEB 1987", "1987-02-18"},
		{"15 JAN/JAN 1990", "1990-01-15"},
		{"20 MAY/MAY 2030", "2030-05-20"},
		{"01 DEC 2025", "2025-12-01"},
	}
	for _, tt := range tests {
		got := normalizeFaceTecDate(tt.input)
		if got != tt.want {
			t.Errorf("normalizeFaceTecDate(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractScanResult_PortraitFromIDScanResults(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	results["photoIDFaceCrop"] = "base64portrait"
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if result.IDScan.DocumentData.Portrait != "base64portrait" {
		t.Errorf("Portrait: got %q, want base64portrait", result.IDScan.DocumentData.Portrait)
	}
}

func TestExtractScanResult_PortraitFallsBackToTopLevel(t *testing.T) {
	p := realPayload()
	// Not present in idScanResultsSoFar — only at the top level.
	p["photoIDFaceCrop"] = "toplevelportrait"
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if result.IDScan.DocumentData.Portrait != "toplevelportrait" {
		t.Errorf("Portrait: got %q, want toplevelportrait", result.IDScan.DocumentData.Portrait)
	}
}

func TestExtractScanResult_PortraitIDScanResultsTakesPrecedence(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	results["photoIDFaceCrop"] = "primary"
	p["photoIDFaceCrop"] = "fallback"
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if result.IDScan.DocumentData.Portrait != "primary" {
		t.Errorf("Portrait: got %q, want primary", result.IDScan.DocumentData.Portrait)
	}
}

func TestExtractScanResult_PortraitAbsent(t *testing.T) {
	result, ok, err := ExtractScanResult(realPayload())
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if result.IDScan.DocumentData.Portrait != "" {
		t.Errorf("Portrait: got %q, want empty", result.IDScan.DocumentData.Portrait)
	}
}

func TestExtractScanResult_NoMatchLevel(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	delete(results, "matchLevel")
	_, ok, err := ExtractScanResult(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when matchLevel missing")
	}
}

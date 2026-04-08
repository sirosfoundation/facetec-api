package facetec

import (
	"testing"
)

// realPayload returns a payload shaped like a real FaceTec Server v10
// /process-request response (successful photo-ID match).
func realPayload() map[string]any {
	return map[string]any{
		"success": true,
		"idScanResultsSoFar": map[string]any{
			"matchLevel":                        float64(7),
			"mrzStatusEnumInt":                  float64(2),
			"nfcAuthenticationStatusEnumInt":    float64(0),
			"barcodeStatusEnumInt":              float64(0),
			"faceOnDocumentStatusEnumInt":       float64(1),
			"fullIDStatusEnumInt":               float64(0),
			"photoIDNextStepEnumInt":            float64(5),
			"nfcStatusEnumInt":                  float64(6),
			"watermarkAndHologramStatusEnumInt": float64(0),
		},
		"documentData": map[string]any{
			"givenName":      "ANNA",
			"familyName":     "SVENSSON",
			"documentNumber": "P1234567",
			"dateOfBirth":    "1990-01-15",
			"dateOfExpiry":   "2030-05-20",
			"nationality":    "SWE",
			"sex":            "F",
			"issuingCountry": "SWE",
			"documentType":   "passport",
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
		t.Fatal("expected ok=true for a successful scan")
	}
	if result.IDScan.FaceMatchLevel != 7 {
		t.Errorf("FaceMatchLevel: got %d, want 7", result.IDScan.FaceMatchLevel)
	}
	if result.IDScan.DocumentData.GivenName != "ANNA" {
		t.Errorf("GivenName: got %q, want ANNA", result.IDScan.DocumentData.GivenName)
	}
	if result.IDScan.DocumentData.DocumentType != "passport" {
		t.Errorf("DocumentType: got %q, want passport", result.IDScan.DocumentData.DocumentType)
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
	results["nfcAuthenticationStatusEnumInt"] = float64(1)
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if !result.IDScan.NFCVerified {
		t.Error("NFCVerified: want true (nfcAuthenticationStatusEnumInt=1)")
	}
}

func TestExtractScanResult_Barcode_Passed(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	results["barcodeStatusEnumInt"] = float64(2)
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if !result.IDScan.BarcodeVerified {
		t.Error("BarcodeVerified: want true (barcodeStatusEnumInt=2)")
	}
}

func TestExtractScanResult_NotSuccess(t *testing.T) {
	p := realPayload()
	p["success"] = false
	_, ok, err := ExtractScanResult(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when success=false")
	}
}

func TestExtractScanResult_NoSuccess(t *testing.T) {
	p := realPayload()
	delete(p, "success")
	_, ok, err := ExtractScanResult(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when success key missing")
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
	delete(p, "documentData")
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
	p["documentData"] = `{"givenName":"ERIK","familyName":"LARSSON","documentType":"dl"}`
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

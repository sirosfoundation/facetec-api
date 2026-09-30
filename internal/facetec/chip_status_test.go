package facetec

import (
	"testing"
)

func TestChipAuthStatusFailed(t *testing.T) {
	for status, want := range map[int]bool{0: false, 1: false, 2: false, 3: true, 4: false, 5: true} {
		if got := ChipAuthStatusFailed(status); got != want {
			t.Errorf("ChipAuthStatusFailed(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestExtractScanResult_ChipAuthStatus(t *testing.T) {
	for _, status := range []float64{0, 1, 2, 3, 4, 5} {
		p := realPayload()
		p["idScanResultsSoFar"].(map[string]any)["nfcAuthenticationStatusEnumInt"] = status
		result, ok, err := ExtractScanResult(p)
		if err != nil || !ok {
			t.Fatalf("status %v: err=%v ok=%v", status, err, ok)
		}
		if result.IDScan.ChipAuthStatus != int(status) {
			t.Errorf("ChipAuthStatus = %d, want %d", result.IDScan.ChipAuthStatus, int(status))
		}
		if result.IDScan.NFCVerified != (status == 4) {
			t.Errorf("status %v: NFCVerified = %v (nfc-verified semantics must be unchanged)", status, result.IDScan.NFCVerified)
		}
		if result.IDScan.ChipTrusted {
			t.Error("ExtractScanResult must never set ChipTrusted")
		}
	}
}

// A wrongly typed status enum must fail closed (error), not read as 0.
func TestExtractScanResult_StatusEnumWrongType_IsFatal(t *testing.T) {
	for _, key := range []string{"nfcAuthenticationStatusEnumInt", "mrzStatusEnumInt", "barcodeStatusEnumInt"} {
		for name, bad := range map[string]any{"string": "FAILED", "bool": true, "float": 3.5, "object": map[string]any{}} {
			p := realPayload()
			p["idScanResultsSoFar"].(map[string]any)[key] = bad
			_, ok, err := ExtractScanResult(p)
			if err == nil || ok {
				t.Errorf("%s=%s: want error and ok=false, got err=%v ok=%v", key, name, err, ok)
			}
		}
	}
}

func TestExtractScanResult_StatusEnumAbsent_NotFatal(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	delete(results, "nfcAuthenticationStatusEnumInt")
	delete(results, "mrzStatusEnumInt")
	delete(results, "barcodeStatusEnumInt")
	if _, ok, err := ExtractScanResult(p); err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
}

func TestExtractNFCRawData(t *testing.T) {
	dd := map[string]any{"nfcValues": map[string]any{"rawData": map[string]any{
		"SOD": "c29k", "DG1": "ZGcx", "DG2": "", "junk": 7.0,
	}}}
	want := map[string]string{"SOD": "c29k", "DG1": "ZGcx"}
	got := extractNFCRawData(dd)
	if len(got) != len(want) || got["SOD"] != "c29k" || got["DG1"] != "ZGcx" {
		t.Errorf("map form: got %v, want %v", got, want)
	}
	got = extractNFCRawData(`{"nfcValues":{"rawData":{"SOD":"c29k"}}}`)
	if got["SOD"] != "c29k" {
		t.Errorf("string form: got %v", got)
	}
	for name, v := range map[string]any{
		"nil": nil, "bad json": "{", "wrong type": 5, "no nfc": map[string]any{},
		"no raw": map[string]any{"nfcValues": map[string]any{}},
	} {
		if got := extractNFCRawData(v); got != nil {
			t.Errorf("%s: got %v, want nil", name, got)
		}
	}
}

func TestExtractScanResult_ChipRawPopulated(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	results["documentData"] = map[string]any{
		"mrzValues": map[string]any{},
		"nfcValues": map[string]any{"rawData": map[string]any{"SOD": "c29k"}},
	}
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if result.IDScan.ChipRaw["SOD"] != "c29k" {
		t.Errorf("ChipRaw = %v", result.IDScan.ChipRaw)
	}
}

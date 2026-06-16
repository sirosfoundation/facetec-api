package quality

import "testing"

func TestCheck_Pass(t *testing.T) {
	a := Assessment{AuditTrailCount: 3, IDScanImageCount: 2}
	if rej := Check(a); rej != nil {
		t.Errorf("expected pass, got rejection: %v", rej)
	}
}

func TestCheck_NoAuditTrail(t *testing.T) {
	a := Assessment{AuditTrailCount: 0, IDScanImageCount: 2}
	rej := Check(a)
	if rej == nil {
		t.Fatal("expected rejection for no audit trail")
	}
	if rej.Reason != "insufficient_audit_trail" {
		t.Errorf("reason = %q", rej.Reason)
	}
}

func TestCheck_NoIDImages(t *testing.T) {
	a := Assessment{AuditTrailCount: 2, IDScanImageCount: 0}
	rej := Check(a)
	if rej == nil {
		t.Fatal("expected rejection for no ID images")
	}
	if rej.Reason != "insufficient_id_images" {
		t.Errorf("reason = %q", rej.Reason)
	}
}

func TestCheck_UnknownCountsPass(t *testing.T) {
	// Missing quality metadata should not cause rejection
	a := Assessment{AuditTrailCount: UnknownCount, IDScanImageCount: UnknownCount}
	if rej := Check(a); rej != nil {
		t.Errorf("expected pass for unknown counts, got rejection: %v", rej)
	}
}

func TestExtractFromPayload(t *testing.T) {
	payload := map[string]any{
		"auditTrailCompressedBase64":        []any{"img1", "img2", "img3"},
		"idScanFrontImagesCompressedBase64": []any{"front1"},
		"idScanBackImagesCompressedBase64":  []any{"back1"},
		"idScanResultsSoFar": map[string]any{
			"sessionDurationMs": float64(4200),
		},
	}
	a := ExtractFromPayload(payload)
	if a.AuditTrailCount != 3 {
		t.Errorf("audit_trail = %d, want 3", a.AuditTrailCount)
	}
	if a.IDScanImageCount != 2 {
		t.Errorf("id_images = %d, want 2", a.IDScanImageCount)
	}
	if a.SessionDurationMS != 4200 {
		t.Errorf("duration = %d, want 4200", a.SessionDurationMS)
	}
}

func TestExtractFromPayload_MissingFields(t *testing.T) {
	// A minimal payload without quality arrays should yield UnknownCount
	a := ExtractFromPayload(map[string]any{"success": true})
	if a.AuditTrailCount != UnknownCount {
		t.Errorf("audit_trail = %d, want %d (UnknownCount)", a.AuditTrailCount, UnknownCount)
	}
	if a.IDScanImageCount != UnknownCount {
		t.Errorf("id_images = %d, want %d (UnknownCount)", a.IDScanImageCount, UnknownCount)
	}
}

func TestSPOCPAtom(t *testing.T) {
	tests := []struct {
		a    Assessment
		want string
	}{
		{Assessment{AuditTrailCount: 3, IDScanImageCount: 3}, "high"},
		{Assessment{AuditTrailCount: 1, IDScanImageCount: 3}, "medium"},
		{Assessment{AuditTrailCount: 1, IDScanImageCount: 1}, "low"},
		// Unknown counts should not count as issues
		{Assessment{AuditTrailCount: UnknownCount, IDScanImageCount: UnknownCount}, "high"},
		{Assessment{AuditTrailCount: UnknownCount, IDScanImageCount: 1}, "medium"},
	}
	for _, tt := range tests {
		got := SPOCPAtom(tt.a)
		if got != tt.want {
			t.Errorf("SPOCPAtom(%+v) = %q, want %q", tt.a, got, tt.want)
		}
	}
}

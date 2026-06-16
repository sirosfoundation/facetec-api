// Package quality provides server-side capture quality verification.
//
// After a successful FaceTec response, quality checks are applied to ensure
// the biometric capture meets minimum standards. Quality fields can also be
// exposed as SPOCP query elements for policy-driven threshold enforcement.
package quality

import (
	"fmt"
)

// Assessment holds the quality indicators extracted from a FaceTec response.
type Assessment struct {
	// AuditTrailCount is the number of audit trail images captured.
	AuditTrailCount int
	// IDScanImageCount is the number of ID scan front/back images.
	IDScanImageCount int
	// SessionDurationMS is the server-reported session time if available.
	SessionDurationMS int
}

// Rejection describes why a quality check failed.
type Rejection struct {
	Reason string
	Detail string
}

func (r Rejection) Error() string {
	return fmt.Sprintf("quality: %s — %s", r.Reason, r.Detail)
}

// Check evaluates an Assessment against minimum thresholds.
// Returns nil if quality is acceptable, or a Rejection describing the failure.
func Check(a Assessment) *Rejection {
	if a.AuditTrailCount < 1 {
		return &Rejection{
			Reason: "insufficient_audit_trail",
			Detail: fmt.Sprintf("got %d audit trail images, need at least 1", a.AuditTrailCount),
		}
	}
	if a.IDScanImageCount < 1 {
		return &Rejection{
			Reason: "insufficient_id_images",
			Detail: fmt.Sprintf("got %d ID scan images, need at least 1", a.IDScanImageCount),
		}
	}
	return nil
}

// ExtractFromPayload attempts to derive quality indicators from the raw
// FaceTec v10 process-request response payload.
func ExtractFromPayload(payload map[string]any) Assessment {
	a := Assessment{}

	// Count audit trail images if present
	if trail, ok := payload["auditTrailCompressedBase64"].([]any); ok {
		a.AuditTrailCount = len(trail)
	}

	// Count ID scan images
	idCount := 0
	if front, ok := payload["idScanFrontImagesCompressedBase64"].([]any); ok {
		idCount += len(front)
	}
	if back, ok := payload["idScanBackImagesCompressedBase64"].([]any); ok {
		idCount += len(back)
	}
	a.IDScanImageCount = idCount

	// Session duration if available
	if results, ok := payload["idScanResultsSoFar"].(map[string]any); ok {
		if dur, ok := results["sessionDurationMs"].(float64); ok {
			a.SessionDurationMS = int(dur)
		}
	}

	return a
}

// SPOCPAtom returns the quality level as a SPOCP atom for policy evaluation.
// Returns "high", "medium", or "low" based on the assessment.
func SPOCPAtom(a Assessment) string {
	issues := 0
	if a.AuditTrailCount < 2 {
		issues++
	}
	if a.IDScanImageCount < 2 {
		issues++
	}
	switch issues {
	case 0:
		return "high"
	case 1:
		return "medium"
	default:
		return "low"
	}
}

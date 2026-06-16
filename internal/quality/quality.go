// Package quality provides server-side capture quality verification.
//
// After a successful FaceTec response, quality checks are applied to ensure
// the biometric capture meets minimum standards. Quality fields can also be
// exposed as SPOCP query elements for policy-driven threshold enforcement.
package quality

import (
	"fmt"
)

// UnknownCount signals that the quality indicator was absent from the payload.
const UnknownCount = -1

// Assessment holds the quality indicators extracted from a FaceTec response.
// A count of UnknownCount (-1) means the field was not present in the payload.
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
// Fields with UnknownCount are skipped (graceful degradation when metadata is absent).
func Check(a Assessment) *Rejection {
	if a.AuditTrailCount != UnknownCount && a.AuditTrailCount < 1 {
		return &Rejection{
			Reason: "insufficient_audit_trail",
			Detail: fmt.Sprintf("got %d audit trail images, need at least 1", a.AuditTrailCount),
		}
	}
	if a.IDScanImageCount != UnknownCount && a.IDScanImageCount < 1 {
		return &Rejection{
			Reason: "insufficient_id_images",
			Detail: fmt.Sprintf("got %d ID scan images, need at least 1", a.IDScanImageCount),
		}
	}
	return nil
}

// ExtractFromPayload attempts to derive quality indicators from the raw
// FaceTec v10 process-request response payload.
// Fields absent from the payload are set to UnknownCount.
func ExtractFromPayload(payload map[string]any) Assessment {
	a := Assessment{
		AuditTrailCount:  UnknownCount,
		IDScanImageCount: UnknownCount,
	}

	// Count audit trail images if present
	if trail, ok := payload["auditTrailCompressedBase64"].([]any); ok {
		a.AuditTrailCount = len(trail)
	}

	// Count ID scan images — only set if at least one array is present
	frontPresent := false
	backPresent := false
	idCount := 0
	if front, ok := payload["idScanFrontImagesCompressedBase64"].([]any); ok {
		frontPresent = true
		idCount += len(front)
	}
	if back, ok := payload["idScanBackImagesCompressedBase64"].([]any); ok {
		backPresent = true
		idCount += len(back)
	}
	if frontPresent || backPresent {
		a.IDScanImageCount = idCount
	}

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
// Unknown/missing fields are ignored (not counted as issues).
func SPOCPAtom(a Assessment) string {
	issues := 0
	if a.AuditTrailCount != UnknownCount && a.AuditTrailCount < 2 {
		issues++
	}
	if a.IDScanImageCount != UnknownCount && a.IDScanImageCount < 2 {
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

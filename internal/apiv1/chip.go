package apiv1

import (
	"context"

	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/emrtd"
	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/idverrors"
)

// newChipChecker builds the eMRTD checker from cfg.Trust. An empty pdp_url
// yields a checker without a PDP: chips are verified locally but can never be
// reported as trusted.
func newChipChecker(cfg config.TrustConfig) *emrtd.Checker {
	var pdp emrtd.TrustEvaluator
	if cfg.PDPURL != "" {
		pdp = emrtd.NewPDPClient(cfg.PDPURL, cfg.Timeout)
	}
	return emrtd.NewChecker(pdp, cfg.Required)
}

// assessChip performs eMRTD passive authentication on the scan's chip data and
// records the outcome in scan.IDScan (ChipTrusted, ChipTrustReason and the
// certificate fingerprints). It returns a non-nil *idverrors.Error when the
// scan must be rejected regardless of the SPOCP policy:
//
//   - FaceTec reported a failed chip authentication (status 3 or 5), or
//   - trust.required is set and chip data was presented but is not trusted.
//
// Status 1 (NOT_SUPPORTED_BY_DOCUMENT: no AA/CA on the chip) is permitted: it
// is a weaker clone-detection signal and is surfaced in the audit log through
// ChipAuthStatus, not a rejection.
func (c *Client) assessChip(ctx context.Context, scan *facetec.ScanResult) *idverrors.Error {
	id := &scan.IDScan
	if facetec.ChipAuthStatusFailed(id.ChipAuthStatus) {
		id.ChipTrusted = false
		id.ChipTrustReason = "facetec_chip_auth_failed"
		return idverrors.New(idverrors.CodeChipAuthFailed, "chip authentication failed")
	}

	dd := id.DocumentData
	out := c.chip.Check(ctx, id.ChipRaw, emrtd.Claimed{
		GivenName:      dd.GivenName,
		FamilyName:     dd.FamilyName,
		DocumentNumber: dd.DocumentNumber,
		DateOfBirth:    dd.DateOfBirth,
		DateOfExpiry:   dd.DateOfExpiry,
		Nationality:    dd.Nationality,
		IssuingCountry: dd.IssuingCountry,
	})
	id.ChipTrusted = out.Trusted
	id.ChipTrustReason = out.Reason
	id.ChipDSCSHA256 = out.Local.DSCFingerprint()
	id.ChipCSCASHA256 = out.Decision.CSCASHA256

	if c.chip.Required() && out.ChipPresented && !out.Trusted {
		return idverrors.Newf(idverrors.CodeChipUntrusted, "eMRTD chip is not trusted (%s)", out.Reason)
	}
	return nil
}

// chipAuditFields are the structured log fields recording how the chip was
// judged, for the AUDIT credential_issued record.
func chipAuditFields(id facetec.IDScanResult) []zap.Field {
	return []zap.Field{
		zap.Bool("chip_trusted", id.ChipTrusted),
		zap.String("chip_trust_reason", id.ChipTrustReason),
		zap.Int("chip_auth_status", id.ChipAuthStatus),
		zap.String("chip_dsc_sha256", id.ChipDSCSHA256),
		zap.String("chip_csca_sha256", id.ChipCSCASHA256),
	}
}

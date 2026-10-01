package apiv1

import (
	"context"
	"slices"

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
// certificate fingerprints). It runs only after the NFC gate (nfcRejection)
// has established that FaceTec authenticated the chip (status 4: clone
// detection via AA/CA and FaceTec's own signature verification), so a chip-less
// scan or any other status is refused before trust is even consulted. It
// returns a non-nil *idverrors.Error when trust.required is set and the chip
// evidence (raw chip data or FaceTec NFC verification) is not trusted. Whether
// an untrusted chip is otherwise acceptable is left to the SPOCP policy
// (chip-trusted).
func (c *Client) assessChip(ctx context.Context, scan *facetec.ScanResult) *idverrors.Error {
	id := &scan.IDScan
	dd := id.DocumentData
	out := c.chip.Check(ctx, id.ChipRaw, emrtd.Claimed{
		GivenName:      dd.GivenName,
		FamilyName:     dd.FamilyName,
		DocumentNumber: dd.DocumentNumber,
		DateOfBirth:    dd.DateOfBirth,
		DateOfExpiry:   dd.DateOfExpiry,
		Nationality:    dd.Nationality,
		IssuingCountry: dd.IssuingCountry,
		Sex:            dd.Sex,
		DocumentType:   dd.DocumentType,
	})
	id.ChipTrusted = out.Trusted
	id.ChipTrustReason = out.Reason
	id.ChipDSCSHA256 = out.Local.DSCFingerprint()
	id.ChipCSCASHA256 = out.Decision.CSCASHA256

	// Any sign of a chip read counts as presented, so an incomplete payload
	// (status reported but SOD missing, stray raw fields) cannot dodge the gate.
	presented := out.ChipPresented || id.ChipAuthStatus != 0 || len(id.ChipRaw) > 0 || id.NFCVerified
	if out.Trusted {
		bindPortraitToChip(id, out.Local.DataGroups)
	}
	if c.chip.Required() && presented && !out.Trusted {
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

// bindPortraitToChip makes sure a chip-trusted scan only carries a portrait
// the SOD vouches for. When DG2's hash was verified, the DG2 face image
// replaces whatever FaceTec supplied (e.g. photoIDFaceCrop); when it was not,
// the portrait is dropped rather than issued under a chip-trusted credential.
func bindPortraitToChip(id *facetec.IDScanResult, verifiedDGs []int) {
	if slices.Contains(verifiedDGs, 2) && id.ChipPortrait != "" {
		id.DocumentData.Portrait = id.ChipPortrait
		return
	}
	id.DocumentData.Portrait = ""
}

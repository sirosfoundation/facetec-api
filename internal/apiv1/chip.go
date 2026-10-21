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
	// Once the SOD signature and the data-group hashes are verified, the
	// identity the chip signed replaces FaceTec's OCR of the MRZ (#83): an OCR
	// misread, e.g. a '<' filler read as a letter, must not reach the
	// credential. This does not depend on the PDP's trust decision: data the
	// chip signed is never worse than OCR of the page printed next to it.
	if local := out.Local; local != nil && local.Identity != nil {
		applyChipIdentity(&id.DocumentData, local.Identity)
		bindPortraitToChip(id, local.DataGroups)
		id.ChipIdentityApplied = true
		if len(local.Mismatches) > 0 && c.log != nil {
			c.log.Info("chip identity differs from OCR; issuing from the chip",
				zap.Strings("fields", local.Mismatches),
				zap.String("doc_type", dd.DocumentType),
			)
		}
	}
	id.ChipTrusted = out.Trusted
	id.ChipTrustReason = out.Reason
	id.ChipDSCSHA256 = out.Local.DSCFingerprint()
	id.ChipCSCASHA256 = out.Decision.CSCASHA256

	// Any sign of a chip read counts as presented, so an incomplete payload
	// (status reported but SOD missing, stray raw fields) cannot dodge the gate.
	presented := out.ChipPresented || id.ChipAuthStatus != 0 || len(id.ChipRaw) > 0 || id.NFCVerified
	// trust.required is enforced for passports (and for scans that reported no
	// document type at all, which fail closed) only: the PDP's eMRTD registry
	// covers ICAO 9303 travel documents, and other documents' chips (e.g. an
	// ISO 18013 driving licence) are governed by the NFC gate and policy
	// (nfc-verified), not by this check.
	// A signed document code that contradicts the reported type is refused
	// outright: the reported type picks the policy rule, so it must not be
	// usable to step outside the passport trust scope below.
	if out.Reason == emrtd.ReasonDocTypeMismatch {
		return idverrors.New(idverrors.CodeChipUntrusted, "eMRTD chip contradicts the reported document type")
	}
	if c.chip.Required() && (id.DocumentData.DocumentType == "passport" || id.DocumentData.DocumentType == "") && presented && !out.Trusted {
		return idverrors.Newf(idverrors.CodeChipUntrusted, "eMRTD chip is not trusted (%s)", out.Reason)
	}
	return nil
}

// chipAuditFields are the structured log fields recording how the chip was
// judged, for the AUDIT credential_issued record.
func chipAuditFields(id facetec.IDScanResult) []zap.Field {
	chipFaceMatchLevel := -1 // not reported
	if id.ChipFaceMatchLevel != nil {
		chipFaceMatchLevel = *id.ChipFaceMatchLevel
	}
	return []zap.Field{
		zap.Int("chip_face_match_level", chipFaceMatchLevel),
		zap.Bool("chip_trusted", id.ChipTrusted),
		zap.String("chip_trust_reason", id.ChipTrustReason),
		zap.Int("chip_auth_status", id.ChipAuthStatus),
		zap.Bool("chip_identity_applied", id.ChipIdentityApplied),
		zap.String("chip_dsc_sha256", id.ChipDSCSHA256),
		zap.String("chip_csca_sha256", id.ChipCSCASHA256),
	}
}

// bindPortraitToChip makes sure a scan issued with the chip's identity only
// carries a portrait the SOD vouches for, whether or not the PDP trusts the
// signer: the portrait follows the same source as the name and dates. When
// DG2's hash was verified, the DG2 face image replaces whatever FaceTec
// supplied (e.g. photoIDFaceCrop, cropped from the camera image of the
// document); when it was not, the portrait is dropped rather than issued
// next to the chip's identity.
func bindPortraitToChip(id *facetec.IDScanResult, verifiedDGs []int) {
	if slices.Contains(verifiedDGs, 2) && id.ChipPortrait != "" {
		id.DocumentData.Portrait = id.ChipPortrait
		return
	}
	id.DocumentData.Portrait = ""
}

// defaultMinChipFaceMatchLevel applies when no minimum is configured (0);
// config.Validate refuses anything outside 0–10.
const defaultMinChipFaceMatchLevel = 6

// maxChipFaceMatchLevel is the top of FaceTec's match level scale.
const maxChipFaceMatchLevel = 10

// chipFaceRejection refuses a scan whose face does not match the photo on the
// document's chip (FaceTec's matchLevelNFCToFaceMap). The chip gates prove
// the chip is genuine and the printed-photo match (matchLevel) proves the face
// matches the data page; only this ties the chip, and so the identity in the
// credential, to the person in front of the camera. Without it, a genuine
// document with a substituted printed photo passes every other check. A scan
// for which FaceTec reported no chip match, or a level outside FaceTec's 0–10
// scale, is refused too (fail closed): a malformed score is not read as an
// exceptionally good match.
func chipFaceRejection(id facetec.IDScanResult, minLevel int) (code idverrors.Code, msg string, rejected bool) {
	if minLevel < 1 {
		minLevel = defaultMinChipFaceMatchLevel
	}
	if id.ChipFaceMatchLevel == nil {
		return idverrors.CodeChipPhotoMismatch, "the face could not be compared with the photo on the document's chip", true
	}
	if level := *id.ChipFaceMatchLevel; level < 0 || level > maxChipFaceMatchLevel {
		return idverrors.CodeChipPhotoMismatch, "the face could not be compared with the photo on the document's chip", true
	}
	if *id.ChipFaceMatchLevel < minLevel {
		return idverrors.CodeChipPhotoMismatch, "the face does not match the photo on the document's chip", true
	}
	return "", "", false
}

// applyChipIdentity replaces the OCR'd identity fields with the chip's values.
// The chip is authoritative for every one of them, including the ones it
// leaves empty: a holder with a single name has no given name, an MRZ date of
// birth with unknown parts (e.g. "85<<<<") yields none, and an unspecified sex
// ('<') is unknown. An empty field is left out of the credential rather than
// filled from OCR, which is trivially falsifiable (#83, #85).
// Country codes are normalised to ISO 3166-1 alpha-3, so ICAO's "D" (Germany)
// becomes "DEU" and maps to an alpha-2 code in the credential; a code with no
// ISO 3166 equivalent stays as signed.
func applyChipIdentity(dd *facetec.DocumentData, chip *emrtd.Identity) {
	dd.FamilyName = chip.FamilyName
	dd.GivenName = chip.GivenName
	dd.DocumentNumber = chip.DocumentNumber
	dd.DateOfBirth = chip.DateOfBirth
	dd.DateOfExpiry = chip.DateOfExpiry
	dd.Sex = chip.Sex
	dd.Nationality = normalizedCountry(chip.Nationality)
	dd.IssuingCountry = normalizedCountry(chip.IssuingState)
}

func normalizedCountry(code string) string {
	if a3, err := emrtd.NormalizeCountry(code); err == nil {
		return a3
	}
	return code
}

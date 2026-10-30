// Package facetec contains types for the FaceTec Server REST API.
// ProcessRequestRequest carries the SDK's opaque request blob, which may hold
// raw biometric capture data; it must never be logged or persisted.
package facetec

// LivenessCheckResult is the liveness half of a scan result. On the
// process-request path the FaceTec Server reports only a verdict, so the score
// is the nominal 1.0 for a session whose liveness step passed.
type LivenessCheckResult struct {
	Success       bool    `json:"success"`
	LivenessScore float64 `json:"livenessScore"` // 0.0–1.0
}

// IDScanResult is the response from the FaceTec Server after a photo ID scan.
type IDScanResult struct {
	Success         bool         `json:"success"`
	FaceMatchLevel  int          `json:"faceMatchLevel"` // 0–10; 10 is highest confidence
	DocumentData    DocumentData `json:"documentData"`
	NFCVerified     bool         `json:"nfcVerified"`
	BarcodeVerified bool         `json:"barcodeVerified"`
	MRZVerified     bool         `json:"mrzVerified"`
	// NFCStatus is idScanResultsSoFar.nfcStatusEnumInt: why the chip was or
	// was not read (see the NFCStatus* constants). It only says whether a
	// read happened; NFCVerified says whether the chip was authenticated.
	// Only set by ExtractScanResult (the /process-request path). The legacy
	// /match-3d-3d response has no such field and never reads this one,
	// hence json:"-" rather than a zero value that would read as
	// NFCStatusNotSpecifiedByTemplate.
	NFCStatus int `json:"-"`

	// ChipAuthStatus is FaceTec's nfcAuthenticationStatusEnumInt: 0 N/A,
	// 1 NOT_SUPPORTED_BY_DOCUMENT (no AA/CA on the chip), 2 NOT_SUPPORTED_BY_SDK,
	// 3 FAILED, 4 AUTHENTICATED, 5 FAILED_DUE_TO_SIGNATURE_VERIFICATION. Only 4
	// (NFCVerified) is accepted; 3 and 5 are refused as nfc_not_authenticated.
	// Only set by ExtractScanResult.
	ChipAuthStatus int `json:"chipAuthStatus"`
	// ChipFaceMatchLevel is FaceTec's matchLevelNFCToFaceMap (0–10): how well
	// the live 3D FaceMap matches the photo on the document's chip (DG2).
	// FaceMatchLevel, by contrast, compares it with the photo printed on the
	// document. nil when FaceTec did not report it (e.g. before a chip read).
	ChipFaceMatchLevel *int `json:"matchLevelNFCToFaceMap,omitempty"`
	// ChipTrusted is true only when facetec-api itself verified the SOD and
	// data-group hashes AND the go-trust PDP trusts the DSC for the issuing
	// state. FaceTec's own checks never contribute to it. Set by the caller
	// (see apiv1), never by ExtractScanResult.
	ChipTrusted bool `json:"chipTrusted"`
	// ChipTrustReason is a machine-readable reason code ("ok" when trusted).
	ChipTrustReason string `json:"chipTrustReason,omitempty"`
	// ChipIdentityApplied is true when the identity fields of DocumentData
	// were replaced by the values signed on the chip (DG1, and DG11 when
	// present). Set by the caller (see apiv1), never by ExtractScanResult.
	ChipIdentityApplied bool `json:"chipIdentityApplied"`
	// ChipDSCSHA256 and ChipCSCASHA256 are hex fingerprints of the document
	// signer and anchor certificates, kept for the audit record.
	ChipDSCSHA256  string `json:"chipDscSha256,omitempty"`
	ChipCSCASHA256 string `json:"chipCscaSha256,omitempty"`
	// ChipRaw holds documentData.nfcValues.rawData (base64 "SOD", "DG1",
	// "DG2", ...) for passive authentication. It is never serialised and never
	// leaves this service.
	ChipRaw map[string]string `json:"-"`
	// ChipPortrait is the face image parsed from the chip's DG2 (base64),
	// before any FaceTec-supplied crop could replace DocumentData.Portrait.
	// It is what the SOD can vouch for once DG2's hash has been verified.
	ChipPortrait string `json:"-"`
}

// FaceTec Server v10 nfcStatusEnumInt values. USER_PRESSED_SKIP and SUCCESS
// were confirmed empirically against a live FaceTec Server response: a
// completed session where NFC was skipped reports nfcStatusEnumInt=2 and
// nfcAuthenticationStatusEnumInt=0, vs. 4 and 4 when the chip is read and
// authenticated.
const (
	// NFCStatusUnknown means the response carried no nfcStatusEnumInt.
	NFCStatusUnknown = -1
	// NFCStatusNotSpecifiedByTemplate: the document's template requests no
	// NFC read, so the user is never prompted for one.
	NFCStatusNotSpecifiedByTemplate = 0
	// NFCStatusDeviceNotCapable: the device cannot read NFC (possibly
	// because NFC is switched off), so the user is never prompted.
	NFCStatusDeviceNotCapable = 1
	// NFCStatusUserSkipped: the user was prompted and pressed skip.
	NFCStatusUserSkipped = 2
	// NFCStatusChipError: the read was attempted but the chip could not be
	// accessed.
	NFCStatusChipError = 3
	// NFCStatusSuccess: the chip was read. Whether it was also authenticated
	// is NFCVerified.
	NFCStatusSuccess = 4
)

// DocumentData contains the OCR-extracted identity fields from the scanned document.
// This is the only data from a scan that may leave the facetec-api security zone.
type DocumentData struct {
	GivenName      string `json:"givenName"`
	FamilyName     string `json:"familyName"`
	DocumentNumber string `json:"documentNumber"`
	DateOfBirth    string `json:"dateOfBirth"`  // YYYY-MM-DD
	DateOfExpiry   string `json:"dateOfExpiry"` // YYYY-MM-DD
	Nationality    string `json:"nationality"`
	Sex            string `json:"sex"`
	IssuingCountry string `json:"issuingCountry"`
	DocumentType   string `json:"documentType"` // passport | dl | id_card
	MRZLine1       string `json:"mrzLine1"`
	MRZLine2       string `json:"mrzLine2"`
	MRZLine3       string `json:"mrzLine3"`
	// Portrait is the base64-encoded face photo cropped from the ID document.
	// It is sourced exclusively from the FaceTec Server response and is never
	// taken from client input.
	Portrait string `json:"portrait,omitempty"`
}

// ScanResult combines an in-memory liveness result with a photo ID scan result.
// It is used exclusively for SPOCP policy evaluation and is never persisted.
type ScanResult struct {
	Liveness LivenessCheckResult
	IDScan   IDScanResult
}

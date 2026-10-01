// Package facetec contains types for the FaceTec Server REST API.
// All types in this package must be treated as sensitive when they contain
// FaceScan or FaceMap data. Neither field should ever be logged or persisted.
package facetec

// SessionTokenResponse is returned by the FaceTec Server /session-token endpoint.
type SessionTokenResponse struct {
	SessionToken string `json:"sessionToken"`
}

// LivenessCheckRequest wraps the biometric capture data sent by the FaceTec SDK
// during an active liveness check. FaceScan and AuditTrail fields contain raw
// biometric data and must not be persisted or logged.
type LivenessCheckRequest struct {
	SessionToken               string   `json:"sessionToken"`
	FaceScanBase64             string   `json:"faceScan"`
	AuditTrailBase64           []string `json:"auditTrail"`
	LowQualityAuditTrailBase64 []string `json:"lowQualityAuditTrail"`
}

// LivenessCheckResult is the response from the FaceTec Server after a liveness check.
// FaceMap is a derived biometric template used for subsequent face matching.
// It must not be persisted to disk and must be discarded immediately after use.
type LivenessCheckResult struct {
	Success          bool    `json:"success"`
	LivenessScore    float64 `json:"livenessScore"` // 0.0–1.0
	SessionTokenUsed string  `json:"sessionTokenUsed"`
	// FaceMap is the server-computed biometric template derived from the FaceScan.
	// Treat as highly sensitive biometric data.
	FaceMap string `json:"facemap"`
}

// IDScanRequest wraps the ID scan capture data and the previously obtained FaceMap.
// The FaceMap must be sourced from an in-memory liveness session, never from client input.
type IDScanRequest struct {
	SessionToken                      string   `json:"sessionToken"`
	IDScanBase64                      string   `json:"idScan"`
	IDScanFrontImagesCompressedBase64 []string `json:"idScanFrontImagesCompressedBase64"`
	IDScanBackImagesCompressedBase64  []string `json:"idScanBackImagesCompressedBase64"`
	// FaceMap is populated server-side from the liveness session. Never set from client input.
	FaceMap string `json:"facemap"`
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
	// ChipTrusted is true only when facetec-api itself verified the SOD and
	// data-group hashes AND the go-trust PDP trusts the DSC for the issuing
	// state. FaceTec's own checks never contribute to it. Set by the caller
	// (see apiv1), never by ExtractScanResult.
	ChipTrusted bool `json:"chipTrusted"`
	// ChipTrustReason is a machine-readable reason code ("ok" when trusted).
	ChipTrustReason string `json:"chipTrustReason,omitempty"`
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

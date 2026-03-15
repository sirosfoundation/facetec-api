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
}

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
}

// ScanResult combines an in-memory liveness result with a photo ID scan result.
// It is used exclusively for SPOCP policy evaluation and is never persisted.
type ScanResult struct {
	Liveness LivenessCheckResult
	IDScan   IDScanResult
}

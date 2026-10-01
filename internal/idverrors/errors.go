// Package idverrors defines machine-readable error codes for IDV provider SDK
// implementations. These codes map directly to the IDVError/IDVException types
// in siros-sdk-swift and siros-sdk-kotlin.
package idverrors

import "fmt"

// Code is a machine-readable error code returned in error responses.
type Code string

const (
	// CodeLivenessFailed indicates the liveness check did not pass.
	CodeLivenessFailed Code = "liveness_failed"
	// CodeMatchFailed indicates the face-match between selfie and document failed.
	CodeMatchFailed Code = "match_failed"
	// CodeDocumentUnreadable indicates the document could not be read or parsed.
	CodeDocumentUnreadable Code = "document_unreadable"
	// CodePolicyRejected indicates the scan passed technically but was rejected by policy.
	CodePolicyRejected Code = "policy_rejected"
	// CodeSessionExpired indicates the liveness session has expired or was already consumed.
	CodeSessionExpired Code = "session_expired"
	// CodeNFCSkipped indicates the user declined/skipped the NFC chip read
	// (FaceTec Server's nfcStatusEnumInt == NFC_REQUESTED_BUT_USER_PRESSED_SKIP),
	// so the assurance level required for issuance was not met.
	CodeNFCSkipped Code = "nfc_skipped"
	// CodeChipUntrusted indicates the eMRTD chip data could not be verified
	// against a trusted document signer and the deployment requires that
	// (trust.required).
	CodeChipUntrusted Code = "chip_untrusted"
	// CodeNFCNotRequested indicates FaceTec's template for the detected
	// document did not request an NFC read (nfcStatusEnumInt ==
	// NO_NFC_SPECIFIED_BY_TEMPLATE), so the user was never prompted. It does
	// not establish that the document has no chip -- only that FaceTec does
	// not read one for this document type.
	CodeNFCNotRequested Code = "nfc_not_requested"
	// CodeNFCDeviceNotCapable indicates the device could not read NFC
	// (nfcStatusEnumInt == NFC_REQUESTED_BUT_DEVICE_NOT_CAPABLE), e.g. no NFC
	// hardware or NFC switched off.
	CodeNFCDeviceNotCapable Code = "nfc_device_not_capable"
	// CodeNFCChipReadFailed indicates the chip read was attempted but failed
	// (nfcStatusEnumInt == NFC_REQUESTED_BUT_ERROR_ACCESSING_CHIP).
	CodeNFCChipReadFailed Code = "nfc_chip_read_failed"
	// CodeNFCNotAuthenticated indicates the chip was not authenticated
	// (nfcAuthenticationStatusEnumInt != AUTHENTICATED), including a chip that
	// was read but failed authentication.
	CodeNFCNotAuthenticated Code = "nfc_not_authenticated"
	// CodeIssuanceFailed indicates credential issuance failed after successful verification.
	CodeIssuanceFailed Code = "issuance_failed"
	// CodeInternalError indicates an unexpected internal error.
	CodeInternalError Code = "internal_error"
)

// Error is a structured IDV error with a machine-readable code.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// New creates a new IDV error.
func New(code Code, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

// Newf creates a new IDV error with a formatted message.
func Newf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

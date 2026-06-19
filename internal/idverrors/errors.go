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

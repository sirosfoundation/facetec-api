// Package evidence provides cryptographic session-to-credential binding.
//
// A random nonce is generated at IPV session start. After a successful policy
// decision, SHA-256(nonce || outcome) is computed and included both in the issued
// credential (as an "ipv_session_hash" claim) and in the audit record, creating
// a verifiable chain from IPV session → policy decision → credential.
package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Binding holds the cryptographic evidence for one IPV session.
type Binding struct {
	// Nonce is a 32-byte random value generated at session start.
	Nonce []byte
	// NonceHex is the hex-encoded nonce for inclusion in credential claims.
	NonceHex string
}

// NewBinding generates a fresh evidence binding with a cryptographically random nonce.
func NewBinding() (*Binding, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("evidence: generate nonce: %w", err)
	}
	return &Binding{
		Nonce:    nonce,
		NonceHex: hex.EncodeToString(nonce),
	}, nil
}

// ComputeHash returns SHA-256(nonce || outcome) as a hex string.
// This hash binds the IPV session nonce to a specific outcome and is included
// in both the credential claims and the audit record.
func (b *Binding) ComputeHash(outcome string) string {
	h := sha256.New()
	h.Write(b.Nonce)
	h.Write([]byte(outcome))
	return hex.EncodeToString(h.Sum(nil))
}

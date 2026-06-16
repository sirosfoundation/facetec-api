package evidence

import (
	"encoding/hex"
	"testing"
)

func TestNewBinding(t *testing.T) {
	b, err := NewBinding()
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Nonce) != 32 {
		t.Errorf("nonce length = %d, want 32", len(b.Nonce))
	}
	if len(b.NonceHex) != 64 {
		t.Errorf("nonce hex length = %d, want 64", len(b.NonceHex))
	}
	// Verify hex encoding is consistent
	decoded, err := hex.DecodeString(b.NonceHex)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(b.Nonce) {
		t.Error("nonce hex does not match nonce bytes")
	}
}

func TestComputeHash_Deterministic(t *testing.T) {
	b := &Binding{
		Nonce:    []byte("test-nonce-32-bytes-padding-here"),
		NonceHex: hex.EncodeToString([]byte("test-nonce-32-bytes-padding-here")),
	}
	h1 := b.ComputeHash("accept")
	h2 := b.ComputeHash("accept")
	if h1 != h2 {
		t.Error("same nonce+outcome should produce same hash")
	}
}

func TestComputeHash_DifferentOutcomes(t *testing.T) {
	b := &Binding{
		Nonce:    []byte("test-nonce-32-bytes-padding-here"),
		NonceHex: hex.EncodeToString([]byte("test-nonce-32-bytes-padding-here")),
	}
	h1 := b.ComputeHash("accept")
	h2 := b.ComputeHash("reject")
	if h1 == h2 {
		t.Error("different outcomes should produce different hashes")
	}
}

func TestNewBinding_Uniqueness(t *testing.T) {
	b1, err := NewBinding()
	if err != nil {
		t.Fatal("NewBinding() error:", err)
	}
	b2, err := NewBinding()
	if err != nil {
		t.Fatal("NewBinding() error:", err)
	}
	if b1.NonceHex == b2.NonceHex {
		t.Error("two bindings should have different nonces")
	}
}

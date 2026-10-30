// Package session provides in-memory, TTL-bounded stores used during the biometric flow.
//
// Neither store holds biometric data: FaceTec 10's process-request flow keeps every FaceScan
// and FaceMap inside the FaceTec Server, so nothing derived from a face is retained here.
//
// OfferStore holds signed credential tokens between issuance and wallet redemption. Entries
// expire after a configurable TTL (default 5 minutes) and are one-time-use.
//
// The liveness proof store holds FaceTec Server's livenessProven verdict for a FaceTec 10
// process-request session, between the session's liveness step and its final photo ID match
// result, which arrive in separate requests. Entries expire after a configurable TTL (default
// 15 minutes, a whole session: face scan, both sides of the document and the chip read) and are
// one-time-use. They hold a boolean, no biometric data.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// OfferEntry holds signed credential tokens for wallet redemption.
type OfferEntry struct {
	Credentials []string
	Scope       string
	ExpiresAt   time.Time
}

// livenessProof is FaceTec Server's liveness verdict for one process-request session.
type livenessProof struct {
	proven    bool
	expiresAt time.Time
}

// Manager holds the in-memory stores with automatic TTL eviction.
type Manager struct {
	mu       sync.Mutex
	offers   map[string]*OfferEntry
	proofs   map[string]*livenessProof
	offerTTL time.Duration
	proofTTL time.Duration
	done     chan struct{} // closed by Close() to stop the reaper goroutine
}

// New creates a Manager with the given TTLs.
// offerTTL is the lifetime of a credential offer after issuance.
// proofTTL is the lifetime of a process-request session's liveness verdict.
func New(offerTTL, proofTTL time.Duration) *Manager {
	m := &Manager{
		offers:   make(map[string]*OfferEntry),
		proofs:   make(map[string]*livenessProof),
		offerTTL: offerTTL,
		proofTTL: proofTTL,
		done:     make(chan struct{}),
	}
	go m.reap()
	return m
}

// Close stops the background eviction goroutine.
// Must be called once when the Manager is no longer needed.
func (m *Manager) Close() {
	close(m.done)
}

// PutOffer stores signed credentials for wallet redemption and returns a transaction ID.
func (m *Manager) PutOffer(credentials []string, scope string) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.offers[id] = &OfferEntry{
		Credentials: credentials,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(m.offerTTL),
	}
	m.mu.Unlock()
	return id, nil
}

// TakeOffer retrieves and atomically removes a credential offer (one-time use).
// Returns an error if the ID is unknown or the entry has expired.
func (m *Manager) TakeOffer(id string) (*OfferEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.offers[id]
	if !ok {
		return nil, fmt.Errorf("session: offer %q not found or expired", id)
	}
	delete(m.offers, id)
	if time.Now().After(e.ExpiresAt) {
		return nil, fmt.Errorf("session: offer %q expired", id)
	}
	return e, nil
}

// RecordLivenessProof stores FaceTec Server's livenessProven verdict for the
// process-request session identified by key. The latest verdict wins, so a
// liveness step the user retried and then passed counts as proven.
func (m *Manager) RecordLivenessProof(key string, proven bool) {
	m.mu.Lock()
	m.proofs[key] = &livenessProof{proven: proven, expiresAt: time.Now().Add(m.proofTTL)}
	m.mu.Unlock()
}

// TakeLivenessProof reports whether liveness was proven for the session
// identified by key, and removes the record (one-time use). An unknown,
// expired or unproven session reports false.
func (m *Manager) TakeLivenessProof(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.proofs[key]
	if !ok {
		return false
	}
	delete(m.proofs, key)
	return p.proven && !time.Now().After(p.expiresAt)
}

// reap periodically removes expired entries from the stores.
// It stops when Close() is called.
func (m *Manager) reap() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			m.mu.Lock()
			for id, e := range m.offers {
				if now.After(e.ExpiresAt) {
					delete(m.offers, id)
				}
			}
			for key, p := range m.proofs {
				if now.After(p.expiresAt) {
					delete(m.proofs, key)
				}
			}
			m.mu.Unlock()
		case <-m.done:
			return
		}
	}
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

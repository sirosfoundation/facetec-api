// Package review provides operator escalation for borderline IPV results.
//
// When policy evaluation produces a "review" outcome (rather than accept/reject),
// the scan result is stored in a time-bounded review queue. Operators can list
// pending reviews, view evidence (document data + scores, never biometric images),
// and submit accept/reject decisions with justification.
package review

import (
	"fmt"
	"sync"
	"time"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
)

// Decision represents an operator's review decision.
type Decision string

const (
	DecisionAccept Decision = "accept"
	DecisionReject Decision = "reject"
)

// Entry holds a scan result awaiting operator review.
type Entry struct {
	SessionID     string
	TenantID      string
	ScanResult    facetec.ScanResult
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Decision      Decision
	DecidedAt     time.Time
	DecidedBy     string
	Justification string
}

// Summary is the non-sensitive view of a pending review (for listing).
type Summary struct {
	SessionID      string    `json:"session_id"`
	TenantID       string    `json:"tenant_id"`
	DocumentType   string    `json:"document_type"`
	LivenessScore  float64   `json:"liveness_score"`
	FaceMatchLevel int       `json:"face_match_level"`
	MRZVerified    bool      `json:"mrz_verified"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// Evidence is the detailed view for operator decision-making.
// It includes document data and scores but NEVER biometric images or FaceMaps.
type Evidence struct {
	Summary
	GivenName       string `json:"given_name"`
	FamilyName      string `json:"family_name"`
	DateOfBirth     string `json:"date_of_birth"`
	Nationality     string `json:"nationality"`
	DocumentNumber  string `json:"document_number"`
	NFCVerified     bool   `json:"nfc_verified"`
	BarcodeVerified bool   `json:"barcode_verified"`
}

// Config holds review queue configuration.
type Config struct {
	// Enabled activates the operator review path. Default false.
	Enabled bool `yaml:"enabled" envconfig:"REVIEW_ENABLED"`
	// TTL is how long a review entry is held before auto-rejection.
	TTL time.Duration `yaml:"ttl" envconfig:"REVIEW_TTL"`
	// WebhookURL is an optional endpoint notified when a new review is queued.
	WebhookURL string `yaml:"webhook_url" envconfig:"REVIEW_WEBHOOK_URL"`
}

// Queue manages pending operator reviews.
type Queue struct {
	mu      sync.Mutex
	entries map[string]*Entry
	ttl     time.Duration
	done    chan struct{}
}

// NewQueue creates a review queue with the given TTL.
func NewQueue(ttl time.Duration) *Queue {
	q := &Queue{
		entries: make(map[string]*Entry),
		ttl:     ttl,
		done:    make(chan struct{}),
	}
	go q.reap()
	return q
}

// Submit adds a scan result to the review queue.
// The FaceMap biometric template is cleared before storage to prevent
// accidental retention of biometric data in the review queue.
func (q *Queue) Submit(sessionID, tenantID string, result facetec.ScanResult) {
	// Sanitize: never retain biometric templates in the review queue.
	result.Liveness.FaceMap = ""
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	q.entries[sessionID] = &Entry{
		SessionID:  sessionID,
		TenantID:   tenantID,
		ScanResult: result,
		CreatedAt:  now,
		ExpiresAt:  now.Add(q.ttl),
	}
}

// Pending returns summaries of all entries awaiting decision.
func (q *Queue) Pending() []Summary {
	q.mu.Lock()
	defer q.mu.Unlock()
	var result []Summary
	for _, e := range q.entries {
		if e.Decision != "" {
			continue
		}
		if time.Now().After(e.ExpiresAt) {
			continue
		}
		result = append(result, toSummary(e))
	}
	return result
}

// GetEvidence returns detailed evidence for operator review.
func (q *Queue) GetEvidence(sessionID string) (*Evidence, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.entries[sessionID]
	if !ok {
		return nil, fmt.Errorf("review: session %q not found", sessionID)
	}
	if e.Decision != "" {
		return nil, fmt.Errorf("review: session %q already decided", sessionID)
	}
	ev := &Evidence{
		Summary:         toSummary(e),
		GivenName:       e.ScanResult.IDScan.DocumentData.GivenName,
		FamilyName:      e.ScanResult.IDScan.DocumentData.FamilyName,
		DateOfBirth:     e.ScanResult.IDScan.DocumentData.DateOfBirth,
		Nationality:     e.ScanResult.IDScan.DocumentData.Nationality,
		DocumentNumber:  e.ScanResult.IDScan.DocumentData.DocumentNumber,
		NFCVerified:     e.ScanResult.IDScan.NFCVerified,
		BarcodeVerified: e.ScanResult.IDScan.BarcodeVerified,
	}
	return ev, nil
}

// Decide records an operator decision on a pending review.
// Returns the entry for further processing (audit, credential issuance).
func (q *Queue) Decide(sessionID string, decision Decision, operatorID, justification string) (*Entry, error) {
	if decision != DecisionAccept && decision != DecisionReject {
		return nil, fmt.Errorf("review: invalid decision %q, must be %q or %q", decision, DecisionAccept, DecisionReject)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.entries[sessionID]
	if !ok {
		return nil, fmt.Errorf("review: session %q not found", sessionID)
	}
	if e.Decision != "" {
		return nil, fmt.Errorf("review: session %q already decided", sessionID)
	}
	if time.Now().After(e.ExpiresAt) {
		return nil, fmt.Errorf("review: session %q expired", sessionID)
	}
	e.Decision = decision
	e.DecidedAt = time.Now()
	e.DecidedBy = operatorID
	e.Justification = justification
	return e, nil
}

// Close stops the background reaper.
func (q *Queue) Close() {
	close(q.done)
}

func (q *Queue) reap() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-q.done:
			return
		case <-ticker.C:
			q.mu.Lock()
			now := time.Now()
			for id, e := range q.entries {
				if e.Decision == "" && now.After(e.ExpiresAt) {
					e.Decision = DecisionReject
					e.DecidedAt = now
					e.Justification = "auto-expired"
				}
				// Remove decided entries older than 1 hour
				if e.Decision != "" && !e.DecidedAt.IsZero() && now.Sub(e.DecidedAt) > time.Hour {
					delete(q.entries, id)
				}
			}
			q.mu.Unlock()
		}
	}
}

func toSummary(e *Entry) Summary {
	return Summary{
		SessionID:      e.SessionID,
		TenantID:       e.TenantID,
		DocumentType:   e.ScanResult.IDScan.DocumentData.DocumentType,
		LivenessScore:  e.ScanResult.Liveness.LivenessScore,
		FaceMatchLevel: e.ScanResult.IDScan.FaceMatchLevel,
		MRZVerified:    e.ScanResult.IDScan.MRZVerified,
		CreatedAt:      e.CreatedAt,
		ExpiresAt:      e.ExpiresAt,
	}
}

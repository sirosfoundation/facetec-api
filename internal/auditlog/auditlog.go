// Package auditlog provides persistent, append-only audit records for IPV sessions.
//
// Each completed IPV session (accept, reject, review, timeout) produces a Record
// written to a configurable sink. Records never contain biometric data — only
// derived scores, boolean verification flags, and outcome metadata.
//
// Supported sinks: "file" (append-only JSONL), "webhook" (HTTP POST).
package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Outcome represents the result of an IPV session.
type Outcome string

const (
	OutcomeAccept  Outcome = "accept"
	OutcomeReject  Outcome = "reject"
	OutcomeReview  Outcome = "review"
	OutcomeTimeout Outcome = "timeout"
)

// Record is a single audit entry for an IPV session.
// It must NEVER contain biometric data (FaceMap, images, FaceScan).
type Record struct {
	SessionID       string    `json:"session_id"`
	Timestamp       time.Time `json:"timestamp"`
	TenantID        string    `json:"tenant_id"`
	Outcome         Outcome   `json:"outcome"`
	PolicyRule      string    `json:"policy_rule,omitempty"`
	LivenessScore   float64   `json:"liveness_score"`
	FaceMatchLevel  int       `json:"face_match_level"`
	DocumentType    string    `json:"document_type"`
	MRZVerified     bool      `json:"mrz_verified"`
	NFCVerified     bool      `json:"nfc_verified"`
	BarcodeVerified bool      `json:"barcode_verified"`
	CredentialOffer string    `json:"credential_offer,omitempty"`
	EvidenceHash    string    `json:"evidence_hash,omitempty"`
	ReviewedBy      string    `json:"reviewed_by,omitempty"`
	ReviewReason    string    `json:"review_reason,omitempty"`
	DurationMS      int64     `json:"duration_ms"`
}

// Logger is the interface for writing audit records.
type Logger interface {
	Write(ctx context.Context, rec Record) error
	Close() error
}

// Config holds audit log configuration.
type Config struct {
	// Sink selects the output: "file" or "webhook". Empty disables auditing.
	Sink string `yaml:"sink" envconfig:"AUDIT_SINK"`
	// Path is the file path for the "file" sink.
	Path string `yaml:"path" envconfig:"AUDIT_PATH"`
	// WebhookURL is the endpoint for the "webhook" sink.
	WebhookURL string `yaml:"webhook_url" envconfig:"AUDIT_WEBHOOK_URL"`
	// RetentionDays is informational — external log rotation should honour this.
	RetentionDays int `yaml:"retention_days" envconfig:"AUDIT_RETENTION_DAYS"`
}

// New creates an audit Logger based on config.
// Returns a no-op logger if sink is empty.
func New(cfg Config, log *zap.Logger) (Logger, error) {
	if log == nil {
		log = zap.NewNop()
	}
	switch strings.ToLower(cfg.Sink) {
	case "file":
		if cfg.Path == "" {
			return nil, fmt.Errorf("auditlog: file sink requires audit.path")
		}
		return newFileLogger(cfg.Path, log)
	case "webhook":
		if cfg.WebhookURL == "" {
			return nil, fmt.Errorf("auditlog: webhook sink requires audit.webhook_url")
		}
		return newWebhookLogger(cfg.WebhookURL, log), nil
	case "", "none":
		return &nopLogger{}, nil
	default:
		return nil, fmt.Errorf("auditlog: unknown sink %q", cfg.Sink)
	}
}

// fileLogger writes JSONL to an append-only file.
type fileLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
	log  *zap.Logger
}

func newFileLogger(path string, log *zap.Logger) (*fileLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("auditlog: open %q: %w", path, err)
	}
	return &fileLogger{
		file: f,
		enc:  json.NewEncoder(f),
		log:  log,
	}, nil
}

func (l *fileLogger) Write(_ context.Context, rec Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.enc.Encode(rec); err != nil {
		l.log.Error("auditlog: write failed", zap.Error(err))
		return err
	}
	return nil
}

func (l *fileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// webhookLogger POSTs records as JSON to a URL.
type webhookLogger struct {
	url    string
	client *http.Client
	log    *zap.Logger
}

func newWebhookLogger(url string, log *zap.Logger) *webhookLogger {
	return &webhookLogger{
		url:    url,
		client: &http.Client{Timeout: 5 * time.Second},
		log:    log,
	}
}

func (l *webhookLogger) Write(ctx context.Context, rec Record) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		l.log.Warn("auditlog: webhook delivery failed", zap.Error(err))
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		l.log.Warn("auditlog: webhook returned error", zap.Int("status", resp.StatusCode))
		return fmt.Errorf("auditlog: webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (l *webhookLogger) Close() error { return nil }

// nopLogger discards all records (used when auditing is disabled).
type nopLogger struct{}

func (l *nopLogger) Write(_ context.Context, _ Record) error { return nil }
func (l *nopLogger) Close() error                            { return nil }

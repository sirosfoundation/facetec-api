package auditlog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestFileLogger(t *testing.T) {
	tmp := t.TempDir() + "/audit.jsonl"
	cfg := Config{Sink: "file", Path: tmp}
	logger, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := Record{
		SessionID:      "test-session-001",
		Timestamp:      time.Now().UTC(),
		TenantID:       "default",
		Outcome:        OutcomeAccept,
		LivenessScore:  0.95,
		FaceMatchLevel: 8,
		DocumentType:   "passport",
		MRZVerified:    true,
		DurationMS:     4200,
	}

	if err := logger.Write(context.Background(), rec); err != nil {
		t.Fatal("write failed:", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal("close failed:", err)
	}

	// Verify file content
	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Record
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal("unmarshal failed:", err)
	}
	if decoded.SessionID != "test-session-001" {
		t.Errorf("got session_id=%q, want test-session-001", decoded.SessionID)
	}
	if decoded.Outcome != OutcomeAccept {
		t.Errorf("got outcome=%q, want accept", decoded.Outcome)
	}
	if decoded.LivenessScore != 0.95 {
		t.Errorf("got liveness_score=%f, want 0.95", decoded.LivenessScore)
	}
}

func TestNopLogger(t *testing.T) {
	cfg := Config{Sink: ""}
	logger, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Should not error
	if err := logger.Write(context.Background(), Record{}); err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidSink(t *testing.T) {
	cfg := Config{Sink: "invalid"}
	_, err := New(cfg, nil)
	if err == nil {
		t.Fatal("expected error for invalid sink")
	}
}

func TestWebhookLogger_Success(t *testing.T) {
	var received Record
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q, want application/json", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{Sink: "webhook", WebhookURL: srv.URL}
	logger, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := Record{
		SessionID:      "webhook-test-001",
		Timestamp:      time.Now().UTC(),
		TenantID:       "default",
		Outcome:        OutcomeAccept,
		LivenessScore:  0.91,
		FaceMatchLevel: 7,
		DocumentType:   "passport",
	}

	if err := logger.Write(context.Background(), rec); err != nil {
		t.Fatal("write failed:", err)
	}
	if received.SessionID != "webhook-test-001" {
		t.Errorf("received session_id = %q, want webhook-test-001", received.SessionID)
	}
}

func TestWebhookLogger_Non2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := Config{Sink: "webhook", WebhookURL: srv.URL}
	logger, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = logger.Write(context.Background(), Record{SessionID: "fail-test"})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestWebhookLogger_RedirectReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://elsewhere.example.com")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	// Disable auto-redirect following
	cfg := Config{Sink: "webhook", WebhookURL: srv.URL}
	logger, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = logger.Write(context.Background(), Record{SessionID: "redirect-test"})
	if err == nil {
		t.Fatal("expected error for 3xx response")
	}
}

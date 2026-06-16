package auditlog

import (
	"context"
	"encoding/json"
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

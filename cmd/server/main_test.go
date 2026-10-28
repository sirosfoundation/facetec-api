package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
)

func TestBuildLogger_PIIWarning(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		for _, include := range []bool{false, true} {
			t.Run(level+"/"+map[bool]string{false: "default", true: "opt-in"}[include], func(t *testing.T) {
				stderr, err := os.CreateTemp(t.TempDir(), "stderr")
				if err != nil {
					t.Fatal(err)
				}
				defer stderr.Close()
				original := os.Stderr
				os.Stderr = stderr
				defer func() { os.Stderr = original }()

				cfg := &config.Config{Logging: config.LoggingConfig{Level: level, IncludePII: include}}
				log, err := buildLogger(cfg)
				if err != nil {
					t.Fatal(err)
				}
				_ = log.Sync()
				output, err := os.ReadFile(stderr.Name())
				if err != nil {
					t.Fatal(err)
				}
				warningExpected := include && level != "error"
				if warningExpected {
					for _, text := range []string{"WARN", "WARNING", "PII", "NFC/OCR", "NEVER enable this in production"} {
						if !strings.Contains(string(output), text) {
							t.Errorf("startup warning missing %q: %s", text, output)
						}
					}
				} else if len(output) != 0 {
					t.Errorf("unexpected startup warning: %s", output)
				}
			})
		}
	}
}

func TestLoggerConfig_Format(t *testing.T) {
	for _, tt := range []struct {
		format       string
		wantEncoding string
	}{
		{"", "console"},
		{config.LogFormatConsole, "console"},
		{config.LogFormatJSON, "json"},
	} {
		t.Run("format="+tt.format, func(t *testing.T) {
			if got := loggerConfig(tt.format).Encoding; got != tt.wantEncoding {
				t.Errorf("encoding: got %q, want %q", got, tt.wantEncoding)
			}
		})
	}
}

// TestLoggerConfig_JSONDoesNotSample guards the reason loggerConfig assembles
// its own config instead of calling zap.NewProductionConfig(): that one
// samples, and zap's sampler counts per level and message, so the one constant
// "AUDIT credential_issued" message would be thinned to 1 in 100 above 100
// issuances a second.
func TestLoggerConfig_JSONDoesNotSample(t *testing.T) {
	if s := loggerConfig(config.LogFormatJSON).Sampling; s != nil {
		t.Errorf("JSON logging must not sample, got initial=%d thereafter=%d",
			s.Initial, s.Thereafter)
	}
	// Pin the premise: this is a trap only because the stock config samples.
	if s := zap.NewProductionConfig().Sampling; s == nil {
		t.Skip("zap.NewProductionConfig() no longer samples; this guard is moot")
	}
}

// TestBuildLogger_JSONIsOneObjectPerLine is the point of the format: a log
// shipper has to be able to parse a line without knowing anything else.
func TestBuildLogger_JSONIsOneObjectPerLine(t *testing.T) {
	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	original := os.Stderr
	os.Stderr = stderr
	defer func() { os.Stderr = original }()

	cfg := &config.Config{Logging: config.LoggingConfig{
		Level:  "info",
		Format: config.LogFormatJSON,
	}}
	log, err := buildLogger(cfg)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("AUDIT credential_issued", zap.String("tenant", "t-1"))
	_ = log.Sync()

	output, err := os.ReadFile(stderr.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %s", len(lines), output)
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v: %s", err, lines[0])
	}
	if entry["msg"] != "AUDIT credential_issued" {
		t.Errorf("msg: got %v", entry["msg"])
	}
	if entry["tenant"] != "t-1" {
		t.Errorf("tenant: got %v", entry["tenant"])
	}
	// RFC3339, not the epoch float zap.NewProductionConfig() would write.
	ts, ok := entry["ts"].(string)
	if !ok {
		t.Fatalf("ts: got %T %v, want an RFC3339 string", entry["ts"], entry["ts"])
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("ts %q is not RFC3339: %v", ts, err)
	}
}

// TestBuildLogger_JSONHonoursLevel pins that logging.level still applies;
// zap.NewProductionConfig() would have pinned the level to info.
func TestBuildLogger_JSONHonoursLevel(t *testing.T) {
	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	original := os.Stderr
	os.Stderr = stderr
	defer func() { os.Stderr = original }()

	cfg := &config.Config{Logging: config.LoggingConfig{
		Level:  "debug",
		Format: config.LogFormatJSON,
	}}
	log, err := buildLogger(cfg)
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("debug entry")
	_ = log.Sync()

	output, err := os.ReadFile(stderr.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "debug entry") {
		t.Errorf("logging.level: debug was not honoured in JSON format: %s", output)
	}
}

package main

import (
	"os"
	"strings"
	"testing"

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
				if include {
					for _, text := range []string{"WARNING", "PII", "NFC/OCR", "NEVER enable this in production"} {
						if !strings.Contains(string(output), text) {
							t.Errorf("startup warning missing %q: %s", text, output)
						}
					}
				} else if len(output) != 0 {
					t.Errorf("unexpected warning with PII disabled: %s", output)
				}
			})
		}
	}
}

// Package policy wraps the go-spocp engine for scan acceptance decisions.
//
// Scan results are evaluated entirely by SPOCP rules loaded from .spoc files.
// Rules encode both numeric thresholds (via star-form range predicates) and
// categorical constraints (document type, verification flags) in a single rule.
//
// Numeric values in queries are formatted as zero-padded fixed-width integers
// so that lexicographic comparison matches numeric order:
//   - liveness-score: 3-digit (000–100)
//   - face-match-level: 2-digit (00–10)
//
// Example rule file (advanced format, one rule per line, no quotes):
//
//	; Accept passports — liveness >= 80, face-match >= 6, MRZ verified
//	(facetec-scan (liveness-score (* range numeric ge 080)) (face-match-level (* range numeric ge 06)) (doc-type passport) (mrz-verified true))
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
	spocp "github.com/sirosfoundation/go-spocp"
	"github.com/sirosfoundation/go-spocp/pkg/persist"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// Engine wraps a go-spocp Engine for scan policy evaluation.
type Engine struct {
	engine *spocp.Engine
}

// New creates a policy Engine and loads all .spoc rule files from rulesDir.
// Rule files must use SPOCP advanced (human-readable) format, one rule per line.
// Star-form elements parsed from file (e.g. range predicates) are reconstructed
// into proper starform types so the comparison engine handles them correctly.
// If rulesDir is empty the engine starts with no rules.
func New(rulesDir string) (*Engine, error) {
	e := spocp.NewEngine()
	if rulesDir != "" {
		entries, err := os.ReadDir(rulesDir)
		if err != nil {
			return nil, fmt.Errorf("policy: read rules dir %q: %w", rulesDir, err)
		}
		opts := persist.LoadOptions{
			Format:      persist.FormatAdvanced,
			SkipInvalid: false,
			Comments:    []string{"#", "//", ";"},
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".spoc") {
				continue
			}
			path := filepath.Join(rulesDir, entry.Name())
			rules, err := persist.LoadFile(path, opts)
			if err != nil {
				return nil, fmt.Errorf("policy: load rules from %q: %w", path, err)
			}
			for _, rule := range rules {
				e.AddRuleElement(rule)
			}
		}
	}
	return &Engine{engine: e}, nil
}

// EvaluateScan evaluates a combined scan result against the loaded SPOCP rules.
// The query includes liveness score and face match level as zero-padded atoms
// so that range predicates in the rules can enforce numeric thresholds.
// Returns nil if the scan is accepted by at least one rule.
func (e *Engine) EvaluateScan(result facetec.ScanResult) error {
	query := buildQueryElement(result)
	if !e.engine.QueryElement(query) {
		return fmt.Errorf("policy: scan rejected by policy rules")
	}
	return nil
}

// RuleCount returns the number of rules currently loaded in the engine.
func (e *Engine) RuleCount() int {
	return e.engine.RuleCount()
}

// buildQueryElement converts a ScanResult into a SPOCP S-expression element.
// Numeric fields are formatted as zero-padded fixed-width integers so that
// lexicographic comparison in RangeNumeric star-forms matches numeric order:
//   - liveness-score: 3-digit zero-padded (000–100)
//   - face-match-level: 2-digit zero-padded (00–10)
//
// Field order: liveness-score, face-match-level, doc-type, mrz-verified,
// nfc-verified, barcode-verified.
func buildQueryElement(r facetec.ScanResult) sexp.Element {
	livenessScore := int(r.Liveness.LivenessScore * 100)
	return sexp.NewList("facetec-scan",
		sexp.NewList("liveness-score", sexp.NewAtom(fmt.Sprintf("%03d", livenessScore))),
		sexp.NewList("face-match-level", sexp.NewAtom(fmt.Sprintf("%02d", r.IDScan.FaceMatchLevel))),
		sexp.NewList("doc-type", sexp.NewAtom(docType(r))),
		sexp.NewList("mrz-verified", sexp.NewAtom(boolStr(r.IDScan.MRZVerified))),
		sexp.NewList("nfc-verified", sexp.NewAtom(boolStr(r.IDScan.NFCVerified))),
		sexp.NewList("barcode-verified", sexp.NewAtom(boolStr(r.IDScan.BarcodeVerified))),
	)
}

func docType(r facetec.ScanResult) string {
	if r.IDScan.DocumentData.DocumentType == "" {
		return "unknown"
	}
	return r.IDScan.DocumentData.DocumentType
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}


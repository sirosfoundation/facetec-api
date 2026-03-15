// Package policy wraps the go-spocp engine for scan acceptance decisions.
//
// Scan results are evaluated in two stages:
//  1. Numeric threshold checks (min_liveness_score, min_face_match_level) —
//     explicit, auditable comparisons that operators configure in policy config.
//  2. Categorical SPOCP check — rules in the .spoc file encode which combinations
//     of document type and verification flags are acceptable.
//
// Separating numeric and categorical checks avoids the need to enumerate every
// possible liveness score value in SPOCP rules (SPOCP atom matching is exact).
// Example rule file (advanced format, one rule per line, no quotes):
//
//	; Accept passports with MRZ verification
//	(facetec-scan (doc-type passport) (mrz-verified true))
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
	engine            *spocp.Engine
	minLivenessScore  int // 0–100; scans below this are rejected before SPOCP
	minFaceMatchLevel int // 0–10;  scans below this are rejected before SPOCP
}

// New creates a policy Engine and loads all .spoc rule files from rulesDir.
// Rule files must use SPOCP advanced (human-readable) format, one rule per line.
// minLivenessScore (0–100) and minFaceMatchLevel (0–10) are enforced before SPOCP;
// rules in the .spoc files only need to address categorical fields (doc-type,
// verification flags). If rulesDir is empty the engine starts with no rules.
func New(rulesDir string, minLivenessScore, minFaceMatchLevel int) (*Engine, error) {
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
			if err := e.LoadRulesFromFileWithOptions(path, opts); err != nil {
				return nil, fmt.Errorf("policy: load rules from %q: %w", path, err)
			}
		}
	}
	return &Engine{
		engine:            e,
		minLivenessScore:  minLivenessScore,
		minFaceMatchLevel: minFaceMatchLevel,
	}, nil
}

// EvaluateScan evaluates a combined scan result against the loaded SPOCP rules.
// It first checks numeric thresholds (fast, explicit), then runs the categorical
// SPOCP query. Returns nil if the scan is accepted.
func (e *Engine) EvaluateScan(result facetec.ScanResult) error {
	// Stage 1: numeric threshold checks.
	score := int(result.Liveness.LivenessScore * 100)
	if score < e.minLivenessScore {
		return fmt.Errorf("policy: liveness score %d below minimum %d", score, e.minLivenessScore)
	}
	if result.IDScan.FaceMatchLevel < e.minFaceMatchLevel {
		return fmt.Errorf("policy: face match level %d below minimum %d",
			result.IDScan.FaceMatchLevel, e.minFaceMatchLevel)
	}
	// Stage 2: categorical SPOCP check (doc-type + verification flags).
	query := buildQueryElement(result)
	if !e.engine.QueryElement(query) {
		return fmt.Errorf("policy: scan rejected — no matching rule for doc-type=%s", docType(result))
	}
	return nil
}

// RuleCount returns the number of rules currently loaded in the engine.
func (e *Engine) RuleCount() int {
	return e.engine.RuleCount()
}

// buildQueryElement converts the categorical fields of a ScanResult into a SPOCP
// S-expression element. Numeric fields (liveness score, face match level) are
// intentionally excluded — they are handled by the explicit threshold checks above.
// Query field order: doc-type, mrz-verified, nfc-verified, barcode-verified.
func buildQueryElement(r facetec.ScanResult) sexp.Element {
	dt := docType(r)
	return sexp.NewList("facetec-scan",
		sexp.NewList("doc-type", sexp.NewAtom(dt)),
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


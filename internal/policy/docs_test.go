package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
)

// queryFieldOrder is the field order of every SPOCP query (see buildQuery).
var queryFieldOrder = []string{
	"liveness-score", "face-match-level", "doc-type", "mrz-verified",
	"nfc-verified", "barcode-verified", "chip-trusted",
}

// docFiles are the documents whose ```scheme blocks must be valid policy.
var docFiles = []string{
	"README.md",
	"docs/adr/001-facetec-api-architecture.md",
	"docs/adr/002-emrtd-document-signer-trust.md",
	"PRIVACY.md",
}

var schemeBlockRe = regexp.MustCompile("(?s)```scheme\n(.*?)```")

// docRules returns every rule line of every ```scheme block in path.
func docRules(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var rules []string
	for _, m := range schemeBlockRe.FindAllStringSubmatch(string(b), -1) {
		for _, line := range strings.Split(m[1], "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "(facetec-scan") {
				rules = append(rules, line)
			}
		}
	}
	return rules
}

// topLevelFields returns the names of the direct children of a rule.
func topLevelFields(rule string) []string {
	var names []string
	depth := 0
	for i := 0; i < len(rule); i++ {
		switch rule[i] {
		case '(':
			depth++
			if depth == 2 {
				j := i + 1
				for j < len(rule) && rule[j] != ' ' && rule[j] != ')' {
					j++
				}
				names = append(names, rule[i+1:j])
			}
		case ')':
			depth--
		}
	}
	return names
}

// Every policy example shown in the docs must follow the positional contract
// (a prefix of the engine's field order, nothing skipped or reordered) and be
// loadable by the real engine.
func TestDocumentedPolicyExamplesAreValid(t *testing.T) {
	total := 0
	for _, f := range docFiles {
		for _, rule := range docRules(t, f) {
			total++
			got := topLevelFields(rule)
			if len(got) == 0 || len(got) > len(queryFieldOrder) || !slices.Equal(got, queryFieldOrder[:len(got)]) {
				t.Errorf("%s: %q lists fields %v, which is not a prefix of %v (positional matching)", f, rule, got, queryFieldOrder)
			}
			e, err := New(writeRules(t, rule+"\n"))
			if err != nil {
				t.Errorf("%s: %q does not load: %v", f, rule, err)
				continue
			}
			if e.RuleCount() != 1 {
				t.Errorf("%s: %q loaded %d rules, want 1", f, rule, e.RuleCount())
			}
		}
	}
	if total == 0 {
		t.Fatal("no documented policy examples found; the extraction is broken")
	}
}

// The README shows the shipped accept rules: each must appear verbatim in
// rules/default.spoc, and, loaded as a rule set, must behave as documented.
func TestReadmeRulesMatchShippedRulesAndBehaviour(t *testing.T) {
	shipped, err := os.ReadFile(filepath.Join("..", "..", "rules", "default.spoc"))
	if err != nil {
		t.Fatal(err)
	}
	rules := docRules(t, "README.md")
	if len(rules) != 3 {
		t.Fatalf("README shows %d rules, want 3 (passport, id_card, dl)", len(rules))
	}
	for _, r := range rules {
		if !strings.Contains(string(shipped), r) {
			t.Errorf("README rule is not in rules/default.spoc: %s", r)
		}
	}

	e, err := New(writeRules(t, strings.Join(rules, "\n")+"\n"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		name string
		scan facetec.ScanResult
		ok   bool
	}{
		{"passport, chip authenticated and trusted", scan("passport", true, true, false, true), true},
		{"passport, chip not trusted", scan("passport", true, true, false, false), false},
		{"passport, chip not authenticated", scan("passport", true, false, false, true), false},
		{"id card with chip", scan("id_card", false, true, false, false), true},
		{"id card without chip", scan("id_card", true, false, false, false), false},
		{"driving licence with chip", scan("dl", false, true, false, false), true},
		{"driving licence barcode only", scan("dl", false, false, true, false), false},
	}
	for _, tc := range cases {
		if err := e.EvaluateScan(tc.scan); (err == nil) != tc.ok {
			t.Errorf("%s: accepted=%v, want %v (err=%v)", tc.name, err == nil, tc.ok, err)
		}
	}
}

// The ADR-001 permissive example must accept a passport scan above its
// thresholds, proving the documented form actually fires.
func TestADR001PermissiveExampleFires(t *testing.T) {
	var permissive string
	for _, r := range docRules(t, "docs/adr/001-facetec-api-architecture.md") {
		if strings.Contains(r, "range numeric") {
			permissive = r
		}
	}
	if permissive == "" {
		t.Fatal("ADR-001 permissive example not found")
	}
	e, err := New(writeRules(t, permissive+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.EvaluateScan(scan("passport", true, true, true, true)); err != nil {
		t.Errorf("above thresholds: %v", err)
	}
	low := scan("passport", true, true, true, true)
	low.Liveness.LivenessScore = 0.5
	if err := e.EvaluateScan(low); err == nil {
		t.Error("liveness 50 must not satisfy ge 080")
	}
}

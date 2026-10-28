package buildmode_test

import (
	"testing"

	"github.com/sirosfoundation/facetec-api/internal/buildmode"
)

// TestProduction_MatchesBuildTag passes under both builds: without the tag it
// must report false, with -tags production it must report true. CI runs the
// suite both ways, so this catches a tag file that stops being selected.
func TestProduction_MatchesBuildTag(t *testing.T) {
	if got := buildmode.Production(); got != expected {
		t.Errorf("Production() = %v, want %v for this build", got, expected)
	}
}

package config_test

import (
	"strings"
	"testing"

	"github.com/sirosfoundation/facetec-api/internal/buildmode"
	"github.com/sirosfoundation/facetec-api/internal/config"
)

// TestValidate_TrustRequiredOptOut checks the one setting whose acceptability
// depends on how the binary was built: trust.required: false switches off the
// document-signer trust check and the verified-identity gate that depends on
// it (#85). A development build tolerates it for a stack with no PDP; a
// production build refuses to start.
//
// The suite runs under both builds, so this pins each side without needing to
// fake the build tag.
func TestValidate_TrustRequiredOptOut(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
		Issuer:  config.IssuerConfig{Addr: "https://x", Scope: "s"},
		JWT:     jwtAuth("", "shared-secret"),
		Trust:   config.TrustConfig{Required: false},
	}

	err := cfg.Validate()
	if buildmode.Production() {
		if err == nil {
			t.Fatal("a production build must refuse trust.required: false")
		}
		for _, want := range []string{"trust.required", "production build", "development build"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error should mention %q, got: %v", want, err)
			}
		}
		return
	}
	if err != nil {
		t.Errorf("a development build should accept trust.required: false, got: %v", err)
	}
}

// TestValidate_TrustRequiredTrueIsAcceptedEverywhere: the safe setting must of
// course pass under both builds, given a PDP.
func TestValidate_TrustRequiredTrueIsAcceptedEverywhere(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
		Issuer:  config.IssuerConfig{Addr: "https://x", Scope: "s"},
		JWT:     jwtAuth("", "shared-secret"),
		Trust:   config.TrustConfig{Required: true, PDPURL: "https://go-trust.example.org"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

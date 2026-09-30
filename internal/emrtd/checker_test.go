package emrtd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/facetec-api/internal/emrtd/emrtdtest"
)

func mustResp(t *testing.T, body string) *authzen.EvaluationResponse {
	t.Helper()
	var r authzen.EvaluationResponse
	require.NoError(t, json.Unmarshal([]byte(body), &r))
	return &r
}

type fakePDP struct {
	dec   TrustDecision
	err   error
	calls int
	got   TrustRequest
}

func (f *fakePDP) EvaluateDSC(_ context.Context, req TrustRequest) (TrustDecision, error) {
	f.calls++
	f.got = req
	return f.dec, f.err
}

func TestChecker_Trusted(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{ExtraCert: true})
	pdp := &fakePDP{dec: TrustDecision{Trusted: true, CSCASHA256: "aa"}}
	out := NewChecker(pdp, true).Check(t.Context(), c.Raw, claimedFor(c))
	assert.True(t, out.Trusted)
	assert.Equal(t, ReasonOK, out.Reason)
	assert.True(t, out.ChipPresented)
	assert.Equal(t, "SWE", pdp.got.IssuingState)
	assert.Equal(t, [][]byte{c.DSC, c.CSCA}, pdp.got.Chain, "DSC first, then extra SOD certs")
	assert.Equal(t, "aa", out.Decision.CSCASHA256)
}

func TestChecker_Denied(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	for code, want := range map[string]string{"no_anchor": "pdp_denied:no_anchor", "": "pdp_denied:unspecified"} {
		out := NewChecker(&fakePDP{dec: TrustDecision{Code: code}}, true).Check(t.Context(), c.Raw, claimedFor(c))
		assert.False(t, out.Trusted)
		assert.Equal(t, want, out.Reason)
	}
}

func TestChecker_PDPErrorAndMalformed(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	out := NewChecker(&fakePDP{err: errors.New("down")}, true).Check(t.Context(), c.Raw, claimedFor(c))
	assert.False(t, out.Trusted)
	assert.Equal(t, ReasonPDPError, out.Reason)

	out = NewChecker(&fakePDP{err: fmt.Errorf("x: %w", ErrMalformedResponse)}, true).Check(t.Context(), c.Raw, claimedFor(c))
	assert.False(t, out.Trusted)
	assert.Equal(t, ReasonPDPMalformed, out.Reason)
}

func TestChecker_LocalFailureSkipsPDP(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{WrongSigner: true})
	pdp := &fakePDP{dec: TrustDecision{Trusted: true, CSCASHA256: "aa"}}
	out := NewChecker(pdp, true).Check(t.Context(), c.Raw, claimedFor(c))
	assert.False(t, out.Trusted)
	assert.Equal(t, ReasonSODSignature, out.Reason)
	assert.Equal(t, 0, pdp.calls, "never ask the PDP about a DSC whose SOD did not verify")
}

func TestChecker_PDPUnconfigured(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	for _, ch := range []*Checker{NewChecker(nil, true), NewChecker(nil, false), nil} {
		out := ch.Check(t.Context(), c.Raw, claimedFor(c))
		assert.False(t, out.Trusted, "unconfigured PDP must never yield trust")
		assert.Equal(t, ReasonPDPUnconfigured, out.Reason)
		assert.True(t, out.ChipPresented)
	}
}

func TestChecker_NoChip(t *testing.T) {
	out := NewChecker(&fakePDP{}, true).Check(t.Context(), nil, Claimed{})
	assert.False(t, out.Trusted)
	assert.False(t, out.ChipPresented)
	assert.Equal(t, ReasonNoChipData, out.Reason)
}

func TestChecker_Required(t *testing.T) {
	assert.True(t, NewChecker(nil, true).Required())
	assert.False(t, NewChecker(nil, false).Required())
	var nilChecker *Checker
	assert.False(t, nilChecker.Required())
}

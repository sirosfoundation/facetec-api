package emrtd

import (
	"context"
	"errors"
)

// Checker combines local passive authentication with the PDP decision.
type Checker struct {
	pdp      TrustEvaluator
	required bool
}

// NewChecker returns a Checker. A nil pdp means "unconfigured": chips are
// still verified locally but can never be reported as trusted. required is
// informational for callers (see Required).
func NewChecker(pdp TrustEvaluator, required bool) *Checker {
	return &Checker{pdp: pdp, required: required}
}

// Required reports whether the deployment demands a trusted chip whenever chip
// data is presented (trust.required).
func (c *Checker) Required() bool { return c != nil && c.required }

// Outcome is the full result of [Checker.Check].
type Outcome struct {
	// Trusted is true only if local verification passed AND the PDP allowed.
	Trusted bool
	// Reason is ReasonOK or a machine-readable reason code.
	Reason string
	// ChipPresented is true when SOD data was supplied at all.
	ChipPresented bool
	// Local is the local verification result (never nil).
	Local *Result
	// Decision is the PDP verdict when a PDP call was made.
	Decision TrustDecision
}

// Check verifies the chip data and asks the PDP about the DSC. Every failure
// path yields Trusted == false.
func (c *Checker) Check(ctx context.Context, raw map[string]string, claimed Claimed) Outcome {
	local := Verify(raw, claimed)
	out := Outcome{Reason: local.Reason, ChipPresented: local.Reason != ReasonNoChipData, Local: local}
	if !local.OK {
		return out
	}
	if c == nil || c.pdp == nil {
		out.Reason = ReasonPDPUnconfigured
		return out
	}
	chain := make([][]byte, 0, 1+len(local.ExtraCerts))
	chain = append(chain, local.DSC)
	chain = append(chain, local.ExtraCerts...)
	dec, err := c.pdp.EvaluateDSC(ctx, TrustRequest{
		IssuingState: local.IssuingState,
		Chain:        chain,
		SigningTime:  local.SigningTime,
	})
	out.Decision = dec
	switch {
	case errors.Is(err, ErrMalformedResponse):
		out.Reason = ReasonPDPMalformed
	case err != nil:
		out.Reason = ReasonPDPError
	case !dec.Trusted:
		code := dec.Code
		if code == "" {
			code = "unspecified"
		}
		out.Reason = ReasonPDPDeniedPrefix + code
	default:
		out.Trusted = true
		out.Reason = ReasonOK
	}
	return out
}

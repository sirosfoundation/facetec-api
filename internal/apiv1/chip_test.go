package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/emrtd"
	"github.com/sirosfoundation/facetec-api/internal/emrtd/emrtdtest"
	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/idverrors"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

type fakeEvaluator struct {
	dec   emrtd.TrustDecision
	err   error
	calls int
}

func (f *fakeEvaluator) EvaluateDSC(context.Context, emrtd.TrustRequest) (emrtd.TrustDecision, error) {
	f.calls++
	return f.dec, f.err
}

// chipPayload is a completed process-request response whose documentData
// carries real (synthetic) chip data and the matching MRZ-derived fields.
func chipPayload(t *testing.T, chip *emrtdtest.Chip, authStatus int, withChip bool) string {
	t.Helper()
	field := func(k, v string) map[string]any { return map[string]any{"fieldKey": k, "value": v} }
	dd := map[string]any{
		"mrzValues": map[string]any{"groups": []any{map[string]any{"fields": []any{
			field("firstName", chip.GivenName),
			field("lastName", chip.FamilyName),
			field("idNumber", chip.DocumentNumber),
			field("dateOfBirth", chip.DateOfBirth),
			field("dateOfExpiration", chip.DateOfExpiry),
			field("nationality", "SWE"),
			field("countryCode", "SWE"),
		}}}},
		"templateInfo": map[string]any{"templateType": "Passport"},
	}
	if withChip {
		raw := map[string]any{}
		for k, v := range chip.Raw {
			raw[k] = v
		}
		dd["nfcValues"] = map[string]any{"rawData": raw}
	}
	body, err := json.Marshal(map[string]any{"idScanResultsSoFar": map[string]any{
		"photoIDNextStepEnumInt":         4,
		"matchLevel":                     8,
		"nfcStatusEnumInt":               4,
		"nfcAuthenticationStatusEnumInt": authStatus,
		"mrzStatusEnumInt":               2,
		"barcodeStatusEnumInt":           3,
		"documentData":                   dd,
	}})
	require.NoError(t, err)
	return string(body)
}

func chipClient(t *testing.T, body string, pdp emrtd.TrustEvaluator, required bool) (*Client, context.Context) {
	t.Helper()
	c := newTestClientForProcessRequest(t, body)
	c.chip = emrtd.NewChecker(pdp, required)
	tc := &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)}
	return c, tenant.WithStdContext(t.Context(), tc)
}

func process(t *testing.T, c *Client, ctx context.Context) *facetec.ProcessRequestResponse {
	t.Helper()
	resp, err := c.ProcessRequest(ctx, &facetec.ProcessRequestRequest{RequestBlob: "opaque"})
	require.NoError(t, err)
	assert.Empty(t, resp.TransactionID, "nothing may be issued in these tests")
	return resp
}

func TestProcessRequest_ChipAuthFailedIsHardReject(t *testing.T) {
	for _, status := range []int{facetec.ChipAuthFailed, facetec.ChipAuthFailedSignature} {
		chip := emrtdtest.New(emrtdtest.Options{})
		// Even a fully trusted chip and non-required trust cannot save it.
		pdp := &fakeEvaluator{dec: emrtd.TrustDecision{Trusted: true, CSCASHA256: "aa"}}
		c, ctx := chipClient(t, chipPayload(t, chip, status, true), pdp, false)
		resp := process(t, c, ctx)
		assert.Equal(t, string(idverrors.CodeChipAuthFailed), resp.CredentialIssueErrCode, "status %d", status)
		assert.Equal(t, 0, pdp.calls, "PDP is not consulted for a chip FaceTec already failed")
	}
}

func TestProcessRequest_ChipAuthStatus1IsPermitted(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	pdp := &fakeEvaluator{dec: emrtd.TrustDecision{Trusted: true, CSCASHA256: "aa"}}
	c, ctx := chipClient(t, chipPayload(t, chip, 1, true), pdp, true)
	resp := process(t, c, ctx)
	// Passed the chip gates; rejected only by the always-rejecting test policy.
	assert.Equal(t, string(idverrors.CodePolicyRejected), resp.CredentialIssueErrCode)
	assert.Equal(t, 1, pdp.calls)
}

func TestProcessRequest_RequiredUntrustedChipRejected(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	for name, pdp := range map[string]*fakeEvaluator{
		"denied":    {dec: emrtd.TrustDecision{Code: "no_anchor"}},
		"pdp error": {err: errors.New("down")},
		"malformed": {err: emrtd.ErrMalformedResponse},
	} {
		t.Run(name, func(t *testing.T) {
			c, ctx := chipClient(t, chipPayload(t, chip, 4, true), pdp, true)
			resp := process(t, c, ctx)
			assert.Equal(t, string(idverrors.CodeChipUntrusted), resp.CredentialIssueErrCode)
		})
	}
}

func TestProcessRequest_RequiredTamperedChipRejected(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{WrongSigner: true})
	pdp := &fakeEvaluator{dec: emrtd.TrustDecision{Trusted: true, CSCASHA256: "aa"}}
	c, ctx := chipClient(t, chipPayload(t, chip, 4, true), pdp, true)
	resp := process(t, c, ctx)
	assert.Equal(t, string(idverrors.CodeChipUntrusted), resp.CredentialIssueErrCode)
	assert.Equal(t, 0, pdp.calls)
}

func TestProcessRequest_RequiredWithoutPDPRejectsPresentedChip(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	c, ctx := chipClient(t, chipPayload(t, chip, 4, true), nil, true)
	resp := process(t, c, ctx)
	assert.Equal(t, string(idverrors.CodeChipUntrusted), resp.CredentialIssueErrCode, "unconfigured PDP must refuse, not skip")
}

func TestProcessRequest_NotRequiredUntrustedChipLeftToPolicy(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	c, ctx := chipClient(t, chipPayload(t, chip, 4, true), nil, false)
	resp := process(t, c, ctx)
	assert.Equal(t, string(idverrors.CodePolicyRejected), resp.CredentialIssueErrCode)
}

func TestProcessRequest_NoChipDataLeftToPolicyEvenWhenRequired(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	pdp := &fakeEvaluator{}
	c, ctx := chipClient(t, chipPayload(t, chip, 4, false), pdp, true)
	resp := process(t, c, ctx)
	assert.Equal(t, string(idverrors.CodePolicyRejected), resp.CredentialIssueErrCode,
		"doc types without a chip (e.g. dl) are governed by SPOCP rules; the passport rule demands chip-trusted")
	assert.Equal(t, 0, pdp.calls)
}

func TestAssessChip_FillsScanResult(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	c := &Client{chip: emrtd.NewChecker(&fakeEvaluator{dec: emrtd.TrustDecision{Trusted: true, CSCASHA256: "cafe"}}, true)}
	scan := &facetec.ScanResult{IDScan: facetec.IDScanResult{
		ChipRaw:        chip.Raw,
		ChipAuthStatus: 1,
		DocumentData: facetec.DocumentData{
			GivenName: chip.GivenName, FamilyName: chip.FamilyName, DocumentNumber: chip.DocumentNumber,
			DateOfBirth: chip.DateOfBirth, DateOfExpiry: chip.DateOfExpiry, Nationality: "SWE", IssuingCountry: "SWE",
		},
	}}
	require.Nil(t, c.assessChip(t.Context(), scan))
	assert.True(t, scan.IDScan.ChipTrusted)
	assert.Equal(t, emrtd.ReasonOK, scan.IDScan.ChipTrustReason)
	assert.Equal(t, "cafe", scan.IDScan.ChipCSCASHA256)
	assert.Len(t, scan.IDScan.ChipDSCSHA256, 64)

	fields := chipAuditFields(scan.IDScan)
	enc := zap.NewExample()
	enc.Info("x", fields...) // must not panic
	assert.Len(t, fields, 5)
}

func TestAssessChip_MRZMismatchUntrusted(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	c := &Client{chip: emrtd.NewChecker(&fakeEvaluator{dec: emrtd.TrustDecision{Trusted: true, CSCASHA256: "cafe"}}, false)}
	scan := &facetec.ScanResult{IDScan: facetec.IDScanResult{
		ChipRaw: chip.Raw,
		DocumentData: facetec.DocumentData{
			DocumentNumber: "SOMETHINGELSE", DateOfBirth: chip.DateOfBirth, DateOfExpiry: chip.DateOfExpiry,
		},
	}}
	require.Nil(t, c.assessChip(t.Context(), scan), "not required: left to policy")
	assert.False(t, scan.IDScan.ChipTrusted)
	assert.Equal(t, emrtd.ReasonMRZMismatch, scan.IDScan.ChipTrustReason)
}

func TestSubmitIDScan_LegacyPathNeverChipTrusted(t *testing.T) {
	c, livenessID := newTestClientForIDScan(t, `{
		"success": true, "faceMatchLevel": 7, "nfcVerified": true, "mrzVerified": true, "barcodeVerified": true,
		"documentData": {"documentType": "passport"}
	}`)
	c.chip = emrtd.NewChecker(&fakeEvaluator{}, true)
	tc := &tenant.Context{ID: "t", Policy: noRulesPolicy(t)}
	_, _, err := c.SubmitIDScan(tenant.WithStdContext(t.Context(), tc), livenessID, &facetec.IDScanRequest{})
	var idvErr *idverrors.Error
	require.True(t, errors.As(err, &idvErr))
	assert.Equal(t, idverrors.CodePolicyRejected, idvErr.Code)
}

func TestNewChipChecker(t *testing.T) {
	assert.True(t, newChipChecker(config.TrustConfig{Required: true}).Required())
	assert.False(t, newChipChecker(config.TrustConfig{}).Required())
	ch := newChipChecker(config.TrustConfig{PDPURL: "http://127.0.0.1:1", Timeout: 50 * time.Millisecond, Required: true})
	chip := emrtdtest.New(emrtdtest.Options{})
	out := ch.Check(t.Context(), chip.Raw, emrtd.Claimed{
		DocumentNumber: chip.DocumentNumber, DateOfBirth: chip.DateOfBirth, DateOfExpiry: chip.DateOfExpiry,
	})
	assert.False(t, out.Trusted)
	assert.Equal(t, emrtd.ReasonPDPError, out.Reason, "unreachable PDP fails closed")
}

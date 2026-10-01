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

// Only FaceTec chip authentication status 4 passes the gate; every other
// status (including 1, no AA/CA on the chip, and the failures 3 and 5) is
// refused before trust is consulted, even for a fully trusted chip.
func TestProcessRequest_ChipAuthStatusNot4IsRefusedBeforeTrust(t *testing.T) {
	for _, status := range []int{0, 1, 2, 3, 5} {
		chip := emrtdtest.New(emrtdtest.Options{})
		pdp := &fakeEvaluator{dec: emrtd.TrustDecision{Trusted: true, CSCASHA256: "aa"}}
		c, ctx := chipClient(t, chipPayload(t, chip, status, true), pdp, false)
		resp := process(t, c, ctx)
		assert.Equal(t, string(idverrors.CodeNFCNotAuthenticated), resp.CredentialIssueErrCode, "status %d", status)
		assert.Equal(t, 0, pdp.calls, "PDP is not consulted without an authenticated chip (status %d)", status)
	}
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

// A chip-less scan (no authentication status) is refused by the NFC gate
// before trust is consulted, whether or not trust.required is set.
func TestProcessRequest_NoChipRefusedByNFCGateBeforeTrust(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	pdp := &fakeEvaluator{}
	c, ctx := chipClient(t, chipPayload(t, chip, 0, false), pdp, true)
	resp := process(t, c, ctx)
	assert.Equal(t, string(idverrors.CodeNFCNotAuthenticated), resp.CredentialIssueErrCode)
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
	assert.Equal(t, idverrors.CodeChipUntrusted, idvErr.Code, "NFC verified by FaceTec alone is chip evidence")
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

func TestAssessChip_RequiredRejectsIncompleteChipEvidence(t *testing.T) {
	cases := map[string]facetec.IDScanResult{
		"status without raw data": {ChipAuthStatus: 4},
		"raw data without SOD":    {ChipRaw: map[string]string{"DG1": "AA=="}},
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			c := &Client{chip: emrtd.NewChecker(&fakeEvaluator{}, true)}
			scan := &facetec.ScanResult{IDScan: id}
			err := c.assessChip(t.Context(), scan)
			require.NotNil(t, err)
			assert.Equal(t, idverrors.CodeChipUntrusted, err.Code)
			assert.False(t, scan.IDScan.ChipTrusted)
		})
	}
}

func TestAssessChip_RequiredAllowsNoChipAtAll(t *testing.T) {
	c := &Client{chip: emrtd.NewChecker(&fakeEvaluator{}, true)}
	require.Nil(t, c.assessChip(t.Context(), &facetec.ScanResult{}))
}

func TestProcessRequest_RequiredStatusWithoutChipDataRejected(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	c, ctx := chipClient(t, chipPayload(t, chip, 4, false), &fakeEvaluator{}, true)
	resp := process(t, c, ctx)
	assert.Equal(t, string(idverrors.CodeChipUntrusted), resp.CredentialIssueErrCode,
		"AUTHENTICATED status with no raw chip data must not dodge trust.required")
}

func TestAssessChip_TrustedPortraitBoundToDG2(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	c := &Client{chip: emrtd.NewChecker(&fakeEvaluator{dec: emrtd.TrustDecision{Trusted: true, CSCASHA256: "cafe"}}, true)}
	scan := &facetec.ScanResult{IDScan: facetec.IDScanResult{
		ChipRaw:      chip.Raw,
		ChipPortrait: "dg2-portrait",
		DocumentData: facetec.DocumentData{
			GivenName: chip.GivenName, FamilyName: chip.FamilyName, DocumentNumber: chip.DocumentNumber,
			DateOfBirth: chip.DateOfBirth, DateOfExpiry: chip.DateOfExpiry, Nationality: "SWE", IssuingCountry: "SWE",
			Portrait: "swapped-crop",
		},
	}}
	require.Nil(t, c.assessChip(t.Context(), scan))
	require.True(t, scan.IDScan.ChipTrusted)
	assert.Equal(t, "dg2-portrait", scan.IDScan.DocumentData.Portrait)

	scan.IDScan.ChipPortrait = ""
	scan.IDScan.DocumentData.Portrait = "swapped-crop"
	require.Nil(t, c.assessChip(t.Context(), scan))
	assert.Empty(t, scan.IDScan.DocumentData.Portrait, "a portrait the SOD does not cover is not issued under a trusted chip")
}

func TestAssessChip_RequiredRejectsMalformedRawData(t *testing.T) {
	c := &Client{chip: emrtd.NewChecker(&fakeEvaluator{}, true)}
	scan := &facetec.ScanResult{IDScan: facetec.IDScanResult{ChipRaw: map[string]string{"SOD": ""}}}
	err := c.assessChip(t.Context(), scan)
	require.NotNil(t, err)
	assert.Equal(t, idverrors.CodeChipUntrusted, err.Code)
}

// Status 4 passes the NFC gate; with trust.required, missing raw chip data
// (nothing for passive authentication) is then refused as chip_untrusted.
func TestProcessRequest_Status4WithoutRawChipDataRefusedWhenRequired(t *testing.T) {
	chip := emrtdtest.New(emrtdtest.Options{})
	pdp := &fakeEvaluator{}
	c, ctx := chipClient(t, chipPayload(t, chip, 4, false), pdp, true)
	resp := process(t, c, ctx)
	assert.Equal(t, string(idverrors.CodeChipUntrusted), resp.CredentialIssueErrCode)
	assert.Equal(t, 0, pdp.calls)
}

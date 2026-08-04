package apiv1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/idverrors"
	"github.com/sirosfoundation/facetec-api/internal/policy"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

// facetecServerStub returns an httptest.Server standing in for the FaceTec
// Server's /process-request endpoint, always replying with the given raw
// JSON body.
func facetecServerStub(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// nfcSkippedPayload is a complete idScanResultsSoFar response where the user
// declined the NFC chip read: nfcStatusEnumInt=2
// (NFC_REQUESTED_BUT_USER_PRESSED_SKIP), nfcAuthenticationStatusEnumInt=0 --
// the exact combination confirmed against a live FaceTec Server response
// (see internal/facetec/process_request_test.go).
const nfcSkippedPayload = `{
	"idScanResultsSoFar": {
		"photoIDNextStepEnumInt": 4,
		"matchLevel": 7,
		"nfcStatusEnumInt": 2,
		"nfcAuthenticationStatusEnumInt": 0,
		"mrzStatusEnumInt": 2,
		"barcodeStatusEnumInt": 3,
		"documentData": {
			"givenName": "Alice",
			"familyName": "Test",
			"documentType": "passport"
		}
	}
}`

// nfcCompletedPayload is the same scan but with a successfully read and
// authenticated NFC chip (nfcStatusEnumInt=4, nfcAuthenticationStatusEnumInt=4).
const nfcCompletedPayload = `{
	"idScanResultsSoFar": {
		"photoIDNextStepEnumInt": 4,
		"matchLevel": 7,
		"nfcStatusEnumInt": 4,
		"nfcAuthenticationStatusEnumInt": 4,
		"mrzStatusEnumInt": 2,
		"barcodeStatusEnumInt": 3,
		"documentData": {
			"givenName": "Alice",
			"familyName": "Test",
			"documentType": "passport"
		}
	}
}`

func newTestClientForProcessRequest(t *testing.T, facetecBody string) *Client {
	t.Helper()
	ft := facetecServerStub(t, facetecBody)
	return &Client{
		cfg: &config.Config{},
		log: zap.NewNop(),
		ft:  facetec.NewClient(ft.URL, "", http.DefaultClient),
	}
}

// noRulesPolicy returns a policy.Engine with no rules loaded, which
// therefore rejects every scan it evaluates -- useful for proving that
// execution reached policy evaluation at all, without needing a real,
// permissive rule set or a working issuer backend.
func noRulesPolicy(t *testing.T) *policy.Engine {
	t.Helper()
	e, err := policy.New("")
	require.NoError(t, err)
	return e
}

// TestProcessRequest_NFCSkipped_RejectsWithoutIssuing verifies the hard gate
// added for skipped NFC reads: issuance must never be attempted, and the
// response must carry CodeNFCSkipped rather than falling through to policy
// evaluation. tc.Policy is deliberately the always-rejecting noRulesPolicy --
// if the gate did NOT fire first, the error code would be CodePolicyRejected
// instead, so this test also proves ordering.
func TestProcessRequest_NFCSkipped_RejectsWithoutIssuing(t *testing.T) {
	c := newTestClientForProcessRequest(t, nfcSkippedPayload)
	tc := &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)}
	ctx := tenant.WithStdContext(t.Context(), tc)

	resp, err := c.ProcessRequest(ctx, &facetec.ProcessRequestRequest{RequestBlob: "opaque"})
	require.NoError(t, err)

	assert.Equal(t, string(idverrors.CodeNFCSkipped), resp.CredentialIssueErrCode)
	assert.NotEmpty(t, resp.CredentialIssueError)
	assert.Empty(t, resp.TransactionID, "no document should have been issued")
	assert.Empty(t, resp.CredentialOfferURL)
}

// TestProcessRequest_NFCCompleted_DoesNotTriggerSkipGate is the inverse
// check: a scan with NFC successfully read must not be rejected by the skip
// gate. tc.Policy is the always-rejecting noRulesPolicy, so the scan is
// still ultimately rejected -- but by CodePolicyRejected, proving the skip
// gate was correctly bypassed rather than incorrectly firing.
func TestProcessRequest_NFCCompleted_DoesNotTriggerSkipGate(t *testing.T) {
	c := newTestClientForProcessRequest(t, nfcCompletedPayload)
	tc := &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)}
	ctx := tenant.WithStdContext(t.Context(), tc)

	resp, err := c.ProcessRequest(ctx, &facetec.ProcessRequestRequest{RequestBlob: "opaque"})
	require.NoError(t, err)

	assert.Equal(t, string(idverrors.CodePolicyRejected), resp.CredentialIssueErrCode)
	assert.NotEqual(t, string(idverrors.CodeNFCSkipped), resp.CredentialIssueErrCode)
}

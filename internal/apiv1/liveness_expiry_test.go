package apiv1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/idverrors"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

// livenessStepPayload is the shape FaceTec Server 10 returns for a session's
// liveness step (taken from a live response): no idScanResultsSoFar yet, and
// the verdict in result.livenessProven.
func livenessStepPayload(proven bool) string {
	if proven {
		return `{"success": true, "result": {"livenessProven": true, "ageV2GroupEnumInt": 3}, "responseBlob": "rb"}`
	}
	return `{"success": false, "result": {"livenessProven": false}, "responseBlob": "rb"}`
}

// sequenceServerStub stands in for FaceTec Server, answering successive
// /process-request calls with successive bodies (the last one repeats).
func sequenceServerStub(t *testing.T, bodies ...string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		body := bodies[min(i, len(bodies)-1)]
		i++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sessionClient(t *testing.T, bodies ...string) (*Client, context.Context) {
	t.Helper()
	c := newTestClientForProcessRequest(t, bodies[0])
	c.ft = facetec.NewClient(sequenceServerStub(t, bodies...).URL, "", http.DefaultClient)
	tc := &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)}
	return c, tenant.WithStdContext(t.Context(), tc)
}

func step(t *testing.T, c *Client, ctx context.Context, ref string) *facetec.ProcessRequestResponse {
	t.Helper()
	resp, err := c.ProcessRequest(ctx, &facetec.ProcessRequestRequest{RequestBlob: "opaque", ExternalDatabaseRefID: ref})
	require.NoError(t, err)
	assert.Empty(t, resp.TransactionID, "nothing may be issued in these tests")
	return resp
}

// A session whose liveness step FaceTec Server proved reaches the policy
// (which, being empty, rejects): the liveness gate let it through.
func TestProcessRequest_LivenessProvenEarlierInSession_PassesGate(t *testing.T) {
	c, ctx := sessionClient(t, livenessStepPayload(true), nfcCompletedPayload)

	first := step(t, c, ctx, "session-1")
	assert.Empty(t, first.CredentialIssueErrCode, "the liveness step itself is not evaluated")

	final := step(t, c, ctx, "session-1")
	assert.Equal(t, string(idverrors.CodePolicyRejected), final.CredentialIssueErrCode)
}

func TestProcessRequest_LivenessNotProven_Rejected(t *testing.T) {
	t.Run("liveness step reported not proven", func(t *testing.T) {
		c, ctx := sessionClient(t, livenessStepPayload(false), nfcCompletedPayload)
		step(t, c, ctx, "session-1")
		assert.Equal(t, string(idverrors.CodeLivenessFailed), step(t, c, ctx, "session-1").CredentialIssueErrCode)
	})

	t.Run("no liveness step in this session", func(t *testing.T) {
		c, ctx := sessionClient(t, nfcCompletedPayload)
		assert.Equal(t, string(idverrors.CodeLivenessFailed), step(t, c, ctx, "session-1").CredentialIssueErrCode)
	})

	t.Run("liveness proven in another session", func(t *testing.T) {
		c, ctx := sessionClient(t, livenessStepPayload(true), nfcCompletedPayload)
		step(t, c, ctx, "session-A")
		assert.Equal(t, string(idverrors.CodeLivenessFailed), step(t, c, ctx, "session-B").CredentialIssueErrCode)
	})

	t.Run("no externalDatabaseRefID ties the request to a session", func(t *testing.T) {
		c, ctx := sessionClient(t, livenessStepPayload(true), nfcCompletedPayload)
		step(t, c, ctx, "")
		assert.Equal(t, string(idverrors.CodeLivenessFailed), step(t, c, ctx, "").CredentialIssueErrCode)
	})

	t.Run("liveness proven for the same ref under another tenant", func(t *testing.T) {
		c, ctx := sessionClient(t, livenessStepPayload(true), nfcCompletedPayload)
		other := tenant.WithStdContext(t.Context(), &tenant.Context{ID: "other-tenant", Policy: noRulesPolicy(t)})
		step(t, c, other, "session-1")
		assert.Equal(t, string(idverrors.CodeLivenessFailed), step(t, c, ctx, "session-1").CredentialIssueErrCode)
	})

	t.Run("a proof is used up by the session's final result", func(t *testing.T) {
		c, ctx := sessionClient(t, livenessStepPayload(true), nfcCompletedPayload)
		step(t, c, ctx, "session-1")
		assert.Equal(t, string(idverrors.CodePolicyRejected), step(t, c, ctx, "session-1").CredentialIssueErrCode)
		assert.Equal(t, string(idverrors.CodeLivenessFailed), step(t, c, ctx, "session-1").CredentialIssueErrCode)
	})
}

// The liveness gate runs before every other gate: without proven liveness,
// nothing else about the scan matters.
func TestProcessRequest_LivenessGateRunsFirst(t *testing.T) {
	c, ctx := sessionClient(t, nfcSkippedPayload)
	assert.Equal(t, string(idverrors.CodeLivenessFailed), step(t, c, ctx, "session-1").CredentialIssueErrCode)
}

func expiryPayload(expiry string) string {
	return `{
	"idScanResultsSoFar": {
		"photoIDNextStepEnumInt": 4,
		"matchLevel": 7,
		"nfcStatusEnumInt": 4,
		"nfcAuthenticationStatusEnumInt": 4,
		"mrzStatusEnumInt": 2,
		"barcodeStatusEnumInt": 3,
		"documentData": {"givenName": "Alice", "familyName": "Test", "documentType": "passport", "dateOfExpiry": "` + expiry + `"}
	}
}`
}

func TestProcessRequest_DocumentExpiry(t *testing.T) {
	cases := []struct {
		name   string
		expiry string
		want   idverrors.Code
	}{
		{"expired", "2020-01-31", idverrors.CodeDocumentExpired},
		{"missing expiry date", "", idverrors.CodeDocumentUnreadable},
		{"unreadable expiry date", "soon", idverrors.CodeDocumentUnreadable},
		// A valid document passes the gate and reaches the (empty, rejecting) policy.
		{"valid", "2099-12-31", idverrors.CodePolicyRejected},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClientForProcessRequest(t, expiryPayload(tt.expiry))
			ctx := tenant.WithStdContext(t.Context(), &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)})
			resp, err := c.ProcessRequest(ctx, provenSession(t, c, ctx))
			require.NoError(t, err)
			assert.Equal(t, string(tt.want), resp.CredentialIssueErrCode)
			assert.Empty(t, resp.TransactionID)
		})
	}
}

// The chip gate runs before the expiry gate, so the expiry date that is
// checked comes from a document whose chip was authenticated.
func TestProcessRequest_ExpiryGateAfterChipGate(t *testing.T) {
	payload := `{
	"idScanResultsSoFar": {
		"photoIDNextStepEnumInt": 4, "matchLevel": 7,
		"nfcStatusEnumInt": 2, "nfcAuthenticationStatusEnumInt": 0,
		"mrzStatusEnumInt": 2, "barcodeStatusEnumInt": 3,
		"documentData": {"documentType": "passport", "dateOfExpiry": "2020-01-31"}
	}
}`
	c := newTestClientForProcessRequest(t, payload)
	ctx := tenant.WithStdContext(t.Context(), &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)})
	resp, err := c.ProcessRequest(ctx, provenSession(t, c, ctx))
	require.NoError(t, err)
	assert.Equal(t, string(idverrors.CodeNFCSkipped), resp.CredentialIssueErrCode)
}

func TestDocumentExpiryRejection(t *testing.T) {
	now := time.Date(2026, 10, 4, 13, 0, 0, 0, time.UTC)
	cases := []struct {
		expiry   string
		rejected bool
		code     idverrors.Code
	}{
		{"2026-10-03", true, idverrors.CodeDocumentExpired},
		{"2026-10-04", false, ""}, // valid through its expiry date
		{"2026-10-05", false, ""},
		{"", true, idverrors.CodeDocumentUnreadable},
		{"04-10-2026", true, idverrors.CodeDocumentUnreadable},
	}
	for _, tt := range cases {
		code, msg, rejected := documentExpiryRejection(zap.NewNop(), facetec.DocumentData{DateOfExpiry: tt.expiry}, now)
		assert.Equal(t, tt.rejected, rejected, "expiry %q", tt.expiry)
		assert.Equal(t, tt.code, code, "expiry %q", tt.expiry)
		if rejected {
			assert.NotEmpty(t, msg)
		}
	}

	// The comparison is in UTC: just after midnight UTC on the day after
	// expiry, the document has expired, whatever the server's time zone.
	amsterdam := time.FixedZone("CEST", 2*60*60)
	_, _, rejected := documentExpiryRejection(zap.NewNop(), facetec.DocumentData{DateOfExpiry: "2026-10-03"}, time.Date(2026, 10, 4, 1, 30, 0, 0, amsterdam))
	assert.False(t, rejected, "01:30 CEST on the 4th is still the 3rd in UTC")
	_, _, rejected = documentExpiryRejection(zap.NewNop(), facetec.DocumentData{DateOfExpiry: "2026-10-03"}, time.Date(2026, 10, 4, 2, 30, 0, 0, amsterdam))
	assert.True(t, rejected, "02:30 CEST on the 4th is the 4th in UTC")
}

func TestSubmitIDScan_ExpiredDocument_Rejected(t *testing.T) {
	c, livenessID := newTestClientForIDScan(t, `{
		"success": true,
		"faceMatchLevel": 7,
		"nfcVerified": true,
		"mrzVerified": true,
		"barcodeVerified": true,
		"documentData": {"givenName": "Alice", "familyName": "Test", "documentType": "passport", "dateOfExpiry": "2020-01-31"}
	}`)
	ctx := tenant.WithStdContext(t.Context(), &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)})

	docID, offerURL, err := c.SubmitIDScan(ctx, livenessID, &facetec.IDScanRequest{})
	require.Error(t, err)
	var idvErr *idverrors.Error
	require.True(t, errors.As(err, &idvErr))
	assert.Equal(t, idverrors.CodeDocumentExpired, idvErr.Code)
	assert.Empty(t, docID)
	assert.Empty(t, offerURL)
}

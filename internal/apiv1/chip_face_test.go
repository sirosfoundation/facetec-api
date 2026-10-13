package apiv1

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/idverrors"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

func intPtr(v int) *int { return &v }

func TestChipFaceRejection(t *testing.T) {
	cases := []struct {
		name     string
		level    *int
		min      int
		rejected bool
	}{
		{"not reported", nil, 6, true},
		{"below the minimum", intPtr(5), 6, true},
		{"at the minimum", intPtr(6), 6, false},
		{"above the minimum", intPtr(9), 6, false},
		{"reported as 0", intPtr(0), 6, true},
		{"no minimum configured uses the default (6)", intPtr(5), 0, true},
		{"no minimum configured, at the default", intPtr(6), 0, false},
		{"stricter configured minimum", intPtr(7), 8, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			code, msg, rejected := chipFaceRejection(facetec.IDScanResult{ChipFaceMatchLevel: tt.level}, tt.min)
			assert.Equal(t, tt.rejected, rejected)
			if tt.rejected {
				assert.Equal(t, idverrors.CodeChipPhotoMismatch, code)
				assert.NotEmpty(t, msg)
			}
		})
	}
}

// completedScan is a /process-request final response with an authenticated
// chip, an unexpired document and the given face matches.
func completedScan(printedMatch int, chipMatch string) string {
	chipField := ""
	if chipMatch != "" {
		chipField = fmt.Sprintf(`"matchLevelNFCToFaceMap": %s,`, chipMatch)
	}
	return fmt.Sprintf(`{
	"idScanResultsSoFar": {
		"photoIDNextStepEnumInt": 4,
		"matchLevel": %d,
		%s
		"nfcStatusEnumInt": 4,
		"nfcAuthenticationStatusEnumInt": 4,
		"mrzStatusEnumInt": 2,
		"barcodeStatusEnumInt": 3,
		"documentData": {"givenName": "Alice", "familyName": "Test", "documentType": "passport", "dateOfExpiry": "2099-12-31"}
	}
}`, printedMatch, chipField)
}

// A genuine document whose printed photo was replaced by the user's own: the
// printed-photo match is excellent, the chip is authentic, but the face does
// not match the chip photo. Nothing may be issued.
func TestProcessRequest_PhotoSubstitution_Refused(t *testing.T) {
	c := newTestClientForProcessRequest(t, completedScan(9, "2"))
	ctx := tenant.WithStdContext(t.Context(), &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)})

	resp, err := c.ProcessRequest(ctx, provenSession(t, c, ctx))
	require.NoError(t, err)
	assert.Equal(t, string(idverrors.CodeChipPhotoMismatch), resp.CredentialIssueErrCode)
	assert.Empty(t, resp.TransactionID)
}

func TestProcessRequest_ChipFaceMatch(t *testing.T) {
	cases := []struct {
		name      string
		chipMatch string
		minLevel  int
		want      idverrors.Code
	}{
		{"not reported", "", 0, idverrors.CodeChipPhotoMismatch},
		{"below the default minimum", "5", 0, idverrors.CodeChipPhotoMismatch},
		// Passing the gate reaches the (empty, rejecting) policy.
		{"at the default minimum", "6", 0, idverrors.CodePolicyRejected},
		{"configured stricter minimum", "7", 8, idverrors.CodeChipPhotoMismatch},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClientForProcessRequest(t, completedScan(9, tt.chipMatch))
			c.cfg.FaceTec.MinChipFaceMatchLevel = tt.minLevel
			ctx := tenant.WithStdContext(t.Context(), &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)})

			resp, err := c.ProcessRequest(ctx, provenSession(t, c, ctx))
			require.NoError(t, err)
			assert.Equal(t, string(tt.want), resp.CredentialIssueErrCode)
		})
	}
}

// The NFC gate runs first: a scan without a chip read is refused for that,
// not for the missing chip face match it implies.
func TestProcessRequest_ChipFaceGateAfterNFCGate(t *testing.T) {
	c := newTestClientForProcessRequest(t, nfcSkippedPayload)
	ctx := tenant.WithStdContext(t.Context(), &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)})

	resp, err := c.ProcessRequest(ctx, provenSession(t, c, ctx))
	require.NoError(t, err)
	assert.Equal(t, string(idverrors.CodeNFCSkipped), resp.CredentialIssueErrCode)
}

func TestSubmitIDScan_ChipFaceMatch(t *testing.T) {
	for _, tt := range []struct {
		name      string
		chipMatch string
		want      idverrors.Code
	}{
		{"not reported", "", idverrors.CodeChipPhotoMismatch},
		{"below the minimum", `"matchLevelNFCToFaceMap": 3,`, idverrors.CodeChipPhotoMismatch},
		{"passes, reaches the policy", `"matchLevelNFCToFaceMap": 8,`, idverrors.CodePolicyRejected},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, livenessID := newTestClientForIDScan(t, `{
				"success": true,
				"faceMatchLevel": 9,
				`+tt.chipMatch+`
				"nfcVerified": true,
				"mrzVerified": true,
				"barcodeVerified": true,
				"documentData": {"givenName": "Alice", "familyName": "Test", "documentType": "passport", "dateOfExpiry": "2099-12-31"}
			}`)
			ctx := tenant.WithStdContext(t.Context(), &tenant.Context{ID: "test-tenant", Policy: noRulesPolicy(t)})

			_, _, err := c.SubmitIDScan(ctx, livenessID, &facetec.IDScanRequest{})
			var idvErr *idverrors.Error
			require.True(t, errors.As(err, &idvErr), "got %v", err)
			assert.Equal(t, tt.want, idvErr.Code)
		})
	}
}

package apiv1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

func TestDocumentLogging(t *testing.T) {
	doc := facetec.DocumentData{
		GivenName: "SyntheticGivenName", FamilyName: "SyntheticFamilyName",
		DocumentNumber: "TEST-DOC-123", DateOfBirth: "1980-01-02",
		DateOfExpiry: "2099-12-31", MRZLine1: "SYNTHETIC-MRZ-LINE",
		DocumentType: "passport", Portrait: "synthetic-face-image",
	}
	docJSON, err := json.Marshal(doc)
	require.NoError(t, err)

	for _, path := range []string{"id-scan", "process-request"} {
		for _, tt := range []struct {
			name    string
			level   zapcore.Level
			include bool
			wantPII bool
		}{
			{"debug default", zap.DebugLevel, false, false},
			{"debug opt-in", zap.DebugLevel, true, true},
			{"info opt-in", zap.InfoLevel, true, false},
			{"warn opt-in", zap.WarnLevel, true, false},
			{"error opt-in", zap.ErrorLevel, true, false},
		} {
			t.Run(path+"/"+tt.name, func(t *testing.T) {
				var c *Client
				var livenessID string
				if path == "id-scan" {
					c, livenessID = newTestClientForIDScan(t, fmt.Sprintf(
						`{"success":true,"nfcVerified":false,"documentData":%s}`, docJSON))
					t.Cleanup(c.sessions.Close)
				} else {
					c = newTestClientForProcessRequest(t, fmt.Sprintf(
						`{"idScanResultsSoFar":{"photoIDNextStepEnumInt":4,"matchLevel":7,"documentData":%s}}`, docJSON))
				}
				c.cfg.Logging.IncludePII = tt.include
				var output bytes.Buffer
				c.log = zap.New(zapcore.NewCore(
					zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
					zapcore.AddSync(&output), tt.level,
				))
				ctx := tenant.WithStdContext(t.Context(), &tenant.Context{ID: "test-tenant"})
				if path == "id-scan" {
					_, _, err := c.SubmitIDScan(ctx, livenessID, &facetec.IDScanRequest{})
					require.Error(t, err, "NFC gate remains enforced")
				} else {
					resp, err := c.ProcessRequest(ctx, &facetec.ProcessRequestRequest{RequestBlob: "opaque"})
					require.NoError(t, err)
					assert.NotEmpty(t, resp.CredentialIssueErrCode, "liveness gate remains enforced")
				}
				logs := output.String()
				for _, pii := range []string{doc.GivenName, doc.FamilyName, doc.DocumentNumber, doc.DateOfBirth, doc.DateOfExpiry, doc.MRZLine1} {
					if tt.wantPII {
						assert.Contains(t, logs, pii)
					} else {
						assert.NotContains(t, logs, pii)
					}
				}
				assert.NotContains(t, logs, doc.Portrait, "portraits must never be logged")
				if tt.wantPII {
					assert.Contains(t, logs, fmt.Sprintf("[%d bytes omitted]", len(doc.Portrait)))
				}
				assert.Equal(t, tt.wantPII, bytes.Contains(output.Bytes(), []byte("document_data")))
			})
		}
	}
}

func TestLogDocumentData_DoesNotMutateDocument(t *testing.T) {
	doc := facetec.DocumentData{GivenName: "SyntheticName", Portrait: "synthetic-face-image"}
	original := doc
	var output bytes.Buffer
	c := newTestClientForProcessRequest(t, `{}`)
	c.cfg.Logging.IncludePII = true
	c.log = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&output), zap.DebugLevel))
	c.logDocumentData("test document data", "test-tenant", doc)
	assert.Equal(t, original, doc)
	assert.NotContains(t, output.String(), doc.Portrait)
}

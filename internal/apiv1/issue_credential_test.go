package apiv1

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/issuerclient"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

// TestIssueCredential_RequestShape verifies that issueCredential sends
// correctly shaped requests to the vc-apigw upload and preauth_offer endpoints.
func TestIssueCredential_RequestShape(t *testing.T) {
	var uploadBody map[string]any
	var preauthBody map[string]any
	var uploadPath, preauthPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		switch r.URL.Path {
		case "/api/v1/datastore":
			uploadPath = r.URL.Path
			require.NoError(t, json.Unmarshal(body, &uploadBody))
			w.WriteHeader(http.StatusOK)

		case "/api/v1/datastore/preauth_offer":
			preauthPath = r.URL.Path
			require.NoError(t, json.Unmarshal(body, &preauthBody))
			w.Header().Set("Content-Type", "application/json")
			resp := issuerclient.PreauthOfferReply{
				CredentialOfferURL: "openid-credential-offer://?test=1",
			}
			require.NoError(t, json.NewEncoder(w).Encode(resp))

		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	issuerClient, err := issuerclient.New(issuerclient.Config{
		BaseURL: srv.URL,
	})
	require.NoError(t, err)

	c := &Client{
		cfg: &config.Config{
			Issuer: config.IssuerConfig{
				AuthenticSource: "test-source",
			},
		},
		log:    zap.NewNop(),
		issuer: issuerClient,
	}

	scanResult := facetec.ScanResult{
		IDScan: facetec.IDScanResult{
			DocumentData: facetec.DocumentData{
				GivenName:  "Alice",
				FamilyName: "Test",
			},
		},
	}
	issuerParams := tenant.IssuerParams{
		Scope:  "test-scope",
		Format: "sdjwt",
	}

	docID, offerURL, err := c.issueCredential(t.Context(), scanResult, issuerParams)
	require.NoError(t, err)

	// Upload request shape
	assert.Equal(t, "/api/v1/datastore", uploadPath)
	meta := uploadBody["meta"].(map[string]any)
	assert.Equal(t, "test-source", meta["authentic_source"])
	assert.Equal(t, "test-scope", meta["scope"])
	assert.Equal(t, docID, meta["document_id"])

	// identity_mapping_ids must be present and contain the document ID
	ids := uploadBody["identity_mapping_ids"].([]any)
	require.Len(t, ids, 1)
	assert.Equal(t, docID, ids[0])

	// document_data must be present
	dd := uploadBody["document_data"].(map[string]any)
	assert.Equal(t, "Alice", dd["given_name"])

	// Fields that must NOT be present (removed from contract)
	assert.NotContains(t, meta, "vct")
	assert.NotContains(t, meta, "document_version")
	assert.NotContains(t, meta, "real_data")
	assert.NotContains(t, uploadBody, "document_data_version")

	// Preauth offer request shape
	assert.Equal(t, "/api/v1/datastore/preauth_offer", preauthPath)
	assert.Equal(t, "test-source", preauthBody["authentic_source"])
	assert.Equal(t, "test-scope", preauthBody["scope"])
	assert.Equal(t, docID, preauthBody["document_id"])

	// Credential offer URL returned
	assert.Equal(t, "openid-credential-offer://?test=1", offerURL)
}

// TestIssueCredential_DefaultAuthenticSource verifies the fallback when
// AuthenticSource is not configured.
func TestIssueCredential_DefaultAuthenticSource(t *testing.T) {
	var uploadBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/api/v1/datastore":
			_ = json.Unmarshal(body, &uploadBody)
			w.WriteHeader(http.StatusOK)
		case "/api/v1/datastore/preauth_offer":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(issuerclient.PreauthOfferReply{
				CredentialOfferURL: "openid-credential-offer://?x=1",
			})
		}
	}))
	defer srv.Close()

	issuerClient, err := issuerclient.New(issuerclient.Config{BaseURL: srv.URL})
	require.NoError(t, err)

	c := &Client{
		cfg:    &config.Config{},
		log:    zap.NewNop(),
		issuer: issuerClient,
	}

	_, _, err = c.issueCredential(t.Context(), facetec.ScanResult{}, tenant.IssuerParams{Scope: "s"})
	require.NoError(t, err)

	meta := uploadBody["meta"].(map[string]any)
	assert.Equal(t, "facetec-api", meta["authentic_source"])
}

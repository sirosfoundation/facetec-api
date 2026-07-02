package issuerclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL})
	require.NoError(t, err)
	return c
}

func TestUpload_NilMeta(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("should not reach server")
	}))

	err := c.Upload(t.Context(), &UploadRequest{
		Meta:               nil,
		IdentityMappingIDs: []string{"id-1"},
		DocumentData:       map[string]any{"k": "v"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "meta is required")
}

func TestUpload_EmptyIdentityMappingIDs(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("should not reach server")
	}))

	err := c.Upload(t.Context(), &UploadRequest{
		Meta:               &MetaData{AuthenticSource: "src", Scope: "s", DocumentID: "d"},
		IdentityMappingIDs: nil,
		DocumentData:       map[string]any{"k": "v"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity_mapping_id is required")
}

func TestUpload_Success(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/datastore", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))

	err := c.Upload(t.Context(), &UploadRequest{
		Meta:               &MetaData{AuthenticSource: "src", Scope: "s", DocumentID: "d"},
		IdentityMappingIDs: []string{"id-1"},
		DocumentData:       map[string]any{"k": "v"},
	})
	require.NoError(t, err)
}

// --- New ---

func TestNew_EmptyBaseURL(t *testing.T) {
	_, err := New(Config{BaseURL: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base URL is required")
}

func TestNew_TrailingSlashStripped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL + "/"})
	require.NoError(t, err)
	assert.False(t, strings.HasSuffix(c.baseURL, "/"))
}

// --- PreauthOffer ---

func TestPreauthOffer_Success(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/datastore/preauth_offer", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PreauthOfferReply{
			CredentialOfferURL: "openid-credential-offer://?x=1",
		})
	}))

	reply, err := c.PreauthOffer(t.Context(), &PreauthOfferRequest{
		AuthenticSource: "src", Scope: "s", DocumentID: "d",
	})
	require.NoError(t, err)
	assert.Equal(t, "openid-credential-offer://?x=1", reply.CredentialOfferURL)
}

func TestPreauthOffer_ServerError(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))

	_, err := c.PreauthOffer(t.Context(), &PreauthOfferRequest{
		AuthenticSource: "src", Scope: "s", DocumentID: "d",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// --- Close ---

func TestClose(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	require.NoError(t, c.Close())
}

// --- post internals ---

func TestPost_SetsAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, APIKey: "test-key"})
	require.NoError(t, err)

	err = c.Upload(t.Context(), &UploadRequest{
		Meta:               &MetaData{AuthenticSource: "s", Scope: "s", DocumentID: "d"},
		IdentityMappingIDs: []string{"id"},
		DocumentData:       map[string]any{},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer test-key", gotAuth)
}

func TestPost_ServerErrorTruncatesBody(t *testing.T) {
	longBody := strings.Repeat("x", 300)
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(longBody))
	}))

	err := c.Upload(t.Context(), &UploadRequest{
		Meta:               &MetaData{AuthenticSource: "s", Scope: "s", DocumentID: "d"},
		IdentityMappingIDs: []string{"id"},
		DocumentData:       map[string]any{},
	})
	require.Error(t, err)
	// Error message should contain truncated body (200 chars + "...")
	assert.Contains(t, err.Error(), "...")
}

// --- truncate ---

func TestTruncate_Short(t *testing.T) {
	assert.Equal(t, "abc", truncate([]byte("abc"), 10))
}

func TestTruncate_Long(t *testing.T) {
	result := truncate([]byte("abcdefghij"), 5)
	assert.Equal(t, "abcde...", result)
}

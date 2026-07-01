package issuerclient

import (
	"net/http"
	"net/http/httptest"
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

package emrtd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleRequest() TrustRequest {
	st := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	return TrustRequest{
		IssuingState: "SWE",
		Chain:        [][]byte{{1, 2, 3}, {4, 5}},
		SigningTime:  &st,
	}
}

func pdpServer(t *testing.T, hits *atomic.Int32, handler http.HandlerFunc) *PDPClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return NewPDPClient(srv.URL, 500*time.Millisecond)
}

func TestPDP_AllowAndRequestShape(t *testing.T) {
	var hits atomic.Int32
	var got map[string]any
	p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/evaluation", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte(`{"decision":true,"context":{"reason":{"admin":{"csca_sha256":"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB","csca_subject":"C=SE, CN=CSCA","dsc_sha256":"EF01"}}}}`))
	})
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	require.NoError(t, err)
	assert.True(t, d.Trusted)
	assert.Equal(t, strings.Repeat("ab", 32), d.CSCASHA256)
	assert.Equal(t, "C=SE, CN=CSCA", d.CSCASubject)
	assert.Equal(t, "ef01", d.DSCSHA256)
	assert.EqualValues(t, 1, hits.Load())

	assert.Equal(t, map[string]any{"type": "key", "id": "SWE"}, got["subject"])
	res := got["resource"].(map[string]any)
	assert.Equal(t, "x5c", res["type"])
	assert.Equal(t, "SWE", res["id"])
	assert.Equal(t, []any{base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), base64.StdEncoding.EncodeToString([]byte{4, 5})}, res["key"])
	assert.Equal(t, "emrtd-document-signer", got["action"].(map[string]any)["name"])
	assert.Equal(t, map[string]any{"signing_time": "2026-09-30T10:00:00Z"}, got["context"])
}

func TestPDP_NoSigningTimeOmitsContext(t *testing.T) {
	var hits atomic.Int32
	var got map[string]any
	p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte(`{"decision":false}`))
	})
	req := sampleRequest()
	req.SigningTime = nil
	_, err := p.EvaluateDSC(t.Context(), req)
	require.NoError(t, err)
	_, has := got["context"]
	assert.False(t, has)
}

func TestPDP_Deny(t *testing.T) {
	var hits atomic.Int32
	p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"decision":false,"context":{"reason":{"admin":{"code":"No_Anchor!"}}}}`))
	})
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	require.NoError(t, err)
	assert.False(t, d.Trusted)
	assert.Equal(t, "no_anchor", d.Code, "codes are sanitised")
}

func TestPDP_DenyCodeFromUserReason(t *testing.T) {
	var hits atomic.Int32
	p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"decision":false,"context":{"reason":{"user":{"code":"expired"}}}}`))
	})
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	require.NoError(t, err)
	assert.Equal(t, "expired", d.Code)
}

func TestPDP_CodeIsTruncated(t *testing.T) {
	assert.Len(t, sanitizeCode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 40)
}

func TestPDP_AllowWithoutAnchorEvidenceIsMalformed(t *testing.T) {
	var hits atomic.Int32
	p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"decision":true}`))
	})
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	require.ErrorIs(t, err, ErrMalformedResponse)
	assert.False(t, d.Trusted)
}

func TestPDP_MalformedBodyNotRetried(t *testing.T) {
	var hits atomic.Int32
	p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>not json`))
	})
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	require.Error(t, err)
	assert.False(t, d.Trusted)
	assert.EqualValues(t, 1, hits.Load())
}

func TestPDP_EmptyJSONIsDeny(t *testing.T) {
	var hits atomic.Int32
	p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	require.NoError(t, err)
	assert.False(t, d.Trusted)
}

func TestPDP_Non200NotRetried(t *testing.T) {
	var hits atomic.Int32
	p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	require.Error(t, err)
	assert.False(t, d.Trusted)
	assert.EqualValues(t, 1, hits.Load(), "HTTP errors are final, only transport errors are retried")
}

func TestPDP_DownIsRetriedOnceThenFails(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // connection refused

	var attempts atomic.Int32
	p := NewPDPClient(url, 200*time.Millisecond)
	p.client.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return http.DefaultTransport.RoundTrip(r)
	})
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	require.Error(t, err)
	assert.False(t, d.Trusted)
	assert.EqualValues(t, maxAttempts, attempts.Load())
}

func TestPDP_TimeoutFailsClosed(t *testing.T) {
	var hits atomic.Int32
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-done:
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	p := NewPDPClient(srv.URL, 100*time.Millisecond)
	start := time.Now()
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	require.Error(t, err)
	assert.False(t, d.Trusted)
	assert.Less(t, time.Since(start), 2*time.Second, "bounded by the per-attempt timeout")
}

func TestPDP_ContextCancelledDuringRetryBackoff(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	ctx, cancel := context.WithCancel(t.Context())
	p := NewPDPClient(url, time.Second)
	n := 0
	p.client.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		n++
		cancel() // cancelled after the first failed attempt
		return http.DefaultTransport.RoundTrip(r)
	})
	_, err := p.EvaluateDSC(ctx, sampleRequest())
	require.Error(t, err)
	assert.Equal(t, 1, n)
}

func TestPDP_DefaultTimeoutAndEmptyRequest(t *testing.T) {
	p := NewPDPClient("http://127.0.0.1:1", 0)
	assert.Equal(t, defaultTimeout, p.client.HTTPClient.Timeout)
	_, err := p.EvaluateDSC(t.Context(), TrustRequest{})
	assert.Error(t, err)
	_, err = p.EvaluateDSC(t.Context(), TrustRequest{IssuingState: "SWE"})
	assert.Error(t, err)
}

func TestDecisionFrom_Nil(t *testing.T) {
	_, err := decisionFrom(nil)
	assert.ErrorIs(t, err, ErrMalformedResponse)
}

func TestReasonMap_RawMessage(t *testing.T) {
	r := mustResp(t, `{"decision":false,"context":{"reason":{"admin":{"code":"chain_invalid"}}}}`)
	assert.Equal(t, "chain_invalid", firstString(reasonMap(r, "admin"), "code"))
	assert.Nil(t, reasonMap(r, "missing"))
	assert.Nil(t, reasonMap(mustResp(t, `{"decision":false}`), "admin"))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPDP_AllowWithMalformedAnchorFingerprintIsMalformed(t *testing.T) {
	for _, fp := range []string{"x", "abcd", "zz" + strings.Repeat("ab", 31), strings.Repeat("ab", 33)} {
		var hits atomic.Int32
		p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"decision":true,"context":{"reason":{"admin":{"csca_sha256":"` + fp + `"}}}}`))
		})
		d, err := p.EvaluateDSC(t.Context(), sampleRequest())
		require.ErrorIs(t, err, ErrMalformedResponse, fp)
		assert.False(t, d.Trusted)
	}
}

func TestPDP_DenyCodeFromTopLevelReason(t *testing.T) {
	var hits atomic.Int32
	p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"decision":false,"context":{"reason":{"code":"unknown_country","admin":{"detail":"x"}}}}`))
	})
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	require.NoError(t, err)
	assert.False(t, d.Trusted)
	assert.Equal(t, "unknown_country", d.Code)
}

func TestPDP_DoesNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		_, _ = w.Write([]byte(`{"decision":true,"context":{"reason":{"admin":{"csca_sha256":"` + strings.Repeat("ab", 32) + `"}}}}`))
	}))
	t.Cleanup(other.Close)
	var hits atomic.Int32
	p := pdpServer(t, &hits, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/evaluation", http.StatusTemporaryRedirect)
	})
	d, err := p.EvaluateDSC(t.Context(), sampleRequest())
	assert.Error(t, err)
	assert.False(t, d.Trusted)
	assert.Zero(t, elsewhere.Load(), "the redirect target must never be contacted")
}

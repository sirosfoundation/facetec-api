// Package integration contains end-to-end HTTP tests for the facetec-api service.
// They test the full HTTP transport layer — routing, authentication, rate limiting,
// and request/response serialisation — using a stub implementation of the Apiv1
// interface in place of real FaceTec or gRPC backends.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/httpserver"
	"github.com/sirosfoundation/facetec-api/internal/session"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

// ----------------------------------------------------------------------------
// Stub Apiv1 — deterministic, controllable fake for integration tests.
// ----------------------------------------------------------------------------

type stubApiv1 struct {
	mu sync.Mutex

	// Configurable return values.
	processResp *facetec.ProcessRequestResponse
	processErr  error

	redeemEntry *session.OfferEntry
	redeemErr   error
}

func (s *stubApiv1) ProcessRequest(_ context.Context, _ *facetec.ProcessRequestRequest) (*facetec.ProcessRequestResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.processErr != nil {
		return nil, s.processErr
	}
	if s.processResp != nil {
		return s.processResp, nil
	}
	return &facetec.ProcessRequestResponse{
		Payload: map[string]any{
			"responseBlob": "response-blob",
			"result": map[string]any{
				"success": true,
			},
		},
	}, nil
}

func (s *stubApiv1) RedeemOffer(_ context.Context, _ string) (*session.OfferEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.redeemErr != nil {
		return nil, s.redeemErr
	}
	e := s.redeemEntry
	if e == nil {
		e = &session.OfferEntry{
			Credentials: []string{"eyJhbGciOiJFUzI1NiJ9.test"},
			Scope:       "photo-id",
		}
	}
	return e, nil
}

func (s *stubApiv1) Ready() error {
	return nil
}

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

func testConfig(appKey string, rateLimitEnabled bool) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Host: "127.0.0.1",
			Port: 0,
		},
		Session: config.SessionConfig{
			LivenessTTL: 2 * time.Minute,
			OfferTTL:    5 * time.Minute,
		},
		Security: config.SecurityConfig{
			AppKey: appKey,
			RateLimit: config.RateLimitConfig{
				Enabled:           rateLimitEnabled,
				RequestsPerMinute: 2, // very low for rate limit tests
			},
		},
		Logging: config.LoggingConfig{
			Level: "error",
		},
	}
}

func newTestServer(t *testing.T, stub *stubApiv1, appKey string) *httptest.Server {
	t.Helper()
	log := zap.NewNop()
	cfg := testConfig(appKey, false)
	reg, err := tenant.NewRegistry(cfg, log)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	svc := httpserver.New(context.Background(), cfg, stub, reg, log)
	ts := httptest.NewServer(svc.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func newTestServerWithRateLimit(t *testing.T, stub *stubApiv1, appKey string) *httptest.Server {
	t.Helper()
	log := zap.NewNop()
	cfg := testConfig(appKey, true)
	reg, err := tenant.NewRegistry(cfg, log)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	svc := httpserver.New(context.Background(), cfg, stub, reg, log)
	ts := httptest.NewServer(svc.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func postJSON(t *testing.T, ts *httptest.Server, path string, body any, appKey string) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if appKey != "" {
		req.Header.Set("Authorization", "Bearer "+appKey)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func getJSON(t *testing.T, ts *httptest.Server, path string, appKey string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if appKey != "" {
		req.Header.Set("Authorization", "Bearer "+appKey)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Errorf("status: got %d, want %d", resp.StatusCode, want)
	}
}

// ----------------------------------------------------------------------------
// Probe endpoint tests (unauthenticated)
// ----------------------------------------------------------------------------

func TestLivez(t *testing.T) {
	ts := newTestServer(t, &stubApiv1{}, "")
	resp := getJSON(t, ts, "/livez", "")
	assertStatus(t, resp, http.StatusOK)
}

func TestReadyz(t *testing.T) {
	ts := newTestServer(t, &stubApiv1{}, "")
	resp := getJSON(t, ts, "/readyz", "")
	assertStatus(t, resp, http.StatusOK)
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t, &stubApiv1{}, "")
	resp := getJSON(t, ts, "/healthz", "")
	assertStatus(t, resp, http.StatusOK)
}

func TestMetrics_ReturnsPrometheusFormat(t *testing.T) {
	ts := newTestServer(t, &stubApiv1{}, "")
	resp := getJSON(t, ts, "/metrics", "")
	assertStatus(t, resp, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	// Prometheus text format must contain at least one HELP or TYPE line.
	if !strings.Contains(string(body), "# HELP") && !strings.Contains(string(body), "# TYPE") {
		t.Error("expected Prometheus text format with HELP/TYPE lines")
	}
}

// ----------------------------------------------------------------------------
// Auth middleware tests
// ----------------------------------------------------------------------------

func TestHealth_Unauthenticated_Forbidden(t *testing.T) {
	ts := newTestServer(t, &stubApiv1{}, "secret-key")
	resp := getJSON(t, ts, "/v1/health", "")
	assertStatus(t, resp, http.StatusUnauthorized)
}

func TestHealth_WrongKey_Forbidden(t *testing.T) {
	ts := newTestServer(t, &stubApiv1{}, "secret-key")
	resp := getJSON(t, ts, "/v1/health", "wrong-key")
	assertStatus(t, resp, http.StatusUnauthorized)
}

func TestHealth_CorrectKey_OK(t *testing.T) {
	ts := newTestServer(t, &stubApiv1{}, "secret-key")
	resp := getJSON(t, ts, "/v1/health", "secret-key")
	assertStatus(t, resp, http.StatusOK)
}

func TestHealth_NoAuth_OK(t *testing.T) {
	// When AppKey is empty, authentication is disabled.
	ts := newTestServer(t, &stubApiv1{}, "")
	resp := getJSON(t, ts, "/v1/health", "")
	assertStatus(t, resp, http.StatusOK)
}

// ----------------------------------------------------------------------------
// Session token endpoint
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// FaceTec process-request endpoint
// ----------------------------------------------------------------------------

func TestProcessRequest_Success(t *testing.T) {
	stub := &stubApiv1{
		processResp: &facetec.ProcessRequestResponse{
			Payload: map[string]any{
				"responseBlob": "resp-blob",
				"result": map[string]any{
					"success": true,
				},
			},
			TransactionID:      "tx-process-1",
			CredentialOfferURL: "openid-credential-offer://?credential_offer_uri=https://issuer.example.com/credential-offer/test-uuid",
		},
	}
	ts := newTestServer(t, stub, "")

	body := map[string]string{
		"requestBlob":           "req-blob",
		"externalDatabaseRefID": "ext-123",
	}
	resp := postJSON(t, ts, "/process-request", body, "")
	assertStatus(t, resp, http.StatusOK)

	var rBody map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rBody); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got, _ := rBody["responseBlob"].(string); got != "resp-blob" {
		t.Errorf("responseBlob: got %q, want %q", got, "resp-blob")
	}
	if got, _ := rBody["transactionId"].(string); got != "tx-process-1" {
		t.Errorf("transactionId: got %q, want %q", got, "tx-process-1")
	}
	if got, _ := rBody["credentialOfferURI"].(string); got == "" {
		t.Error("expected credentialOfferURI in process-request response")
	}
}

func TestProcessRequest_IssuanceError_PreservedPayload(t *testing.T) {
	stub := &stubApiv1{
		processResp: &facetec.ProcessRequestResponse{
			Payload: map[string]any{
				"responseBlob": "resp-blob",
				"result": map[string]any{
					"success": true,
				},
			},
			CredentialIssueError: "scan rejected by policy",
		},
	}
	ts := newTestServer(t, stub, "")

	resp := postJSON(t, ts, "/v1/process-request", map[string]string{"requestBlob": "req-blob"}, "")
	assertStatus(t, resp, http.StatusOK)

	var rBody map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rBody); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got, _ := rBody["responseBlob"].(string); got != "resp-blob" {
		t.Errorf("responseBlob: got %q, want %q", got, "resp-blob")
	}
	if got, _ := rBody["credentialIssueError"].(string); got != "scan rejected by policy" {
		t.Errorf("credentialIssueError: got %q, want %q", got, "scan rejected by policy")
	}
}

func TestProcessRequest_BackendError_502(t *testing.T) {
	stub := &stubApiv1{processErr: errors.New("facetec unavailable")}
	ts := newTestServer(t, stub, "")

	resp := postJSON(t, ts, "/process-request", map[string]string{"requestBlob": "req-blob"}, "")
	assertStatus(t, resp, http.StatusBadGateway)
}

// ----------------------------------------------------------------------------
// Liveness endpoint
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// ID scan endpoint
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Offer redemption endpoint
// ----------------------------------------------------------------------------

func TestOffer_Success(t *testing.T) {
	stub := &stubApiv1{
		redeemEntry: &session.OfferEntry{
			Credentials: []string{"cred1"},
			Scope:       "photo-id",
		},
	}
	ts := newTestServer(t, stub, "")
	resp := getJSON(t, ts, "/v1/offer/tx-999", "")
	assertStatus(t, resp, http.StatusOK)

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["scope"] != "photo-id" {
		t.Errorf("scope: got %v, want %q", body["scope"], "photo-id")
	}
}

func TestOffer_NotFound_404(t *testing.T) {
	stub := &stubApiv1{redeemErr: errors.New("not found")}
	ts := newTestServer(t, stub, "")
	resp := getJSON(t, ts, "/v1/offer/no-such-tx", "")
	assertStatus(t, resp, http.StatusNotFound)
}

// ----------------------------------------------------------------------------
// Rate limiting test
// ----------------------------------------------------------------------------

func TestRateLimit_BiometricEndpoint(t *testing.T) {
	stub := &stubApiv1{}
	ts := newTestServerWithRateLimit(t, stub, "")

	body := map[string]string{"requestBlob": "opaque"}

	// The rate limit is 2 rpm. The first two requests should succeed;
	// the third should be rate-limited.
	for i := 0; i < 2; i++ {
		resp := postJSON(t, ts, "/v1/process-request", body, "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: got %d, want 200", i+1, resp.StatusCode)
		}
		resp.Body.Close()
	}

	resp := postJSON(t, ts, "/v1/process-request", body, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("third request: got %d, want 429", resp.StatusCode)
	}
}

// ----------------------------------------------------------------------------
// Full biometric flow test
// ----------------------------------------------------------------------------

func TestFullFlow(t *testing.T) {
	stub := &stubApiv1{
		processResp: &facetec.ProcessRequestResponse{
			Payload:            map[string]any{"responseBlob": "response-blob"},
			TransactionID:      "tx-flow",
			CredentialOfferURL: "openid-credential-offer://tx-flow",
		},
		redeemEntry: &session.OfferEntry{
			Credentials: []string{"issued-credential"},
			Scope:       "photo-id",
		},
	}
	ts := newTestServer(t, stub, "")

	// Step 1: the SDK's final process-request returns the credential offer.
	scanResp := postJSON(t, ts, "/v1/process-request", map[string]string{"requestBlob": "opaque"}, "")
	assertStatus(t, scanResp, http.StatusOK)
	var scanRespBody struct {
		TransactionID      string `json:"transactionId"`
		CredentialOfferURI string `json:"credentialOfferURI"`
	}
	if err := json.NewDecoder(scanResp.Body).Decode(&scanRespBody); err != nil {
		t.Fatalf("decode process-request response: %v", err)
	}
	scanResp.Body.Close()
	if scanRespBody.TransactionID == "" {
		t.Fatal("expected non-empty transactionId")
	}
	if scanRespBody.CredentialOfferURI == "" {
		t.Fatal("expected non-empty credentialOfferURI")
	}

	// Step 2: the wallet redeems the offer.
	offerResp := getJSON(t, ts, fmt.Sprintf("/v1/offer/%s", scanRespBody.TransactionID), "")
	assertStatus(t, offerResp, http.StatusOK)
	var offerBody struct {
		Credentials []string `json:"credentials"`
		Scope       string   `json:"scope"`
	}
	if err := json.NewDecoder(offerResp.Body).Decode(&offerBody); err != nil {
		t.Fatalf("decode offer response: %v", err)
	}
	offerResp.Body.Close()
	if len(offerBody.Credentials) == 0 {
		t.Error("expected at least one credential in offer")
	}
	if offerBody.Scope != "photo-id" {
		t.Errorf("scope: got %q, want %q", offerBody.Scope, "photo-id")
	}
}

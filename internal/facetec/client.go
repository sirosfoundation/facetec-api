package facetec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Client wraps the FaceTec Server REST API.
// It never persists any data; all biometric payloads pass through in memory only.
type Client struct {
	serverURL  string
	deviceKey  string
	httpClient *http.Client
}

// NewClient creates a FaceTec Server client.
// serverURL must be the base URL of the FaceTec Server (e.g. "https://facetec.example.org").
// deviceKey is the FaceTec device SDK key used to authenticate requests.
func NewClient(serverURL, deviceKey string, httpClient *http.Client) *Client {
	return &Client{
		serverURL:  serverURL,
		deviceKey:  deviceKey,
		httpClient: httpClient,
	}
}

// GetSessionToken requests a new session token from the FaceTec Server.
func (c *Client) GetSessionToken(ctx context.Context) (*SessionTokenResponse, error) {
	resp, err := c.post(ctx, "/session-token", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facetec: session-token: unexpected status %d", resp.StatusCode)
	}
	var result SessionTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("facetec: session-token: decode response: %w", err)
	}
	return &result, nil
}

// SubmitLiveness forwards a FaceScan to the FaceTec Server for liveness verification.
// The returned LivenessCheckResult.FaceMap must be held in memory only and never written to disk.
func (c *Client) SubmitLiveness(ctx context.Context, req *LivenessCheckRequest) (*LivenessCheckResult, error) {
	resp, err := c.post(ctx, "/liveness-3d", req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facetec: liveness: unexpected status %d", resp.StatusCode)
	}
	var result LivenessCheckResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("facetec: liveness: decode response: %w", err)
	}
	return &result, nil
}

// SubmitIDScan forwards an ID scan to the FaceTec Server for face matching and OCR.
// req.FaceMap must be populated from the in-memory liveness session before calling this method.
func (c *Client) SubmitIDScan(ctx context.Context, req *IDScanRequest) (*IDScanResult, error) {
	resp, err := c.post(ctx, "/match-3d-3d", req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facetec: id-scan: unexpected status %d", resp.StatusCode)
	}
	var result IDScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("facetec: id-scan: decode response: %w", err)
	}
	return &result, nil
}

func (c *Client) post(ctx context.Context, path string, body any) (*http.Response, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, fmt.Errorf("facetec: encode request: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+path, &buf)
	if err != nil {
		return nil, fmt.Errorf("facetec: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Device-Key", c.deviceKey)
	return c.httpClient.Do(req)
}

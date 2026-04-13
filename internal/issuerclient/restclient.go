// Package issuerclient provides an HTTP client for the vc apigw REST API.
//
// It replaces the previous gRPC-based client with calls to the apigw's
// upload and notification endpoints, which handle credential issuance
// and OID4VCI credential offer generation.
package issuerclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config holds connection details for the vc apigw REST API.
type Config struct {
	// BaseURL is the apigw base URL (e.g. "https://didrik.issuer.id.siros.org").
	BaseURL string
	// APIKey is an optional Bearer token for authenticated endpoints.
	APIKey string
	// TLS enables TLS certificate verification settings.
	TLS      bool
	CAFile   string
	CertFile string
	KeyFile  string
	// Timeout for HTTP requests.
	Timeout time.Duration
}

// UploadRequest is the body for POST /api/v1/upload.
type UploadRequest struct {
	Meta                *MetaData      `json:"meta"`
	DocumentData        map[string]any `json:"document_data"`
	DocumentDataVersion string         `json:"document_data_version"`
}

// MetaData matches the vc apigw's metadata model.
type MetaData struct {
	AuthenticSource string `json:"authentic_source"`
	DocumentVersion string `json:"document_version"`
	VCT             string `json:"vct"`
	Scope           string `json:"scope"`
	DocumentID      string `json:"document_id"`
	RealData        bool   `json:"real_data"`
}

// NotificationRequest is the body for POST /api/v1/notification.
type NotificationRequest struct {
	AuthenticSource string `json:"authentic_source"`
	VCT             string `json:"vct"`
	DocumentID      string `json:"document_id"`
}

// NotificationReply holds the credential offer data returned by /api/v1/notification.
type NotificationReply struct {
	Data *QRData `json:"data"`
}

// QRData holds the QR code and credential offer URL from a notification response.
type QRData struct {
	CredentialOfferURL string `json:"credential_offer_url"`
	QRBase64           string `json:"qr_base64"`
}

// Client is an HTTP client for the vc apigw.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// New creates a Client connected to the vc apigw REST API.
func New(cfg Config) (*Client, error) {
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	if baseURL == "" {
		return nil, fmt.Errorf("issuerclient: base URL is required")
	}

	httpClient, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("issuerclient: %w", err)
	}

	return &Client{
		httpClient: httpClient,
		baseURL:    baseURL,
		apiKey:     cfg.APIKey,
	}, nil
}

// Upload sends document data to the apigw for credential issuance.
func (c *Client) Upload(ctx context.Context, req *UploadRequest) error {
	fullURL := c.baseURL + "/api/v1/upload"
	_, err := c.post(ctx, fullURL, req, nil)
	return err
}

// Notification requests a credential offer for a previously uploaded document.
func (c *Client) Notification(ctx context.Context, req *NotificationRequest) (*NotificationReply, error) {
	fullURL := c.baseURL + "/api/v1/notification"
	reply := &NotificationReply{}
	_, err := c.post(ctx, fullURL, req, reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// Close is a no-op for the HTTP client (satisfies the interface for clean shutdown).
func (c *Client) Close() error {
	return nil
}

func (c *Client) post(ctx context.Context, u string, body any, result any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST %s: %w", u, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return resp, fmt.Errorf("read response from %s: %w", u, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, fmt.Errorf("HTTP POST %s returned %d: %s", req.URL.Path, resp.StatusCode, truncate(respBody, 200))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return resp, fmt.Errorf("decode response from %s: %w", u, err)
		}
	}

	return resp, nil
}

func truncate(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}

func buildHTTPClient(cfg Config) (*http.Client, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	transport := &http.Transport{}

	if cfg.TLS || cfg.CAFile != "" || cfg.CertFile != "" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

		if cfg.CAFile != "" {
			ca, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return nil, fmt.Errorf("parse CA certificate from %s", cfg.CAFile)
			}
			tlsConfig.RootCAs = pool
		}

		if cfg.CertFile != "" && cfg.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

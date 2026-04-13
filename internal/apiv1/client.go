// Package apiv1 contains the business logic for facetec-api.
//
// It orchestrates four components:
//
//  1. FaceTec Server client — forwards liveness and ID scan requests.
//  2. Tenant registry ([tenant.Registry]) — resolves per-tenant policy engines
//     and issuer parameters from the JWT tenant_id claim on the request context.
//  3. SPOCP policy engine (per tenant) — evaluates each scan result against
//     numeric thresholds and categorical rules before issuing a credential.
//  4. VC apigw REST client — uploads document data and triggers credential
//     offer generation once policy passes.
//
// All biometric data (FaceMap templates, raw scan images) is held exclusively
// in an in-memory session store ([session.Manager]) and is never written to disk.
// FaceMap bytes are explicitly zeroed with clear() after use and on shutdown.
package apiv1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/issuerclient"
	"github.com/sirosfoundation/facetec-api/internal/session"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

// Client is the central business logic component for facetec-api.
type Client struct {
	cfg      *config.Config
	log      *zap.Logger
	ft       *facetec.Client
	tenants  *tenant.Registry
	sessions *session.Manager
	issuer   *issuerclient.Client
}

// New constructs a Client, wiring up all dependencies.
// registry provides per-tenant policy engines and issuer parameters.
func New(_ context.Context, cfg *config.Config, registry *tenant.Registry, log *zap.Logger) (*Client, error) {
	ftHTTPClient, err := buildFaceTecHTTPClient(cfg.FaceTec)
	if err != nil {
		return nil, fmt.Errorf("apiv1: configure facetec HTTP client: %w", err)
	}
	ft := facetec.NewClient(
		cfg.FaceTec.ServerURL,
		cfg.FaceTec.DeviceKey,
		ftHTTPClient,
	)

	ses := session.New(cfg.Session.LivenessTTL, cfg.Session.OfferTTL)

	log.Info("connecting to vc issuer", zap.String("addr", cfg.Issuer.Addr))
	issuer, err := issuerclient.New(issuerclient.Config{
		BaseURL:  cfg.Issuer.Addr,
		APIKey:   cfg.Issuer.APIKey,
		TLS:      cfg.Issuer.TLS,
		CAFile:   cfg.Issuer.CAFile,
		CertFile: cfg.Issuer.CertFile,
		KeyFile:  cfg.Issuer.KeyFile,
	})
	if err != nil {
		return nil, fmt.Errorf("apiv1: connect to vc issuer at %q: %w", cfg.Issuer.Addr, err)
	}
	log.Info("vc issuer client ready", zap.String("addr", cfg.Issuer.Addr))

	return &Client{
		cfg:      cfg,
		log:      log,
		ft:       ft,
		tenants:  registry,
		sessions: ses,
		issuer:   issuer,
	}, nil
}

// GetSessionToken proxies a session-token request to the FaceTec Server.
func (c *Client) GetSessionToken(ctx context.Context) (*facetec.SessionTokenResponse, error) {
	resp, err := c.ft.GetSessionToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get session token: %w", err)
	}
	return resp, nil
}

// SubmitLiveness forwards a FaceScan to the FaceTec Server, validates that liveness
// passed, stores the FaceMap as a []byte in an in-memory session, and returns an opaque
// session ID. The FaceMap is converted to []byte immediately after receipt so the
// backing array can be zeroed with clear() in the subsequent id-scan step.
func (c *Client) SubmitLiveness(ctx context.Context, req *facetec.LivenessCheckRequest) (string, error) {
	result, err := c.ft.SubmitLiveness(ctx, req)
	if err != nil {
		return "", fmt.Errorf("liveness: facetec server: %w", err)
	}
	if !result.Success {
		return "", fmt.Errorf("liveness: check did not pass")
	}

	// Convert to []byte immediately so the backing array can be explicitly zeroed later.
	// Note: the original string from JSON unmarshalling cannot be zeroed by the Go runtime;
	// this copy is the one that will be cleared.
	faceMapBytes := []byte(result.FaceMap)
	result.FaceMap = "" // drop string reference

	livenessSessionID, err := c.sessions.PutLiveness(faceMapBytes, result.LivenessScore)
	if err != nil {
		clear(faceMapBytes)
		return "", fmt.Errorf("liveness: store face map: %w", err)
	}

	c.log.Info("liveness check accepted",
		zap.Float64("score", result.LivenessScore),
	)
	return livenessSessionID, nil
}

// SubmitIDScan performs the photo ID scan flow:
//  1. Retrieves and consumes the in-memory FaceMap ([]byte) for livenessSessionID.
//  2. Forwards the combined request to the FaceTec Server (FaceMap converted to string for JSON).
//  3. Immediately zeros the FaceMap bytes via defer.
//  4. Evaluates the combined ScanResult against numeric thresholds + SPOCP policy.
//  5. On policy pass, issues a credential via the vc gRPC issuer.
//  6. Returns an opaque transaction ID redeemable via RedeemOffer.
func (c *Client) SubmitIDScan(ctx context.Context, livenessSessionID string, idScanReq *facetec.IDScanRequest) (string, error) {
	lv, err := c.sessions.TakeLiveness(livenessSessionID)
	if err != nil {
		return "", fmt.Errorf("id-scan: liveness session: %w", err)
	}
	// Zero the FaceMap bytes on return regardless of outcome (P1).
	defer clear(lv.FaceMap)

	idScanReq.FaceMap = string(lv.FaceMap) // convert []byte → string for JSON serialization
	idScanResult, err := c.ft.SubmitIDScan(ctx, idScanReq)
	idScanReq.FaceMap = "" // drop string reference immediately after the call

	if err != nil {
		return "", fmt.Errorf("id-scan: facetec server: %w", err)
	}
	if !idScanResult.Success {
		return "", fmt.Errorf("id-scan: scan did not pass")
	}

	scanResult := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{
			Success:       true,
			LivenessScore: lv.LivenessScore,
		},
		IDScan: *idScanResult,
	}

	tc, ok := tenant.FromStdContext(ctx)
	if !ok {
		return "", fmt.Errorf("id-scan: tenant context missing from request")
	}

	if err := tc.Policy.EvaluateScan(scanResult); err != nil {
		c.log.Debug("scan rejected by policy",
			zap.String("tenant", tc.ID),
			zap.String("doc_type", idScanResult.DocumentData.DocumentType),
			zap.Int("face_match_level", idScanResult.FaceMatchLevel),
		)
		return "", fmt.Errorf("id-scan: %w", err)
	}

	txID, err := c.issueCredential(ctx, scanResult, tc.Issuer)
	if err != nil {
		return "", fmt.Errorf("id-scan: issue credential: %w", err)
	}

	// P6: structured audit record — no biometric or PII fields.
	c.log.Info("AUDIT credential_issued",
		zap.String("tenant", tc.ID),
		zap.String("transaction_id", txID),
		zap.String("doc_type", idScanResult.DocumentData.DocumentType),
		zap.String("format", tc.Issuer.Format),
		zap.String("scope", tc.Issuer.Scope),
	)
	return txID, nil
}

// ProcessRequest proxies FaceTec's requestBlob/responseBlob exchange and, when
// the upstream result represents a successful photo-ID match, reuses the
// existing policy and credential issuance pipeline.
func (c *Client) ProcessRequest(ctx context.Context, req *facetec.ProcessRequestRequest) (*facetec.ProcessRequestResponse, error) {
	payload, err := c.ft.ProcessRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("process-request: facetec server: %w", err)
	}

	resp := &facetec.ProcessRequestResponse{Payload: payload}

	scanResult, ok, err := facetec.ExtractScanResult(payload)
	if err != nil {
		c.log.Warn("process-request result could not be translated for issuance",
			zap.Error(err),
		)
		resp.CredentialIssueError = "unable to evaluate scan result"
		return resp, nil
	}
	if !ok {
		return resp, nil
	}

	tc, ok := tenant.FromStdContext(ctx)
	if !ok {
		c.log.Error("process-request tenant context missing")
		resp.CredentialIssueError = "credential issuance unavailable"
		return resp, nil
	}

	if err := tc.Policy.EvaluateScan(*scanResult); err != nil {
		c.log.Info("process-request scan rejected by policy",
			zap.String("tenant", tc.ID),
			zap.String("doc_type", scanResult.IDScan.DocumentData.DocumentType),
			zap.Int("face_match_level", scanResult.IDScan.FaceMatchLevel),
			zap.Error(err),
		)
		resp.CredentialIssueError = "scan rejected by policy"
		return resp, nil
	}

	txID, err := c.issueCredential(ctx, *scanResult, tc.Issuer)
	if err != nil {
		c.log.Error("process-request credential issuance failed", zap.Error(err))
		resp.CredentialIssueError = "credential issuance failed"
		return resp, nil
	}

	c.log.Info("AUDIT credential_issued",
		zap.String("tenant", tc.ID),
		zap.String("transaction_id", txID),
		zap.String("doc_type", scanResult.IDScan.DocumentData.DocumentType),
		zap.String("format", tc.Issuer.Format),
		zap.String("scope", tc.Issuer.Scope),
	)
	resp.TransactionID = txID
	return resp, nil
}

// RedeemOffer retrieves and atomically removes a credential offer by transaction ID.
// The offer is one-time-use; a second call with the same ID returns an error.
func (c *Client) RedeemOffer(ctx context.Context, txID string) (*session.OfferEntry, error) {
	entry, err := c.sessions.TakeOffer(txID)
	if err != nil {
		return nil, fmt.Errorf("redeem offer: %w", err)
	}
	return entry, nil
}

// Close stops the session manager (zeroing all in-memory biometric data) and
// releases the HTTP client to the vc apigw.
func (c *Client) Close(_ context.Context) error {
	c.sessions.Close()
	return c.issuer.Close()
}

// Ready returns nil if the service is fully operational.
// Currently checks that the policy engine has at least one rule loaded.
func (c *Client) Ready() error {
	if empty := c.tenants.EmptyPolicies(); len(empty) > 0 {
		return fmt.Errorf("tenants with no policy rules loaded: %v", empty)
	}
	return nil
}

// issueCredential sends the policy-approved DocumentData to the vc issuer and
// stores the resulting signed credential in the session manager.
// P2: raw MRZ lines are stripped before forwarding — they encode the full identity
// in machine-readable form and must not leave this service.
func (c *Client) issueCredential(ctx context.Context, result facetec.ScanResult, issuer tenant.IssuerParams) (string, error) {
	// Strip raw MRZ lines — they duplicate all identity fields in a parseable format.
	docData := result.IDScan.DocumentData
	docData.MRZLine1 = ""
	docData.MRZLine2 = ""
	docData.MRZLine3 = ""

	data, err := json.Marshal(docData)
	if err != nil {
		return "", fmt.Errorf("marshal document data: %w", err)
	}
	var docDataMap map[string]any
	if err := json.Unmarshal(data, &docDataMap); err != nil {
		return "", fmt.Errorf("unmarshal document data: %w", err)
	}

	authenticSource := c.cfg.Issuer.AuthenticSource
	if authenticSource == "" {
		authenticSource = "facetec-api"
	}
	vct := c.cfg.Issuer.VCT
	if vct == "" {
		vct = issuer.Scope
	}

	documentID := fmt.Sprintf("ft-%d", time.Now().UnixNano())

	uploadReq := &issuerclient.UploadRequest{
		Meta: &issuerclient.MetaData{
			AuthenticSource: authenticSource,
			DocumentVersion: "1.0.0",
			VCT:             vct,
			Scope:           issuer.Scope,
			DocumentID:      documentID,
			RealData:        true,
		},
		DocumentData:        docDataMap,
		DocumentDataVersion: "1.0.0",
	}

	if err := c.issuer.Upload(ctx, uploadReq); err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}

	notifReq := &issuerclient.NotificationRequest{
		AuthenticSource: authenticSource,
		VCT:             vct,
		DocumentID:      documentID,
	}

	notifReply, err := c.issuer.Notification(ctx, notifReq)
	if err != nil {
		return "", fmt.Errorf("notification: %w", err)
	}

	if notifReply.Data == nil || notifReply.Data.CredentialOfferURL == "" {
		return "", fmt.Errorf("notification: no credential offer returned")
	}

	// Store the credential offer URL. The wallet will use the apigw's
	// OID4VCI flow directly via this URI.
	return c.sessions.PutOffer([]string{notifReply.Data.CredentialOfferURL}, issuer.Scope)
}

// buildFaceTecHTTPClient constructs an *http.Client with the TLS configuration
// specified in the FaceTec config block (S6).
func buildFaceTecHTTPClient(cfg config.FaceTecConfig) (*http.Client, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.TLS.SkipVerify, //nolint:gosec // operator opt-in, validated at startup
	}
	if cfg.TLS.SkipVerify {
		// Logged at startup by the caller; just ensure it fails Validate() in production mode.
		_ = "skip_verify enabled"
	}
	if cfg.TLS.CAFile != "" {
		pem, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("facetec TLS CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("facetec TLS CA file %q: no valid certificates found", cfg.TLS.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.TLS.CertFile != "" || cfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("facetec TLS client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}

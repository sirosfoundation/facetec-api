// Package apiv1 contains the business logic for facetec-api.
// It orchestrates the FaceTec client, SPOCP policy engine, session manager,
// and vc gRPC issuer client.
package apiv1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/issuerclient"
	"github.com/sirosfoundation/facetec-api/internal/policy"
	"github.com/sirosfoundation/facetec-api/internal/session"
)

// Client is the central business logic component for facetec-api.
type Client struct {
	cfg      *config.Config
	log      *zap.Logger
	ft       *facetec.Client
	pol      *policy.Engine
	sessions *session.Manager
	issuer   *issuerclient.Client
}

// New constructs a Client, wiring up all dependencies.
func New(_ context.Context, cfg *config.Config, log *zap.Logger) (*Client, error) {
	ftHTTPClient, err := buildFaceTecHTTPClient(cfg.FaceTec)
	if err != nil {
		return nil, fmt.Errorf("apiv1: configure facetec HTTP client: %w", err)
	}
	ft := facetec.NewClient(
		cfg.FaceTec.ServerURL,
		cfg.FaceTec.DeviceKey,
		ftHTTPClient,
	)

	pol, err := policy.New(cfg.Policy.RulesDir, cfg.Policy.MinLivenessScore, cfg.Policy.MinFaceMatchLevel)
	if err != nil {
		return nil, fmt.Errorf("apiv1: init policy engine: %w", err)
	}
	log.Info("policy engine ready",
		zap.Int("rules", pol.RuleCount()),
		zap.Int("min_liveness_score", cfg.Policy.MinLivenessScore),
		zap.Int("min_face_match_level", cfg.Policy.MinFaceMatchLevel),
	)
	if pol.RuleCount() == 0 {
		log.Warn("policy engine has no rules — all scans will be rejected; set policy.rules_dir in config")
	}

	ses := session.New(cfg.Session.LivenessTTL, cfg.Session.OfferTTL)

	log.Info("connecting to vc issuer", zap.String("addr", cfg.Issuer.Addr), zap.Bool("tls", cfg.Issuer.TLS))
	issuer, err := issuerclient.New(issuerclient.TLSConfig{
		Addr:         cfg.Issuer.Addr,
		TLS:          cfg.Issuer.TLS,
		CAFilePath:   cfg.Issuer.CAFile,
		CertFilePath: cfg.Issuer.CertFile,
		KeyFilePath:  cfg.Issuer.KeyFile,
	})
	if err != nil {
		return nil, fmt.Errorf("apiv1: connect to vc issuer at %q: %w", cfg.Issuer.Addr, err)
	}
	log.Info("vc issuer client ready", zap.String("addr", cfg.Issuer.Addr))

	return &Client{
		cfg:      cfg,
		log:      log,
		ft:       ft,
		pol:      pol,
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

	if err := c.pol.EvaluateScan(scanResult); err != nil {
		c.log.Debug("scan rejected by policy", // P5: behavioral attributes at Debug, not Info
			zap.String("doc_type", idScanResult.DocumentData.DocumentType),
			zap.Int("face_match_level", idScanResult.FaceMatchLevel),
		)
		return "", fmt.Errorf("id-scan: %w", err)
	}

	txID, err := c.issueCredential(ctx, scanResult)
	if err != nil {
		return "", fmt.Errorf("id-scan: issue credential: %w", err)
	}

	// P6: structured audit record — no biometric or PII fields.
	c.log.Info("AUDIT credential_issued",
		zap.String("transaction_id", txID),
		zap.String("doc_type", idScanResult.DocumentData.DocumentType),
		zap.String("format", c.cfg.Issuer.Format),
		zap.String("scope", c.cfg.Issuer.Scope),
	)
	return txID, nil
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
// releases the gRPC connection to the vc issuer.
func (c *Client) Close(_ context.Context) error {
	c.sessions.Close()
	return c.issuer.Close()
}

// Ready returns nil if the service is fully operational.
// Currently checks that the policy engine has at least one rule loaded.
func (c *Client) Ready() error {
	if c.pol.RuleCount() == 0 {
		return fmt.Errorf("policy engine has no rules loaded")
	}
	return nil
}

// issueCredential sends the policy-approved DocumentData to the vc issuer and
// stores the resulting signed credential in the session manager.
// P2: raw MRZ lines are stripped before forwarding — they encode the full identity
// in machine-readable form and must not leave this service.
func (c *Client) issueCredential(ctx context.Context, result facetec.ScanResult) (string, error) {
	// Strip raw MRZ lines — they duplicate all identity fields in a parseable format.
	docData := result.IDScan.DocumentData
	docData.MRZLine1 = ""
	docData.MRZLine2 = ""
	docData.MRZLine3 = ""

	data, err := json.Marshal(docData)
	if err != nil {
		return "", fmt.Errorf("marshal document data: %w", err)
	}

	var credentials []string

	switch c.cfg.Issuer.Format {
	case "mdoc":
		resp, err := c.issuer.MakeMDoc(ctx, issuerclient.MakeMDocRequest{
			Scope:        c.cfg.Issuer.Scope,
			DocType:      "org.iso.18013.5.1.mDL",
			DocumentData: data,
		})
		if err != nil {
			return "", fmt.Errorf("MakeMDoc: %w", err)
		}
		credentials = []string{string(resp.MDoc)}

	case "vc20":
		resp, err := c.issuer.MakeVC20(ctx, issuerclient.MakeVC20Request{
			Scope:        c.cfg.Issuer.Scope,
			DocumentData: data,
		})
		if err != nil {
			return "", fmt.Errorf("MakeVC20: %w", err)
		}
		credentials = []string{string(resp.Credential)}

	default: // sdjwt
		resp, err := c.issuer.MakeSDJWT(ctx, issuerclient.MakeSDJWTRequest{
			Scope:        c.cfg.Issuer.Scope,
			DocumentData: data,
		})
		if err != nil {
			return "", fmt.Errorf("MakeSDJWT: %w", err)
		}
		credentials = resp.Credentials
	}

	return c.sessions.PutOffer(credentials, c.cfg.Issuer.Scope)
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

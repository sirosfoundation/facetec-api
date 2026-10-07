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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/emrtd"
	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/idverrors"
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
	// chip performs eMRTD passive authentication and asks the go-trust PDP
	// about the document signer. nil is valid (no PDP, not required).
	chip *emrtd.Checker
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

	ses := session.New(cfg.Session.LivenessTTL, cfg.Session.OfferTTL, cfg.Session.LivenessProofTTL)

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
		chip:     newChipChecker(cfg.Trust),
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
		return "", idverrors.New(idverrors.CodeLivenessFailed, "liveness check did not pass")
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
//  4. Rejects outright if NFC wasn't verified (see the NFCVerified check below).
//  5. Evaluates the combined ScanResult against numeric thresholds and tenant policy.
//  6. On policy pass, issues a credential using the configured issuer client flow.
//  7. Returns the issued document ID and credential offer URL.
func (c *Client) SubmitIDScan(ctx context.Context, livenessSessionID string, idScanReq *facetec.IDScanRequest) (string, string, error) {
	lv, err := c.sessions.TakeLiveness(livenessSessionID)
	if err != nil {
		return "", "", idverrors.Newf(idverrors.CodeSessionExpired, "liveness session expired or not found: %v", err)
	}
	// Zero the FaceMap bytes on return regardless of outcome (P1).
	defer clear(lv.FaceMap)

	idScanReq.FaceMap = string(lv.FaceMap) // convert []byte → string for JSON serialization
	idScanResult, err := c.ft.SubmitIDScan(ctx, idScanReq)
	idScanReq.FaceMap = "" // drop string reference immediately after the call

	if err != nil {
		return "", "", fmt.Errorf("id-scan: facetec server: %w", err)
	}
	if !idScanResult.Success {
		return "", "", idverrors.New(idverrors.CodeMatchFailed, "document scan or face-match did not pass")
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
		return "", "", fmt.Errorf("id-scan: tenant context missing from request")
	}

	c.log.Debug("id-scan document data",
		zap.String("tenant", tc.ID),
		zap.Any("document_data", documentDataForLog(idScanResult.DocumentData)),
	)

	// Same hard gate as ProcessRequest's nfcRejection check, adapted to this
	// legacy path's response shape. FaceTec's /match-3d-3d response (decoded
	// directly into IDScanResult) only carries a plain NFCVerified bool, with
	// no equivalent to /process-request's nfcStatusEnumInt that would let us
	// distinguish "skipped" from "attempted and failed" -- so both are
	// treated as not meeting the required assurance level. Without this,
	// /v1/liveness + /v1/id-scan would be a way to issue credentials that
	// completely bypasses the NFC requirement enforced on /process-request.
	if !idScanResult.NFCVerified {
		c.log.Info("id-scan scan rejected: NFC not verified",
			zap.String("tenant", tc.ID),
			zap.String("doc_type", idScanResult.DocumentData.DocumentType),
		)
		return "", "", idverrors.New(idverrors.CodeNFCSkipped, "NFC verification was skipped or failed")
	}

	// The legacy response carries no raw chip data, so chip-trusted is always
	// false here. Because NFCVerified (required above) counts as chip
	// evidence, trust.required hard-rejects this path in assessChip; with
	// trust.required off, policy rules that demand chip-trusted reject it.
	if rej := c.assessChip(ctx, &scanResult); rej != nil {
		c.log.Info("id-scan scan rejected: chip check",
			zap.String("tenant", tc.ID), zap.String("reason", scanResult.IDScan.ChipTrustReason))
		return "", "", rej
	}

	if code, msg, rejected := documentExpiryRejection(idScanResult.DocumentData, time.Now()); rejected {
		c.log.Info("id-scan scan rejected: document expiry",
			zap.String("tenant", tc.ID),
			zap.String("doc_type", idScanResult.DocumentData.DocumentType),
			zap.String("code", string(code)),
		)
		return "", "", idverrors.New(code, msg)
	}

	if err := tc.Policy.EvaluateScan(scanResult); err != nil {
		c.log.Debug("scan rejected by policy",
			zap.String("tenant", tc.ID),
			zap.String("doc_type", idScanResult.DocumentData.DocumentType),
			zap.Int("face_match_level", idScanResult.FaceMatchLevel),
		)
		return "", "", idverrors.Newf(idverrors.CodePolicyRejected, "scan rejected by policy: %v", err)
	}

	docID, offerURL, err := c.issueCredential(ctx, scanResult, tc.Issuer)
	if err != nil {
		return "", "", idverrors.Newf(idverrors.CodeIssuanceFailed, "credential issuance failed: %v", err)
	}

	// P6: structured audit record — no biometric or PII fields.
	c.log.Info("AUDIT credential_issued", append([]zap.Field{
		zap.String("tenant", tc.ID),
		zap.String("document_id", docID),
		zap.String("doc_type", idScanResult.DocumentData.DocumentType),
		zap.String("format", tc.Issuer.Format),
		zap.String("scope", tc.Issuer.Scope),
	}, chipAuditFields(scanResult.IDScan)...)...)
	return docID, offerURL, nil
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

	// FaceTec Server reports whether liveness was proven on the session's
	// liveness step, a request before the one that completes the photo ID
	// match. Remember the verdict so that final result can require it.
	if proven, ok := facetec.LivenessProven(payload); ok {
		if key, hasKey := livenessProofKey(ctx, req.ExternalDatabaseRefID); hasKey {
			c.sessions.RecordLivenessProof(key, proven)
		}
	}

	scanResult, ok, err := facetec.ExtractScanResult(payload)
	if err != nil {
		c.log.Warn("process-request result could not be translated for issuance",
			zap.Error(err),
		)
		resp.CredentialIssueError = "unable to evaluate scan result"
		resp.CredentialIssueErrCode = string(idverrors.CodeMatchFailed)
		return resp, nil
	}
	if !ok {
		return resp, nil
	}

	tc, ok := tenant.FromStdContext(ctx)
	if !ok {
		c.log.Error("process-request tenant context missing")
		resp.CredentialIssueError = "credential issuance unavailable"
		resp.CredentialIssueErrCode = string(idverrors.CodeInternalError)
		return resp, nil
	}

	c.log.Debug("process-request document data",
		zap.String("tenant", tc.ID),
		zap.Any("document_data", documentDataForLog(scanResult.IDScan.DocumentData)),
	)

	// Hard gate: nothing is issued unless FaceTec Server proved liveness
	// earlier in this same session. The final response does not say so
	// itself; the verdict was recorded from the liveness step, keyed by the
	// session's externalDatabaseRefID. Without that ID the session cannot be
	// tied to a liveness step at all.
	key, hasKey := livenessProofKey(ctx, req.ExternalDatabaseRefID)
	if !hasKey || !c.sessions.TakeLivenessProof(key) {
		c.log.Info("process-request scan rejected: liveness not proven for this session",
			zap.String("tenant", tc.ID),
			zap.Bool("has_external_database_ref_id", hasKey),
		)
		resp.CredentialIssueError = "liveness was not proven for this session"
		resp.CredentialIssueErrCode = string(idverrors.CodeLivenessFailed)
		return resp, nil
	}
	// FaceTec 10 reports liveness as proven or not, without a score. A proven
	// session counts as a full score, so a policy's liveness-score rule still
	// sees it and an unproven one never reaches the policy.
	scanResult.Liveness = facetec.LivenessCheckResult{Success: true, LivenessScore: 1.0}

	// Hard gate, independent of per-tenant SPOCP policy thresholds: nothing
	// is issued unless the document's chip was read and authenticated,
	// whatever the reason it was not (never prompted, skipped, read error),
	// and regardless of how well the rest of the scan scored.
	if code, msg, rejected := nfcRejection(scanResult.IDScan); rejected {
		c.log.Info("process-request scan rejected: NFC chip not authenticated",
			zap.String("tenant", tc.ID),
			zap.String("doc_type", scanResult.IDScan.DocumentData.DocumentType),
			zap.Int("nfc_status", scanResult.IDScan.NFCStatus),
			zap.String("code", string(code)),
		)
		resp.CredentialIssueError = msg
		resp.CredentialIssueErrCode = string(code)
		return resp, nil
	}

	// Failed FaceTec chip authentication (clone / signature failure) is a hard
	// reject, and so is an untrusted chip when trust.required is set.
	if rej := c.assessChip(ctx, scanResult); rej != nil {
		c.log.Info("process-request scan rejected: chip check",
			zap.String("tenant", tc.ID),
			zap.String("doc_type", scanResult.IDScan.DocumentData.DocumentType),
			zap.Int("chip_auth_status", scanResult.IDScan.ChipAuthStatus),
			zap.String("chip_trust_reason", scanResult.IDScan.ChipTrustReason),
		)
		resp.CredentialIssueError = rej.Message
		resp.CredentialIssueErrCode = string(rej.Code)
		return resp, nil
	}

	// Hard gate: an expired document, or one whose expiry date could not be
	// read, is not a basis for a credential.
	if code, msg, rejected := documentExpiryRejection(scanResult.IDScan.DocumentData, time.Now()); rejected {
		c.log.Info("process-request scan rejected: document expiry",
			zap.String("tenant", tc.ID),
			zap.String("doc_type", scanResult.IDScan.DocumentData.DocumentType),
			zap.String("code", string(code)),
		)
		resp.CredentialIssueError = msg
		resp.CredentialIssueErrCode = string(code)
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
		resp.CredentialIssueErrCode = string(idverrors.CodePolicyRejected)
		return resp, nil
	}

	docID, offerURL, err := c.issueCredential(ctx, *scanResult, tc.Issuer)
	if err != nil {
		c.log.Error("process-request credential issuance failed", zap.Error(err))
		resp.CredentialIssueError = "credential issuance failed"
		resp.CredentialIssueErrCode = string(idverrors.CodeIssuanceFailed)
		return resp, nil
	}

	c.log.Info("AUDIT credential_issued", append([]zap.Field{
		zap.String("tenant", tc.ID),
		zap.String("document_id", docID),
		zap.String("doc_type", scanResult.IDScan.DocumentData.DocumentType),
		zap.String("format", tc.Issuer.Format),
		zap.String("scope", tc.Issuer.Scope),
	}, chipAuditFields(scanResult.IDScan)...)...)
	resp.TransactionID = docID
	resp.CredentialOfferURL = offerURL
	return resp, nil
}

// nfcRejection reports why a scan without an authenticated chip is refused,
// or rejected=false when the chip was authenticated. The code tells the
// client what the user can do about it.
func nfcRejection(r facetec.IDScanResult) (code idverrors.Code, msg string, rejected bool) {
	if r.NFCVerified {
		return "", "", false
	}
	switch r.NFCStatus {
	case facetec.NFCStatusNotSpecifiedByTemplate:
		return idverrors.CodeNFCNotRequested, "no NFC chip read was requested for this document", true
	case facetec.NFCStatusDeviceNotCapable:
		return idverrors.CodeNFCDeviceNotCapable, "the device could not read the NFC chip", true
	case facetec.NFCStatusUserSkipped:
		return idverrors.CodeNFCSkipped, "NFC verification was skipped", true
	case facetec.NFCStatusChipError:
		return idverrors.CodeNFCChipReadFailed, "the NFC chip could not be read", true
	default:
		return idverrors.CodeNFCNotAuthenticated, "the NFC chip was not authenticated", true
	}
}

// livenessProofKey identifies a process-request session for the liveness
// proof store: the tenant and the client's externalDatabaseRefID, which the
// FaceTec SDK sends unchanged with every request of one session. hasKey is
// false when the request carries no externalDatabaseRefID.
func livenessProofKey(ctx context.Context, externalDatabaseRefID string) (key string, hasKey bool) {
	if externalDatabaseRefID == "" {
		return "", false
	}
	tenantID := ""
	if tc, ok := tenant.FromStdContext(ctx); ok {
		tenantID = tc.ID
	}
	return tenantID + "\x00" + externalDatabaseRefID, true
}

// documentDataForLog is the OCR result written at debug level. The portrait
// is a base64 face image, so only its length is included.
func documentDataForLog(doc facetec.DocumentData) facetec.DocumentData {
	if n := len(doc.Portrait); n > 0 {
		doc.Portrait = fmt.Sprintf("[%d bytes omitted]", n)
	}
	return doc
}

// documentExpiryRejection refuses a document that has expired, or whose
// expiry date is missing or unreadable. A document is valid through its
// expiry date; dates are compared in UTC.
func documentExpiryRejection(doc facetec.DocumentData, now time.Time) (code idverrors.Code, msg string, rejected bool) {
	expiry, ok := parseISODate(doc.DateOfExpiry)
	if !ok {
		return idverrors.CodeDocumentUnreadable, "the document's expiry date could not be read", true
	}
	if !now.UTC().Before(expiry.AddDate(0, 0, 1)) {
		return idverrors.CodeDocumentExpired, "the document has expired", true
	}
	return "", "", false
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

// issueCredential sends the policy-approved DocumentData to the vc apigw REST
// issuer (upload + preauth_offer) and returns the document ID and credential offer URL.
// P2: only the credential-schema fields are forwarded via MapDocumentData — MRZ lines
// and internal FaceTec metadata are excluded by the mapper and never leave this service.
func (c *Client) issueCredential(ctx context.Context, result facetec.ScanResult, issuer tenant.IssuerParams) (documentID string, offerURL string, err error) {
	authenticSource := c.cfg.Issuer.AuthenticSource
	if authenticSource == "" {
		authenticSource = "facetec-api"
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate document ID: %w", err)
	}
	documentID = "ft-" + hex.EncodeToString(b)

	docDataMap, err := c.credentialClaims(result.IDScan.DocumentData, documentID, authenticSource, issuer.Format)
	if err != nil {
		return "", "", err
	}

	uploadReq := &issuerclient.UploadRequest{
		Meta: &issuerclient.MetaData{
			AuthenticSource: authenticSource,
			Scope:           issuer.Scope,
			DocumentID:      documentID,
		},
		IdentityMappingIDs: []string{documentID},
		DocumentData:       docDataMap,
	}

	if err := c.issuer.Upload(ctx, uploadReq); err != nil {
		return "", "", fmt.Errorf("upload: %w", err)
	}

	preauthReq := &issuerclient.PreauthOfferRequest{
		AuthenticSource: authenticSource,
		Scope:           issuer.Scope,
		DocumentID:      documentID,
	}

	preauthReply, err := c.issuer.PreauthOffer(ctx, preauthReq)
	if err != nil {
		return "", "", fmt.Errorf("preauth_offer: %w", err)
	}

	if preauthReply.CredentialOfferURL == "" {
		return "", "", fmt.Errorf("preauth_offer: no credential offer returned")
	}

	return documentID, preauthReply.CredentialOfferURL, nil
}

// credentialClaims returns the document_data uploaded to the vc apigw for the
// tenant's credential format. mdoc issues an EWC RFC013 Photo ID (see
// MapPhotoIDClaims); every other format keeps the flat CredentialClaims shape.
func (c *Client) credentialClaims(doc facetec.DocumentData, documentID, authenticSource, format string) (map[string]any, error) {
	if format == "mdoc" {
		authority := c.cfg.Issuer.IssuingAuthority
		if authority == "" {
			authority = authenticSource
		}
		return MapPhotoIDClaims(doc, documentID, PhotoIDIssuer{
			Authority: authority,
			Country:   c.cfg.Issuer.IssuingCountry,
		}, time.Now()), nil
	}

	data, err := json.Marshal(MapDocumentData(doc))
	if err != nil {
		return nil, fmt.Errorf("marshal credential claims: %w", err)
	}
	var docDataMap map[string]any
	if err := json.Unmarshal(data, &docDataMap); err != nil {
		return nil, fmt.Errorf("unmarshal credential claims: %w", err)
	}
	return docDataMap, nil
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

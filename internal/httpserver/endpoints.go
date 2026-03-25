package httpserver

import (
	"maps"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/facetec"
)

// endpointLivez is a Kubernetes liveness probe — always returns 200 if the
// process is running. No authentication required.
func (s *Service) endpointLivez(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// endpointReadyz is a Kubernetes readiness probe. It calls apiv1.Ready() to
// verify that the policy engine has rules loaded and the service is operational.
// No authentication required.
func (s *Service) endpointReadyz(c *gin.Context) {
	if err := s.apiv1.Ready(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready", "reason": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// endpointHealth returns service metadata (authenticated).
//
//	GET /v1/health → 200 { "status": "ok" }
func (s *Service) endpointHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// endpointSessionToken proxies a session-token request to the FaceTec Server.
//
//	POST /v1/session-token
//	→ 200 { "sessionToken": "..." }
func (s *Service) endpointSessionToken(c *gin.Context) {
	resp, err := s.apiv1.GetSessionToken(c.Request.Context())
	if err != nil {
		s.fail(c, http.StatusBadGateway, err, "failed to obtain session token")
		return
	}
	s.respond(c, http.StatusOK, resp)
}

// endpointProcessRequest accepts FaceTec's opaque requestBlob payload, forwards
// it to the FaceTec Server, and preserves the upstream response JSON. When the
// upstream result is a successful photo-ID match, the response is augmented with
// transactionId and credentialOfferURI for the wallet flow.
func (s *Service) endpointProcessRequest(c *gin.Context) {
	var req facetec.ProcessRequestRequest
	if err := s.bindJSON(c, &req); err != nil {
		return
	}

	resp, err := s.apiv1.ProcessRequest(c.Request.Context(), &req)
	if err != nil {
		s.fail(c, http.StatusBadGateway, err, "process-request failed")
		return
	}

	body := gin.H{}
	for key, value := range maps.Clone(resp.Payload) {
		body[key] = value
	}
	if resp.TransactionID != "" {
		body["transactionId"] = resp.TransactionID
		body["credentialOfferURI"] = buildOfferURI(s.cfg.Server, resp.TransactionID)
	}
	if resp.CredentialIssueError != "" {
		body["credentialIssueError"] = resp.CredentialIssueError
	}

	s.respond(c, http.StatusOK, body)
}

// LivenessScanRequest is the body expected by POST /v1/liveness.
// The FaceScan and AuditTrail fields contain raw biometric data; they must not be logged.
type LivenessScanRequest struct {
	SessionToken               string   `json:"sessionToken"            binding:"required"`
	FaceScanBase64             string   `json:"faceScan"                binding:"required"`
	AuditTrailBase64           []string `json:"auditTrail"`
	LowQualityAuditTrailBase64 []string `json:"lowQualityAuditTrail"`
}

// livenessResponse is returned on a successful liveness check.
type livenessResponse struct {
	// LivenessSessionID is an opaque token that must be passed to POST /v1/id-scan.
	// It references an in-memory FaceMap with a short TTL.
	LivenessSessionID string `json:"livenessSessionId"`
}

// endpointLiveness accepts a FaceScan from the mobile SDK, validates liveness,
// stores the FaceMap in memory, and returns an opaque livenessSessionId.
//
//	POST /v1/liveness  { sessionToken, faceScan, … }
//	→ 200 { "livenessSessionId": "..." }
func (s *Service) endpointLiveness(c *gin.Context) {
	var req LivenessScanRequest
	if err := s.bindJSON(c, &req); err != nil {
		return
	}

	ftReq := &facetec.LivenessCheckRequest{
		SessionToken:               req.SessionToken,
		FaceScanBase64:             req.FaceScanBase64,
		AuditTrailBase64:           req.AuditTrailBase64,
		LowQualityAuditTrailBase64: req.LowQualityAuditTrailBase64,
	}

	livenessSessionID, err := s.apiv1.SubmitLiveness(c.Request.Context(), ftReq)
	if err != nil {
		s.log.Info("liveness check failed", zap.Error(err))
		s.fail(c, http.StatusUnprocessableEntity, err, "liveness check failed")
		return
	}

	s.respond(c, http.StatusOK, livenessResponse{LivenessSessionID: livenessSessionID})
}

// IDScanSubmitRequest is expected by POST /v1/id-scan.
// IDScan fields contain raw document image data; they must not be logged.
type IDScanSubmitRequest struct {
	SessionToken                      string   `json:"sessionToken"                      binding:"required"`
	LivenessSessionID                 string   `json:"livenessSessionId"                 binding:"required"`
	IDScanBase64                      string   `json:"idScan"                            binding:"required"`
	IDScanFrontImagesCompressedBase64 []string `json:"idScanFrontImagesCompressedBase64"`
	IDScanBackImagesCompressedBase64  []string `json:"idScanBackImagesCompressedBase64"`
}

// idScanResponse is returned on a successful document scan and credential issuance.
type idScanResponse struct {
	TransactionID      string `json:"transactionId"`
	CredentialOfferURI string `json:"credentialOfferURI"`
}

// endpointIDScan accepts an ID scan, matches it against the stored FaceMap,
// evaluates SPOCP policy, issues a credential, and returns a transaction ID.
//
//	POST /v1/id-scan  { sessionToken, livenessSessionId, idScan, … }
//	→ 200 { "transactionId": "...", "credentialOfferURI": "openid-credential-offer://..." }
func (s *Service) endpointIDScan(c *gin.Context) {
	var req IDScanSubmitRequest
	if err := s.bindJSON(c, &req); err != nil {
		return
	}

	ftReq := &facetec.IDScanRequest{
		SessionToken:                      req.SessionToken,
		IDScanBase64:                      req.IDScanBase64,
		IDScanFrontImagesCompressedBase64: req.IDScanFrontImagesCompressedBase64,
		IDScanBackImagesCompressedBase64:  req.IDScanBackImagesCompressedBase64,
		// FaceMap is populated server-side by SubmitIDScan; never set from client input.
	}

	txID, err := s.apiv1.SubmitIDScan(c.Request.Context(), req.LivenessSessionID, ftReq)
	if err != nil {
		s.log.Info("id-scan flow failed", zap.Error(err))
		s.fail(c, http.StatusUnprocessableEntity, err, "id-scan flow failed")
		return
	}

	offerURI := buildOfferURI(s.cfg.Server, txID)
	s.respond(c, http.StatusOK, idScanResponse{
		TransactionID:      txID,
		CredentialOfferURI: offerURI,
	})
}

// endpointOffer redeems a credential offer by transaction ID (one-time-use).
//
//	GET /v1/offer/:txid
//	→ 200 { "credentials": [...], "scope": "..." }
func (s *Service) endpointOffer(c *gin.Context) {
	txID := c.Param("txid")

	entry, err := s.apiv1.RedeemOffer(c.Request.Context(), txID)
	if err != nil {
		s.fail(c, http.StatusNotFound, err, "offer not found or expired")
		return
	}

	s.respond(c, http.StatusOK, gin.H{
		"credentials": entry.Credentials,
		"scope":       entry.Scope,
	})
}

// buildOfferURI constructs an OpenID4VCI credential offer URI.
// If srv.PublicBaseURL is set it is used as the base (production deployments);
// otherwise the service falls back to scheme + bind address (dev/local only).
func buildOfferURI(srv config.ServerConfig, txID string) string {
	base := srv.PublicBaseURL
	if base == "" {
		scheme := "http"
		if srv.TLS.Enabled {
			scheme = "https"
		}
		base = scheme + "://" + srv.Address()
	}
	return "openid-credential-offer://?credential_offer_uri=" + base + "/v1/offer/" + txID
}

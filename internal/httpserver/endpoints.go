package httpserver

import (
	"net/http"

	"github.com/gin-gonic/gin"

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

	if resp.TransactionID != "" {
		resp.Payload["transactionId"] = resp.TransactionID
		resp.Payload["credentialOfferURI"] = resp.CredentialOfferURL
	}
	if resp.CredentialIssueError != "" {
		resp.Payload["credentialIssueError"] = resp.CredentialIssueError
		resp.Payload["credentialIssueErrorCode"] = resp.CredentialIssueErrCode
	}

	s.respond(c, http.StatusOK, resp.Payload)
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

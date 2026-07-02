package httpserver

import (
	"context"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/session"
)

// Apiv1 is the interface consumed by the HTTP layer.
// It contains only the operations needed by the HTTP handlers — business logic
// beyond this boundary is invisible to the transport layer.
type Apiv1 interface {
	GetSessionToken(ctx context.Context) (*facetec.SessionTokenResponse, error)
	SubmitLiveness(ctx context.Context, req *facetec.LivenessCheckRequest) (string, error)
	SubmitIDScan(ctx context.Context, livenessSessionID string, req *facetec.IDScanRequest) (string, string, error)
	ProcessRequest(ctx context.Context, req *facetec.ProcessRequestRequest) (*facetec.ProcessRequestResponse, error)
	RedeemOffer(ctx context.Context, txID string) (*session.OfferEntry, error)
	// Ready returns nil when the service is fully operational (policy rules loaded, etc.).
	// Used by the /readyz probe.
	Ready() error
	// IssueDummyCredential is a temporary debug tool that runs the issuance
	// pipeline against fixed placeholder identity data, bypassing FaceTec
	// entirely. Only registered when not running in production mode.
	IssueDummyCredential(ctx context.Context) (documentID string, offerURL string, err error)
}

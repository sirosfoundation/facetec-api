package emrtd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
)

// ActionDocumentSigner is the AuthZEN action name the go-trust emrtd policy
// is registered under.
const ActionDocumentSigner = "emrtd-document-signer"

const (
	defaultTimeout = 5 * time.Second
	maxAttempts    = 2
	retryBackoff   = 100 * time.Millisecond
)

// TrustRequest is what the PEP asks the PDP. It carries certificates and a
// country code only: no personal data and no SOD.
type TrustRequest struct {
	// IssuingState is the ISO 3166-1 alpha-3 code (subject.id).
	IssuingState string
	// Chain[0] is the DSC, further entries are untrusted certificates from the SOD.
	Chain [][]byte
	// SigningTime is passed as context.signing_time when non-nil.
	SigningTime *time.Time
}

// TrustDecision is the PDP's verdict. Trusted is true only for an explicit
// allow carrying the anchor evidence required by the contract.
type TrustDecision struct {
	Trusted     bool
	Code        string // machine-readable deny code, when provided
	CSCASHA256  string
	CSCASubject string
	DSCSHA256   string
}

// TrustEvaluator decides whether a DSC is trusted for an issuing state.
// Implementations must fail closed: any error means "not trusted".
type TrustEvaluator interface {
	EvaluateDSC(ctx context.Context, req TrustRequest) (TrustDecision, error)
}

// ErrMalformedResponse is returned (wrapped) when the PDP answered with a body
// that is not a usable AuthZEN decision.
var ErrMalformedResponse = errors.New("emrtd: malformed PDP response")

// PDPClient is a TrustEvaluator backed by a go-trust AuthZEN PDP.
type PDPClient struct {
	client *authzenclient.Client
}

// NewPDPClient builds a client for the PDP at baseURL. timeout bounds each
// attempt; zero selects a 5s default.
func NewPDPClient(baseURL string, timeout time.Duration) *PDPClient {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &PDPClient{client: authzenclient.New(baseURL, authzenclient.WithTimeout(timeout))}
}

// EvaluateDSC implements TrustEvaluator. It retries once, and only for
// transport errors (connection failures, timeouts); HTTP error statuses and
// undecodable bodies are final.
func (p *PDPClient) EvaluateDSC(ctx context.Context, req TrustRequest) (TrustDecision, error) {
	if len(req.Chain) == 0 || req.IssuingState == "" {
		return TrustDecision{}, errors.New("emrtd: empty trust request")
	}
	keys := make([]interface{}, len(req.Chain))
	for i, der := range req.Chain {
		keys[i] = base64.StdEncoding.EncodeToString(der)
	}
	ar := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: req.IssuingState},
		Resource: authzen.Resource{Type: "x5c", ID: req.IssuingState, Key: keys},
		Action:   authzenclient.NewAction(ActionDocumentSigner),
	}
	if req.SigningTime != nil {
		ar.Context = map[string]interface{}{"signing_time": req.SigningTime.UTC().Format(time.RFC3339)}
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return TrustDecision{}, fmt.Errorf("emrtd: PDP unreachable: %w", errors.Join(lastErr, ctx.Err()))
			case <-time.After(retryBackoff):
			}
		}
		resp, err := p.client.Evaluate(ctx, ar)
		if err == nil {
			return decisionFrom(resp)
		}
		lastErr = err
		if !isTransport(err) {
			break
		}
	}
	return TrustDecision{}, fmt.Errorf("emrtd: PDP evaluation failed: %w", lastErr)
}

// isTransport reports whether err is a connection-level failure of the HTTP
// round trip (as opposed to a non-200 status or an undecodable body).
func isTransport(err error) bool {
	var ue *url.Error
	return errors.As(err, &ue)
}

func decisionFrom(resp *authzen.EvaluationResponse) (TrustDecision, error) {
	if resp == nil {
		return TrustDecision{}, fmt.Errorf("%w: empty response", ErrMalformedResponse)
	}
	admin := reasonMap(resp, "admin")
	d := TrustDecision{
		Code:        firstString(admin, "code"),
		CSCASHA256:  strings.ToLower(firstString(admin, "csca_sha256")),
		CSCASubject: firstString(admin, "csca_subject"),
		DSCSHA256:   strings.ToLower(firstString(admin, "dsc_sha256")),
	}
	if d.Code == "" {
		d.Code = firstString(reasonMap(resp, "user"), "code")
	}
	d.Code = sanitizeCode(d.Code)
	if !resp.Decision {
		return d, nil
	}
	// An allow must name the anchor it relied on (contract), otherwise it is
	// indistinguishable from a PDP that is not running the emrtd registry.
	if d.CSCASHA256 == "" {
		return TrustDecision{}, fmt.Errorf("%w: allow without csca_sha256", ErrMalformedResponse)
	}
	if b, err := hex.DecodeString(d.CSCASHA256); err != nil || len(b) != sha256.Size {
		return TrustDecision{}, fmt.Errorf("%w: csca_sha256 is not a SHA-256 hex digest", ErrMalformedResponse)
	}
	d.Trusted = true
	return d, nil
}

func reasonMap(resp *authzen.EvaluationResponse, key string) map[string]interface{} {
	if resp.Context == nil || resp.Context.Reason == nil {
		return nil
	}
	switch v := resp.Context.Reason[key].(type) {
	case map[string]interface{}:
		return v
	case json.RawMessage:
		var m map[string]interface{}
		if json.Unmarshal(v, &m) == nil {
			return m
		}
	}
	return nil
}

func firstString(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}

// sanitizeCode restricts a PDP-supplied deny code to [a-z0-9_] (max 40 chars)
// since it ends up in audit records.
func sanitizeCode(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if sb.Len() >= 40 {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

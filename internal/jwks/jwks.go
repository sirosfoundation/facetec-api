// Package jwks verifies asymmetrically signed JWTs against a remote JSON Web
// Key Set.
//
// The set is fetched over HTTPS, cached, and re-fetched when a token presents
// a kid the cache does not hold -- which is how key rotation at the issuer
// reaches this service without a restart. Refetching is rate-limited, because
// the kid in a token is attacker-controlled: without a floor, a stream of
// tokens carrying random kids would turn this service into a load generator
// against the issuer's JWKS endpoint.
//
// Only asymmetric algorithms are accepted. An HMAC or "none" token is refused
// here whatever the key set holds, so a key fetched from the issuer can never
// be pressed into service as an HMAC secret.
package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Algorithms are the signature algorithms a token may use. They match what the
// go-wallet-backend authorization server signs with (internal/as/token.go), and
// every one of them is asymmetric: a public key from the key set verifies, and
// cannot also sign.
var Algorithms = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.EdDSA}

// maxJWKSBody caps the response body. A key set is a few hundred bytes per key;
// this leaves room for generous rotation while refusing to buffer a hostile or
// misconfigured endpoint's reply.
const maxJWKSBody = 1 << 20 // 1 MiB

// Verifier holds a cached key set and verifies token signatures against it.
type Verifier struct {
	uri        string
	httpClient *http.Client

	// cacheTTL is how long a fetched set is served before a refresh.
	cacheTTL time.Duration
	// minRefresh is the floor between fetches triggered by an unknown kid.
	minRefresh time.Duration

	mu          sync.RWMutex
	keys        jose.JSONWebKeySet
	fetchedAt   time.Time
	lastAttempt time.Time

	// now is overridable in tests.
	now func() time.Time
}

// Config configures a Verifier.
type Config struct {
	// URI is the key set endpoint, e.g. https://backend.example.org/.well-known/jwks.json.
	URI string
	// HTTPClient performs the fetch. Required: the caller owns the timeout and
	// TLS configuration.
	HTTPClient *http.Client
	// CacheTTL is how long a fetched set is reused. Zero selects 15 minutes.
	CacheTTL time.Duration
	// MinRefresh is the floor between unknown-kid refetches. Zero selects 1 minute.
	MinRefresh time.Duration
}

// New creates a Verifier. The key set is not fetched yet; the first
// verification, or a call to Refresh, fetches it.
func New(cfg Config) (*Verifier, error) {
	if cfg.URI == "" {
		return nil, fmt.Errorf("jwks: URI is required")
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("jwks: HTTPClient is required")
	}
	v := &Verifier{
		uri:        cfg.URI,
		httpClient: cfg.HTTPClient,
		cacheTTL:   cfg.CacheTTL,
		minRefresh: cfg.MinRefresh,
		now:        time.Now,
	}
	if v.cacheTTL == 0 {
		v.cacheTTL = 15 * time.Minute
	}
	if v.minRefresh == 0 {
		v.minRefresh = time.Minute
	}
	return v, nil
}

// KeyFor returns the public key for kid, fetching or refreshing the key set
// when the cache cannot answer. An empty kid matches a single-key set, which is
// what an issuer that has never rotated publishes.
func (v *Verifier) KeyFor(ctx context.Context, kid string) (any, error) {
	if key, ok := v.cachedKey(kid); ok {
		return key, nil
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	if key, ok := v.cachedKey(kid); ok {
		return key, nil
	}
	return nil, fmt.Errorf("jwks: no key for kid %q", kid)
}

// Refresh fetches the key set unconditionally, ignoring the cache TTL but not
// the refresh floor.
func (v *Verifier) Refresh(ctx context.Context) error { return v.refresh(ctx) }

func (v *Verifier) cachedKey(kid string) (any, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.fetchedAt.IsZero() || v.now().Sub(v.fetchedAt) > v.cacheTTL {
		return nil, false
	}
	if kid == "" {
		if len(v.keys.Keys) == 1 {
			return v.keys.Keys[0].Key, true
		}
		return nil, false
	}
	for _, k := range v.keys.Key(kid) {
		return k.Key, true
	}
	return nil, false
}

func (v *Verifier) refresh(ctx context.Context) error {
	v.mu.Lock()
	if !v.lastAttempt.IsZero() && v.now().Sub(v.lastAttempt) < v.minRefresh {
		v.mu.Unlock()
		return fmt.Errorf("jwks: refresh rate-limited (floor %s)", v.minRefresh)
	}
	v.lastAttempt = v.now()
	v.mu.Unlock()

	set, err := v.fetch(ctx)
	if err != nil {
		return err
	}

	v.mu.Lock()
	v.keys = *set
	v.fetchedAt = v.now()
	v.mu.Unlock()
	return nil
}

func (v *Verifier) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.uri, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: fetch %s: %w", v.uri, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: fetch %s: unexpected status %d", v.uri, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBody+1))
	if err != nil {
		return nil, fmt.Errorf("jwks: read body: %w", err)
	}
	if len(body) > maxJWKSBody {
		return nil, fmt.Errorf("jwks: key set larger than %d bytes", maxJWKSBody)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("jwks: decode key set: %w", err)
	}

	// Drop anything that is not a usable public verification key, so a set
	// carrying a private key or a symmetric key cannot be selected later.
	kept := set.Keys[:0]
	for _, k := range set.Keys {
		if !k.IsPublic() || !k.Valid() {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		kept = append(kept, k)
	}
	set.Keys = kept

	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("jwks: %s served no usable public signing key", v.uri)
	}
	return &set, nil
}

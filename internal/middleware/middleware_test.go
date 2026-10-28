package middleware_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gin-gonic/gin"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/middleware"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newRouter wires a single middleware in front of a trivial GET /test handler.
func newRouter(mw gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(mw)
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// get performs a GET /test request through r and returns the response recorder.
func get(r *gin.Engine, header ...string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	r.ServeHTTP(w, req)
	return w
}

// ── SecurityHeaders ───────────────────────────────────────────────────────────

func TestSecurityHeaders_AllHeadersSet(t *testing.T) {
	r := newRouter(middleware.SecurityHeaders())
	w := get(r)
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Cache-Control":          "no-store",
	}
	for hdr, val := range want {
		if got := w.Header().Get(hdr); got != val {
			t.Errorf("header %q: got %q, want %q", hdr, got, val)
		}
	}
}

func TestSecurityHeaders_PassThrough(t *testing.T) {
	r := newRouter(middleware.SecurityHeaders())
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ── AppKeyAuth ────────────────────────────────────────────────────────────────

func TestAppKeyAuth_DisabledIsNoOp(t *testing.T) {
	cfg := &config.SecurityConfig{} // AppKey == ""
	r := newRouter(middleware.AppKeyAuth(cfg, zap.NewNop()))
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200 (no-op), got %d", w.Code)
	}
}

func TestAppKeyAuth_CorrectTokenAllowed(t *testing.T) {
	cfg := &config.SecurityConfig{AppKey: "s3cr3t"}
	r := newRouter(middleware.AppKeyAuth(cfg, zap.NewNop()))
	if w := get(r, "Authorization", "Bearer s3cr3t"); w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAppKeyAuth_WrongTokenRejected(t *testing.T) {
	cfg := &config.SecurityConfig{AppKey: "s3cr3t"}
	r := newRouter(middleware.AppKeyAuth(cfg, zap.NewNop()))
	if w := get(r, "Authorization", "Bearer wrong"); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAppKeyAuth_MissingTokenRejected(t *testing.T) {
	cfg := &config.SecurityConfig{AppKey: "s3cr3t"}
	r := newRouter(middleware.AppKeyAuth(cfg, zap.NewNop()))
	if w := get(r); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAppKeyAuth_BearerPrefixRequired(t *testing.T) {
	// Supplying the key without "Bearer " must be rejected.
	cfg := &config.SecurityConfig{AppKey: "s3cr3t"}
	r := newRouter(middleware.AppKeyAuth(cfg, zap.NewNop()))
	if w := get(r, "Authorization", "s3cr3t"); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── RateLimit ─────────────────────────────────────────────────────────────────

func TestRateLimit_DisabledIsNoOp(t *testing.T) {
	cfg := &config.SecurityConfig{RateLimit: config.RateLimitConfig{Enabled: false}}
	rl, _ := middleware.RateLimit(cfg, zap.NewNop())
	r := newRouter(rl)
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200 (no-op), got %d", w.Code)
	}
}

func TestRateLimit_ZeroRPMIsNoOp(t *testing.T) {
	cfg := &config.SecurityConfig{
		RateLimit: config.RateLimitConfig{Enabled: true, RequestsPerMinute: 0},
	}
	rl, _ := middleware.RateLimit(cfg, zap.NewNop())
	r := newRouter(rl)
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200 (no-op), got %d", w.Code)
	}
}

func TestRateLimit_AllowsWithinLimit(t *testing.T) {
	cfg := &config.SecurityConfig{
		RateLimit: config.RateLimitConfig{Enabled: true, RequestsPerMinute: 5},
	}
	rl, stop := middleware.RateLimit(cfg, zap.NewNop())
	defer stop()
	r := newRouter(rl)
	for i := range 5 {
		if w := get(r); w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimit_BlocksWhenExceeded(t *testing.T) {
	cfg := &config.SecurityConfig{
		RateLimit: config.RateLimitConfig{Enabled: true, RequestsPerMinute: 2},
	}
	rl, stop := middleware.RateLimit(cfg, zap.NewNop())
	defer stop()
	r := newRouter(rl)
	codes := make([]int, 4)
	for i := range 4 {
		codes[i] = get(r).Code
	}
	// After 2 allowed requests the 3rd or 4th must be 429.
	got429 := false
	for _, c := range codes[2:] {
		if c == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Errorf("expected at least one 429 after exceeding limit; codes: %v", codes)
	}
}

// ── RequestLogger ─────────────────────────────────────────────────────────────

func TestRequestLogger_PassesThrough(t *testing.T) {
	r := newRouter(middleware.RequestLogger(zap.NewNop()))
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ── TenantAuth ────────────────────────────────────────────────────────────────

// buildTestRegistry creates a single-tenant registry with empty policy (no rules dir).
func buildTestRegistry(t *testing.T) *tenant.Registry {
	t.Helper()
	cfg := &config.Config{
		Policy: config.PolicyConfig{},
		Issuer: config.IssuerConfig{Scope: "test-scope"},
	}
	reg, err := tenant.NewRegistry(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

// makeJWT signs a MapClaims with the given HMAC secret.
// Pass tenantID == "" to omit the tenant_id claim (tests default-fallback path).
func makeJWT(t *testing.T, secret, issuer, tenantID string) string {
	t.Helper()
	claims := jwtlib.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if issuer != "" {
		claims["iss"] = issuer
	}
	if tenantID != "" {
		claims["tenant_id"] = tenantID
	}
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return s
}

// TestTenantAuth_DevMode passes all requests without any auth header.
func TestTenantAuth_DevModePassThrough(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{} // no JWT.Secret, no Security.AppKey
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200 (dev mode), got %d", w.Code)
	}
}

// TestTenantAuth_LegacyMode_CorrectKey exercises the plain Bearer fallback path.
func TestTenantAuth_LegacyMode_CorrectKey(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{Security: config.SecurityConfig{AppKey: "s3cr3t"}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	if w := get(r, "Authorization", "Bearer s3cr3t"); w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestTenantAuth_LegacyMode_WrongKey(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{Security: config.SecurityConfig{AppKey: "s3cr3t"}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	if w := get(r, "Authorization", "Bearer wrong"); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestTenantAuth_LegacyMode_MissingHeader(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{Security: config.SecurityConfig{AppKey: "s3cr3t"}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	if w := get(r); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTenantAuth_JWT_ValidToken verifies a correctly signed JWT grants access.
func TestTenantAuth_JWT_ValidToken(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	tok := makeJWT(t, "test-secret", "", "")
	if w := get(r, "Authorization", "Bearer "+tok); w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestTenantAuth_JWT_InvalidToken verifies a tampered JWT is rejected.
func TestTenantAuth_JWT_InvalidToken(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	if w := get(r, "Authorization", "Bearer invalid.jwt.token"); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTenantAuth_JWT_WrongSecret verifies a JWT signed with a different secret is rejected.
func TestTenantAuth_JWT_WrongSecret(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "correct-secret", RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	tok := makeJWT(t, "wrong-secret", "", "")
	if w := get(r, "Authorization", "Bearer "+tok); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTenantAuth_JWT_WrongIssuer verifies iss claim validation.
func TestTenantAuth_JWT_WrongIssuer(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{
		Secret:      "test-secret",
		Issuer:      "https://expected.example.org",
		RequireAuth: true,
	}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	tok := makeJWT(t, "test-secret", "https://wrong.example.org", "")
	if w := get(r, "Authorization", "Bearer "+tok); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTenantAuth_JWT_NoRequireAuth_NoToken verifies unauthenticated requests get
// the default tenant when require_auth is false.
func TestTenantAuth_JWT_NoRequireAuth_NoToken(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", RequireAuth: false}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200 (default tenant fallback), got %d", w.Code)
	}
}

// TestTenantAuth_JWT_UnknownTenantFallsBackToDefault verifies that a valid JWT
// with an unconfigured tenant_id falls back to the "default" tenant rather than
// returning 401 — crucial for the "most tenants use default settings" use-case.
func TestTenantAuth_JWT_UnknownTenantFallsBackToDefault(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	tok := makeJWT(t, "test-secret", "", "unknown-tenant-xyz")
	if w := get(r, "Authorization", "Bearer "+tok); w.Code != http.StatusOK {
		t.Errorf("expected 200 (fallback to default), got %d", w.Code)
	}
}

// TestTenantAuth_JWT_MissingHeaderRequireAuth verifies 401 when header absent and require_auth=true.
func TestTenantAuth_JWT_MissingHeaderRequireAuth(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))
	if w := get(r); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── MaxConcurrent ─────────────────────────────────────────────────────────────

func TestMaxConcurrent_AllowsUnderLimit(t *testing.T) {
	r := newRouter(middleware.MaxConcurrent(2))
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestMaxConcurrent_DisabledWhenZero(t *testing.T) {
	r := newRouter(middleware.MaxConcurrent(0))
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200 (no-op), got %d", w.Code)
	}
}

func TestMaxConcurrent_RejectsWhenFull(t *testing.T) {
	started := make(chan struct{})
	block := make(chan struct{})
	r := gin.New()
	r.Use(middleware.MaxConcurrent(1))
	r.GET("/test", func(c *gin.Context) {
		started <- struct{}{} // signal handler is running
		<-block               // wait for test to unblock
		c.Status(http.StatusOK)
	})

	// First request occupies the single slot.
	go func() {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)
	}()
	<-started // first request is in the handler, holding the semaphore

	// Second request must be rejected immediately.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when all slots occupied, got %d", w.Code)
	}

	close(block) // let first request complete
}

// ── Prometheus ────────────────────────────────────────────────────────────────

func TestPrometheus_RecordsMetrics(t *testing.T) {
	r := gin.New()
	r.Use(middleware.Prometheus("/skip"))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/skip", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Request to /test should be recorded.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Request to /skip should not be recorded but still served.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/skip", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("skip path: expected 200, got %d", w2.Code)
	}
}

func TestPrometheus_UnmatchedPath(t *testing.T) {
	r := gin.New()
	r.Use(middleware.Prometheus())
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Request to a non-existent path — should label as "unmatched".
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	r.ServeHTTP(w, req)
	// Gin returns 404 for unmatched routes when NoRoute is not set.
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unmatched, got %d", w.Code)
	}
}

// ── JWKS (ES256) verification, issue #12 ─────────────────────────────────────

// jwksServer serves a key set holding pub under kid, counting requests so a
// test can assert the set is cached rather than fetched per request.
func jwksServer(t *testing.T, kid string, pub crypto.PublicKey, hits *int32) *httptest.Server {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       pub,
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newES256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// makeES256JWT signs claims with key, putting kid in the header.
func makeES256JWT(t *testing.T, key *ecdsa.PrivateKey, kid, tenantID string) string {
	t.Helper()
	claims := jwtlib.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}
	if tenantID != "" {
		claims["tenant_id"] = tenantID
	}
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodES256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign ES256 JWT: %v", err)
	}
	return s
}

func TestTenantAuth_JWKS_AcceptsES256(t *testing.T) {
	key := newES256Key(t)
	srv := jwksServer(t, "kid-1", key.Public(), nil)

	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{JWKSURI: srv.URL, RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))

	token := makeES256JWT(t, key, "kid-1", "")
	if w := get(r, "Authorization", "Bearer "+token); w.Code != http.StatusOK {
		t.Errorf("expected 200 for a valid ES256 token, got %d", w.Code)
	}
}

func TestTenantAuth_JWKS_RejectsOtherKey(t *testing.T) {
	srv := jwksServer(t, "kid-1", newES256Key(t).Public(), nil)

	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{JWKSURI: srv.URL, RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))

	// Signed by a key the issuer never published, but presenting a kid it did.
	token := makeES256JWT(t, newES256Key(t), "kid-1", "")
	if w := get(r, "Authorization", "Bearer "+token); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for a token signed by an unpublished key, got %d", w.Code)
	}
}

func TestTenantAuth_JWKS_RejectsUnknownKid(t *testing.T) {
	key := newES256Key(t)
	srv := jwksServer(t, "kid-1", key.Public(), nil)

	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{JWKSURI: srv.URL, RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))

	token := makeES256JWT(t, key, "kid-does-not-exist", "")
	if w := get(r, "Authorization", "Bearer "+token); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for an unknown kid, got %d", w.Code)
	}
}

// TestTenantAuth_JWKS_RejectsHMACSignedWithThePublicKey covers the algorithm
// confusion case in the key-set-only configuration. An attacker takes the
// issuer's PUBLIC key -- published, by design, at the JWKS endpoint -- and uses
// it as an HMAC secret to sign a token whose header says HS256.
//
// Here the refusal comes from WithValidMethods, which lists no HS* algorithm
// when no secret is configured, so the token never reaches the keyfunc. The
// keyfunc's own family switch is covered by
// TestTenantAuth_DualValidation_RejectsHMACSignedWithThePublicKey, which is
// the configuration where a forged HS256 token does reach it.
func TestTenantAuth_JWKS_RejectsHMACSignedWithThePublicKey(t *testing.T) {
	key := newES256Key(t)
	srv := jwksServer(t, "kid-1", key.Public(), nil)

	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{JWKSURI: srv.URL, RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))

	// The published public key, in the form an attacker would read it from the
	// JWKS endpoint, used as an HMAC secret.
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	for _, method := range []jwtlib.SigningMethod{
		jwtlib.SigningMethodHS256, jwtlib.SigningMethodHS384, jwtlib.SigningMethodHS512,
	} {
		t.Run(method.Alg(), func(t *testing.T) {
			tok := jwtlib.NewWithClaims(method, jwtlib.MapClaims{
				"exp":       time.Now().Add(time.Hour).Unix(),
				"tenant_id": "default",
			})
			tok.Header["kid"] = "kid-1"
			forged, err := tok.SignedString(pubDER)
			if err != nil {
				t.Fatalf("sign forged token: %v", err)
			}
			if w := get(r, "Authorization", "Bearer "+forged); w.Code != http.StatusUnauthorized {
				t.Errorf("expected 401 for an %s token forged with the published public key, got %d",
					method.Alg(), w.Code)
			}
		})
	}
}

// TestTenantAuth_DualValidation_RejectsHMACSignedWithThePublicKey is the test
// that actually exercises the keyfunc's family switch.
//
// With only a key set configured, WithValidMethods does not list HS* at all, so
// an HS256 token is refused before the keyfunc runs -- which is why
// TestTenantAuth_JWKS_RejectsHMACSignedWithThePublicKey above still passes if
// the family switch is removed. In the dual-validation window both families are
// listed, the forged token reaches the keyfunc, and only the switch on
// t.Method stands between the issuer's published public key and its use as an
// HMAC secret. Verified by mutation: make the HMAC branch return the JWKS key's
// DER bytes and this test fails while that one does not.
func TestTenantAuth_DualValidation_RejectsHMACSignedWithThePublicKey(t *testing.T) {
	key := newES256Key(t)
	srv := jwksServer(t, "kid-1", key.Public(), nil)

	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{
		JWKSURI:     srv.URL,
		Secret:      "shared-secret",
		RequireAuth: true,
	}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))

	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	for _, secret := range []struct {
		name  string
		bytes []byte
	}{
		{"pkix_der", pubDER},
		{"uncompressed_point", elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)},
	} {
		t.Run(secret.name, func(t *testing.T) {
			tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
				"exp":       time.Now().Add(time.Hour).Unix(),
				"tenant_id": "default",
			})
			tok.Header["kid"] = "kid-1"
			forged, err := tok.SignedString(secret.bytes)
			if err != nil {
				t.Fatalf("sign forged token: %v", err)
			}
			if w := get(r, "Authorization", "Bearer "+forged); w.Code != http.StatusUnauthorized {
				t.Errorf("expected 401 for an HS256 token forged with the published public key (%s), got %d",
					secret.name, w.Code)
			}
		})
	}
}

// TestTenantAuth_JWKS_RejectsAlgNone covers the other half of the family
// check: an unsigned token must not be accepted whatever is configured.
func TestTenantAuth_JWKS_RejectsAlgNone(t *testing.T) {
	srv := jwksServer(t, "kid-1", newES256Key(t).Public(), nil)

	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{JWKSURI: srv.URL, RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))

	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, jwtlib.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	unsigned, err := tok.SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("build alg=none token: %v", err)
	}
	if w := get(r, "Authorization", "Bearer "+unsigned); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for alg=none, got %d", w.Code)
	}
}

// TestTenantAuth_SecretOnly_RejectsES256 is the mirror image: with only a
// shared secret configured, an ES256 token has no key to be checked against
// and must be refused rather than fall through to the HMAC branch.
func TestTenantAuth_SecretOnly_RejectsES256(t *testing.T) {
	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "shared-secret", RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))

	token := makeES256JWT(t, newES256Key(t), "kid-1", "")
	if w := get(r, "Authorization", "Bearer "+token); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for ES256 with no key set configured, got %d", w.Code)
	}
}

// TestTenantAuth_DualValidation is the migration window the issue asks for:
// both a key set and a secret configured, each accepting its own family.
func TestTenantAuth_DualValidation(t *testing.T) {
	key := newES256Key(t)
	srv := jwksServer(t, "kid-1", key.Public(), nil)

	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{
		JWKSURI:     srv.URL,
		Secret:      "shared-secret",
		RequireAuth: true,
	}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))

	es256 := makeES256JWT(t, key, "kid-1", "")
	if w := get(r, "Authorization", "Bearer "+es256); w.Code != http.StatusOK {
		t.Errorf("ES256: expected 200, got %d", w.Code)
	}

	hs256 := makeJWT(t, "shared-secret", "", "")
	if w := get(r, "Authorization", "Bearer "+hs256); w.Code != http.StatusOK {
		t.Errorf("HS256: expected 200, got %d", w.Code)
	}

	// Still no crossing over: the wrong secret fails even though a key set is
	// configured too.
	wrong := makeJWT(t, "not-the-secret", "", "")
	if w := get(r, "Authorization", "Bearer "+wrong); w.Code != http.StatusUnauthorized {
		t.Errorf("HS256 with the wrong secret: expected 401, got %d", w.Code)
	}
}

// TestTenantAuth_JWKS_CachesKeySet pins that the key set is not refetched per
// request: the issuer's endpoint is on the hot path of every authenticated
// call, and a fetch per request would make this service a load generator.
func TestTenantAuth_JWKS_CachesKeySet(t *testing.T) {
	var hits int32
	key := newES256Key(t)
	srv := jwksServer(t, "kid-1", key.Public(), &hits)

	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{JWKSURI: srv.URL, RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))

	token := makeES256JWT(t, key, "kid-1", "")
	for i := 0; i < 5; i++ {
		if w := get(r, "Authorization", "Bearer "+token); w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("key set was fetched %d times for 5 requests, want 1", n)
	}
}

// TestTenantAuth_JWKS_TenantClaimStillApplies proves the tenant_id claim is
// read from an ES256 token exactly as from an HMAC one.
func TestTenantAuth_JWKS_TenantClaimStillApplies(t *testing.T) {
	key := newES256Key(t)
	srv := jwksServer(t, "kid-1", key.Public(), nil)

	reg := buildTestRegistry(t)
	cfg := &config.Config{JWT: config.JWTConfig{JWKSURI: srv.URL, RequireAuth: true}}
	r := newRouter(middleware.TenantAuth(reg, cfg, zap.NewNop()))

	// An unknown tenant_id falls back to "default", same as the HMAC path.
	token := makeES256JWT(t, key, "kid-1", "no-such-tenant")
	if w := get(r, "Authorization", "Bearer "+token); w.Code != http.StatusOK {
		t.Errorf("expected 200 with fallback to the default tenant, got %d", w.Code)
	}
}

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestRateLimit_Blocks_WhenExceeded(t *testing.T) {
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
func TestTenantAuth_DevMode_PassThrough(t *testing.T) {
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

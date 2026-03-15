package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/middleware"
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
	r := newRouter(middleware.RateLimit(cfg, zap.NewNop()))
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200 (no-op), got %d", w.Code)
	}
}

func TestRateLimit_ZeroRPMIsNoOp(t *testing.T) {
	cfg := &config.SecurityConfig{
		RateLimit: config.RateLimitConfig{Enabled: true, RequestsPerMinute: 0},
	}
	r := newRouter(middleware.RateLimit(cfg, zap.NewNop()))
	if w := get(r); w.Code != http.StatusOK {
		t.Errorf("expected 200 (no-op), got %d", w.Code)
	}
}

func TestRateLimit_AllowsWithinLimit(t *testing.T) {
	cfg := &config.SecurityConfig{
		RateLimit: config.RateLimitConfig{Enabled: true, RequestsPerMinute: 5},
	}
	r := newRouter(middleware.RateLimit(cfg, zap.NewNop()))
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
	r := newRouter(middleware.RateLimit(cfg, zap.NewNop()))
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

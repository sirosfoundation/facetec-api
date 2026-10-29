// Package middleware provides Gin middleware for facetec-api.
package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/go-tokenauth/validator"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

// AppKeyAuth returns a middleware that requires a Bearer token matching cfg.Security.AppKey.
// If AppKey is empty (development mode), the middleware is a no-op and logs a warning.
func AppKeyAuth(cfg *config.SecurityConfig, log *zap.Logger) gin.HandlerFunc {
	if cfg.AppKey == "" {
		log.Warn("SECURITY: app key authentication is DISABLED — not suitable for production")
		return func(c *gin.Context) { c.Next() }
	}
	expected := []byte("Bearer " + cfg.AppKey)
	return func(c *gin.Context) {
		got := []byte(c.GetHeader("Authorization"))
		// Constant-time compare to prevent timing attacks.
		if subtle.ConstantTimeCompare(got, expected) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

// TenantAuth selects the appropriate authentication mode from cfg and returns a
// middleware that resolves every request to a [tenant.Context].
//
// Three modes, evaluated in order:
//   - JWT mode (cfg.JWT.JWKSURI != "" or cfg.JWT.Secret != ""): validates a
//     Bearer JWT with go-tokenauth and extracts the tenant_id claim to select
//     the tenant. A missing or unknown tenant_id falls back to the "default"
//     tenant, so deployments with a single policy need no per-request
//     tenant_id at all. With jwks_uri, tokens are verified against the
//     issuer's published public keys and this service holds nothing that can
//     mint one; with secret, they are verified against a shared HMAC secret,
//     which can. Both may be configured during the migration (#12).
//   - Legacy mode (cfg.Security.AppKey != "", no JWT secret): constant-time
//     comparison of the raw Bearer token against the global app key. All
//     requests use the "default" tenant. Retained for backward compatibility
//     with single-tenant deployments.
//   - Dev mode (both empty): no authentication; the "default" tenant is always
//     injected and a warning is logged once at construction time.
//
// The second return value stops the background JWKS refresh that JWT mode
// starts; it is nil in the other two modes. Callers must invoke it during
// shutdown, as they already do for [RateLimit], or leak a goroutine.
func TenantAuth(registry *tenant.Registry, cfg *config.Config, log *zap.Logger) (gin.HandlerFunc, func()) {
	switch {
	case cfg.JWT.JWKSURI != "", cfg.JWT.Secret != "":
		return jwtTenantAuth(registry, cfg.JWT, log)
	case cfg.Security.AppKey != "":
		return legacyBearerTenantAuth(registry, cfg.Security.AppKey, log), nil
	default:
		defTenant, _ := registry.Resolve("default")
		log.Warn("SECURITY: authentication is DISABLED (no jwt.secret or security.app_key configured) — not suitable for production")
		return func(c *gin.Context) {
			tenant.SetGin(c, defTenant)
			c.Request = c.Request.WithContext(tenant.WithStdContext(c.Request.Context(), defTenant))
			c.Next()
		}, nil
	}
}

// jwtTenantAuth validates Bearer JWTs with go-tokenauth and resolves the
// tenant_id claim to a [tenant.Context]. A missing or unconfigured tenant_id
// falls back to the "default" tenant, so tokens without a tenant_id claim work
// correctly for single-tenant deployments.
//
// Signature verification is keyed on the algorithm family and nothing else:
// go-tokenauth routes an ES256/ES384/EdDSA token to a public key from the
// issuer's key set and an HS256/HS384/HS512 token to the shared secret, and
// neither key is ever offered to the other family. That separation is the
// whole mitigation for algorithm confusion -- a token header claiming HS256
// while carrying a signature made with the issuer's published public key as
// the HMAC secret is the classic attack, and it fails because the HMAC path
// never sees a JWKS key. A family with no key configured is refused outright
// rather than falling through: with jwks_uri alone, legacy HMAC validation is
// switched off entirely.
//
// Returns a stop function for the validator's background key refresh.
func jwtTenantAuth(registry *tenant.Registry, jwtCfg config.JWTConfig, log *zap.Logger) (gin.HandlerFunc, func()) {
	v := validator.New(validator.Config{
		JWKSURL:     jwtCfg.JWKSURI,
		JWKSRefresh: jwtCfg.JWKSRefresh,
		Issuer:      jwtCfg.Issuer,
		Audiences:   jwtCfg.Audience,
		Legacy: validator.LegacyConfig{
			// Only enabled when a secret is actually configured, so a
			// deployment that has finished the migration refuses every HS*
			// token outright instead of reporting a key mismatch.
			Enabled:    jwtCfg.Secret != "",
			HMACSecret: []byte(jwtCfg.Secret),
			Issuers:    []string{jwtCfg.Issuer},
		},
	})
	v.Start(context.Background())

	switch {
	case jwtCfg.JWKSURI != "" && jwtCfg.Secret != "":
		log.Warn("jwt.secret is still configured alongside jwt.jwks_uri: HMAC-signed tokens remain accepted. Remove jwt.secret to finish the migration",
			zap.String("jwks_uri", jwtCfg.JWKSURI))
	case jwtCfg.JWKSURI != "":
		log.Info("verifying Bearer JWTs against the issuer's key set", zap.String("jwks_uri", jwtCfg.JWKSURI))
	default:
		log.Info("verifying Bearer JWTs against the shared HMAC secret (jwt.secret); prefer jwt.jwks_uri")
	}

	handler := func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			if !jwtCfg.RequireAuth {
				// Unauthenticated requests use the default tenant.
				injectTenant(c, registry, "default", log)
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		result, err := v.Validate(c.Request.Context(), strings.TrimPrefix(h, "Bearer "))
		if err != nil {
			log.Debug("JWT validation failed", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		tenantID := result.TenantID
		if tenantID == "" {
			tenantID = "default"
		}
		if !injectTenant(c, registry, tenantID, log) {
			return
		}
		c.Next()
	}
	return handler, v.Stop
}

// legacyBearerTenantAuth performs a constant-time comparison of the raw Bearer
// token against appKey and injects the "default" tenant on success. This mode
// is retained for backward compatibility — new deployments should use jwt:
func legacyBearerTenantAuth(registry *tenant.Registry, appKey string, log *zap.Logger) gin.HandlerFunc {
	expected := []byte("Bearer " + appKey)
	defTenant, _ := registry.Resolve("default")
	log.Info("using legacy single-tenant Bearer authentication (configure jwt: for multi-tenant support)")
	return func(c *gin.Context) {
		got := []byte(c.GetHeader("Authorization"))
		if subtle.ConstantTimeCompare(got, expected) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		tenant.SetGin(c, defTenant)
		c.Request = c.Request.WithContext(tenant.WithStdContext(c.Request.Context(), defTenant))
		c.Next()
	}
}

// injectTenant resolves tenantID from the registry and injects the resulting
// [tenant.Context] into both the Gin and stdlib request contexts. Falls back to
// the "default" tenant when tenantID is not configured — this allows JWTs with
// unknown or absent tenant_id claims to work in single-policy deployments.
// Returns false and aborts c if neither the requested tenant nor "default" exists.
func injectTenant(c *gin.Context, registry *tenant.Registry, tenantID string, log *zap.Logger) bool {
	tc, ok := registry.Resolve(tenantID)
	if !ok && tenantID != "default" {
		log.Debug("tenant not configured, using default", zap.String("requested", tenantID))
		tc, ok = registry.Resolve("default")
	}
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return false
	}
	tenant.SetGin(c, tc)
	c.Request = c.Request.WithContext(tenant.WithStdContext(c.Request.Context(), tc))
	return true
}

// RateLimit returns a per-IP sliding-window rate limiter middleware and a stop
// function that halts its background cleanup goroutine. The caller must invoke
// the returned stop function during shutdown to prevent a goroutine leak.
// If cfg.RateLimit.Enabled is false, the middleware is a no-op and stop is nil.
func RateLimit(cfg *config.SecurityConfig, log *zap.Logger) (gin.HandlerFunc, func()) {
	if !cfg.RateLimit.Enabled || cfg.RateLimit.RequestsPerMinute <= 0 {
		return func(c *gin.Context) { c.Next() }, nil
	}
	rpm := cfg.RateLimit.RequestsPerMinute
	type entry struct {
		mu         sync.Mutex
		timestamps []time.Time
	}
	var mu sync.Mutex
	buckets := make(map[string]*entry)
	done := make(chan struct{})

	// Background cleanup: remove stale IP buckets to prevent unbounded map growth (S4).
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cutoff := time.Now().Add(-time.Minute)
				mu.Lock()
				for ip, e := range buckets {
					e.mu.Lock()
					if len(e.timestamps) == 0 || e.timestamps[len(e.timestamps)-1].Before(cutoff) {
						delete(buckets, ip)
					}
					e.mu.Unlock()
				}
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()

	stop := func() { close(done) }

	handler := func(c *gin.Context) {
		ip := c.ClientIP()
		mu.Lock()
		e, ok := buckets[ip]
		if !ok {
			e = &entry{}
			buckets[ip] = e
		}
		mu.Unlock()

		now := time.Now()
		window := now.Add(-time.Minute)

		e.mu.Lock()
		// Evict timestamps outside the window.
		kept := e.timestamps[:0]
		for _, t := range e.timestamps {
			if t.After(window) {
				kept = append(kept, t)
			}
		}
		e.timestamps = kept
		allowed := len(e.timestamps) < rpm
		if allowed {
			e.timestamps = append(e.timestamps, now)
		}
		e.mu.Unlock()

		if !allowed {
			log.Info("rate limit exceeded", zap.String("ip", ip), zap.String("path", c.Request.URL.Path))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}

	return handler, stop
}

// MaxConcurrent returns a middleware that caps the number of requests processed
// simultaneously. When n slots are occupied, excess requests receive 503
// (Service Unavailable) immediately rather than queuing. This bounds peak
// memory from large biometric payloads under concurrency.
// n <= 0 disables the limit (no-op middleware).
func MaxConcurrent(n int) gin.HandlerFunc {
	if n <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	sem := make(chan struct{}, n)
	return func(c *gin.Context) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			c.Next()
		default:
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": "server busy, please retry",
			})
		}
	}
}

// SecurityHeaders adds common HTTP security response headers to all responses.
// These prevent MIME sniffing, clickjacking, and inadvertent caching of credentials.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Cache-Control", "no-store")
		c.Next()
	}
}

// RequestLogger returns a structured zap request-logging middleware.
// It deliberately does NOT log request or response bodies to prevent
// accidental capture of biometric data.
func RequestLogger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		log.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("ip", c.ClientIP()),
			zap.String("user_agent", strings.TrimSpace(c.Request.UserAgent())),
		)
	}
}

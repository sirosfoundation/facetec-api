// Package middleware provides Gin middleware for facetec-api.
package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
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

// RateLimit returns a per-IP sliding-window rate limiter middleware.
// Requests exceeding rpm per minute from a single IP receive HTTP 429.
// If cfg.RateLimit.Enabled is false, the middleware is a no-op.
func RateLimit(cfg *config.SecurityConfig, log *zap.Logger) gin.HandlerFunc {
	if !cfg.RateLimit.Enabled || cfg.RateLimit.RequestsPerMinute <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	rpm := cfg.RateLimit.RequestsPerMinute
	type entry struct {
		mu        sync.Mutex
		timestamps []time.Time
	}
	var mu sync.Mutex
	buckets := make(map[string]*entry)

	// Background cleanup: remove stale IP buckets to prevent unbounded map growth (S4).
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
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
		}
	}()

	return func(c *gin.Context) {
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

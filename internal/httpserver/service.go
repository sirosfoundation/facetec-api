package httpserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/middleware"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

// Service is the HTTP server for facetec-api.
type Service struct {
	cfg    *config.Config
	log    *zap.Logger
	apiv1  Apiv1
	router *gin.Engine
	server *http.Server
}

// New creates and configures the HTTP service but does not start listening.
// registry is used to resolve Bearer tokens to tenant contexts on every request.
func New(_ context.Context, cfg *config.Config, apiv1 Apiv1, registry *tenant.Registry, log *zap.Logger) *Service {
	if cfg.Logging.Production {
		gin.SetMode(gin.ReleaseMode)
	}

	// Use gin.New() (not gin.Default()) so we control every middleware and
	// never accidentally log request bodies that may contain biometric data.
	router := gin.New()
	router.Use(
		gin.RecoveryWithWriter(nil), // panic recovery without body logging
		middleware.SecurityHeaders(),
		middleware.RequestLogger(log),
	)

	svc := &Service{cfg: cfg, log: log, apiv1: apiv1, router: router}
	svc.registerRoutes(router, registry)

	svc.server = &http.Server{
		Addr:              cfg.Server.Address(),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		// WriteTimeout must be longer than the FaceTec round-trip timeout.
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return svc
}

// Handler returns the underlying http.Handler, enabling use with httptest.NewServer in tests.
func (s *Service) Handler() http.Handler {
	return s.router
}

// Start begins listening. It blocks until the server stops.
// http.ErrServerClosed is treated as a clean shutdown and is not returned.
func (s *Service) Start(_ context.Context) error {
	s.log.Info("facetec-api HTTP server starting", zap.String("addr", s.cfg.Server.Address()))
	var err error
	if s.cfg.Server.TLS.Enabled {
		err = s.server.ListenAndServeTLS(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile)
	} else {
		err = s.server.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close gracefully shuts down the HTTP server.
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("facetec-api HTTP server shutting down")
	return s.server.Shutdown(ctx)
}

func (s *Service) registerRoutes(r *gin.Engine, registry *tenant.Registry) {
	// Unauthenticated probes — always accessible.
	r.GET("/livez", s.endpointLivez)
	r.GET("/readyz", s.endpointReadyz)

	// Versioned API — authentication + rate limiting applied to all routes.
	auth := middleware.TenantAuth(registry, s.cfg, s.log)
	rl := middleware.RateLimit(&s.cfg.Security, s.log)

	v1 := r.Group("/v1", auth)
	{
		// Health (authenticated, no rate limit).
		v1.GET("/health", s.endpointHealth)

		// Biometric endpoints — additionally rate-limited.
		bio := v1.Group("", rl)
		bio.POST("/session-token", s.endpointSessionToken)
		bio.POST("/liveness", s.endpointLiveness)
		bio.POST("/id-scan", s.endpointIDScan)

		// Offer redemption — authenticated, no rate limit (wallet pull).
		v1.GET("/offer/:txid", s.endpointOffer)
	}
}

// respond writes a JSON response using the supplied HTTP status code.
func (s *Service) respond(c *gin.Context, status int, body any) {
	c.JSON(status, body)
}

// fail logs err internally and writes a safe JSON error response.
// The raw error detail is never sent to the caller to avoid leaking internals.
func (s *Service) fail(c *gin.Context, status int, err error, clientMsg string) {
	if err != nil {
		s.log.Error(clientMsg, zap.Error(err), zap.Int("status", status))
	}
	c.JSON(status, gin.H{"error": clientMsg})
	c.Abort()
}

// bindJSON decodes a JSON body into dst, failing the request on error.
// The body is capped at 10 MB to prevent memory exhaustion (S3).
func (s *Service) bindJSON(c *gin.Context, dst any) error {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 10<<20) // 10 MB
	if err := c.ShouldBindJSON(dst); err != nil {
		// Use a generic client message to avoid leaking internal struct/field names (S1).
		s.fail(c, http.StatusBadRequest, err, "invalid request body")
		return err
	}
	return nil
}

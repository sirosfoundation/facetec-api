// Package tenant provides multi-tenancy for facetec-api.
//
// Each tenant owns its own SPOCP policy engine (rules + numeric thresholds) and
// issuer parameters (credential scope + format). The FaceTec Server connection,
// HTTP infrastructure, and in-memory session store are shared across all tenants.
//
// # Authentication
//
// Tenant selection is performed by [middleware.TenantAuth] at request time.
// Three modes are available, evaluated in order:
//
//  1. JWT mode (jwt.secret configured): an HMAC-signed Bearer JWT is validated;
//     the tenant_id claim selects the tenant. Tokens without a tenant_id, or
//     with an unconfigured value, fall back to the "default" tenant.
//  2. Legacy Bearer mode (security.app_key set, no JWT secret): constant-time
//     comparison of the raw token against a single global key. All requests use
//     the "default" tenant. Retained for backward compatibility.
//  3. Dev mode (neither set): no authentication; all requests use "default".
//     A warning is logged at startup. Must not be used in production.
//
// # Registry
//
// A [Registry] is constructed from [config.Config] at startup via [NewRegistry]
// and can be atomically reloaded on SIGHUP via [Registry.Reload] without
// dropping in-flight requests.
//
// # Single-tenant mode
//
// When no tenants: section is present in the config the Registry synthesises a
// single "default" tenant from the global policy and issuer settings.
// Existing single-tenant deployments need no configuration changes.
//
// # Multi-tenant mode
//
// When a tenants: block is present, each [config.TenantConfig] is stored under
// its ID. Unknown tenant_id claims fall back to the "default" tenant, so new
// tenants can be onboarded incrementally without breaking existing tokens.
package tenant

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/policy"
)

// IssuerParams holds the per-tenant issuer parameters.
type IssuerParams struct {
	// Scope is the credential scope URI, e.g. "https://credentials.example.org/photo-id".
	Scope string
	// Format is the credential format: sdjwt (default), mdoc, or vc20.
	Format string
}

// Context is the fully resolved runtime state for a single tenant.
// It is immutable after construction and safe for concurrent use.
type Context struct {
	// ID is the human-readable tenant identifier used in logs and audit records.
	ID string
	// Policy is the SPOCP policy engine loaded with this tenant's rules and thresholds.
	Policy *policy.Engine
	// Issuer holds the credential issuance parameters for this tenant.
	Issuer IssuerParams
}

// snapshot is the immutable key→Context map stored atomically in Registry.
type snapshot map[string]*Context

// Registry maps app keys to tenant Contexts.
// It is safe for concurrent reads and supports atomic full replacement via [Reload].
type Registry struct {
	current atomic.Pointer[snapshot]
}

// NewRegistry constructs a Registry from a fully loaded and validated Config.
// It synthesises a "default" tenant when cfg.Tenants is empty.
func NewRegistry(cfg *config.Config, log *zap.Logger) (*Registry, error) {
	m, err := build(cfg, log)
	if err != nil {
		return nil, err
	}
	r := &Registry{}
	s := snapshot(m)
	r.current.Store(&s)
	return r, nil
}

// Reload atomically replaces all tenant contexts.
// In-flight requests that already hold a *Context proceed unaffected.
func (r *Registry) Reload(cfg *config.Config, log *zap.Logger) error {
	m, err := build(cfg, log)
	if err != nil {
		return err
	}
	s := snapshot(m)
	r.current.Store(&s)
	return nil
}

// Resolve looks up a tenant context by its app key (the raw token, without the
// "Bearer " prefix). In dev mode (no keys configured), the empty string "" maps
// to the default tenant and all requests are accepted.
func (r *Registry) Resolve(key string) (*Context, bool) {
	p := r.current.Load()
	if p == nil {
		return nil, false
	}
	tc, ok := (*p)[key]
	return tc, ok
}

// EmptyPolicies returns the IDs of tenants that have zero SPOCP rules loaded.
// A non-empty result should cause the /readyz probe to return not-ready.
func (r *Registry) EmptyPolicies() []string {
	p := r.current.Load()
	if p == nil {
		return nil
	}
	var empty []string
	for _, tc := range *p {
		if tc.Policy.RuleCount() == 0 {
			empty = append(empty, tc.ID)
		}
	}
	return empty
}

// ── Gin / stdlib context plumbing ─────────────────────────────────────────────

const ginKey = "facetec.tenant"

// SetGin stores tc in the Gin request context.
func SetGin(c *gin.Context, tc *Context) { c.Set(ginKey, tc) }

// GetGin retrieves a *Context from a Gin request context.
// Returns an error if TenantAuth middleware has not run on this request.
func GetGin(c *gin.Context) (*Context, error) {
	v, ok := c.Get(ginKey)
	if !ok {
		return nil, fmt.Errorf("tenant: context not set on request (TenantAuth middleware missing?)")
	}
	tc, ok := v.(*Context)
	if !ok {
		return nil, fmt.Errorf("tenant: context has unexpected type %T", v)
	}
	return tc, nil
}

// stdCtxKey is the unexported key type used for stdlib context values.
// Using a private type prevents collisions with other packages.
type stdCtxKey struct{}

// WithStdContext returns a copy of ctx carrying tc under the package-private key.
func WithStdContext(ctx context.Context, tc *Context) context.Context {
	return context.WithValue(ctx, stdCtxKey{}, tc)
}

// FromStdContext extracts a *Context from a stdlib context.
// Returns (nil, false) if the context was not enriched by WithStdContext.
func FromStdContext(ctx context.Context) (*Context, bool) {
	tc, ok := ctx.Value(stdCtxKey{}).(*Context)
	return tc, ok
}

// ── Internal builders ──────────────────────────────────────────────────────────

func build(cfg *config.Config, log *zap.Logger) (map[string]*Context, error) {
	if len(cfg.Tenants) == 0 {
		return buildSingleTenant(cfg, log)
	}
	return buildMultiTenant(cfg, log)
}

func buildSingleTenant(cfg *config.Config, log *zap.Logger) (map[string]*Context, error) {
	tc, err := newContext("default", cfg.Policy, IssuerParams{
		Scope:  cfg.Issuer.Scope,
		Format: normaliseFormat(cfg.Issuer.Format),
	}, log)
	if err != nil {
		return nil, err
	}
	// Always stored under "default" — auth mode (JWT / legacy Bearer / dev) is
	// determined by the middleware, not by the registry key.
	return map[string]*Context{"default": tc}, nil
}

func buildMultiTenant(cfg *config.Config, log *zap.Logger) (map[string]*Context, error) {
	m := make(map[string]*Context, len(cfg.Tenants))
	for _, t := range cfg.Tenants {
		pol := mergedPolicy(t.Policy, cfg.Policy)
		issuer := mergedIssuer(t.Issuer, cfg.Issuer)
		tc, err := newContext(t.ID, pol, issuer, log)
		if err != nil {
			return nil, fmt.Errorf("tenant %q: %w", t.ID, err)
		}
		// Duplicate IDs are caught by Validate(), but guard here too so Reload()
		// never silently overwrites a live tenant context.
		if _, dup := m[t.ID]; dup {
			return nil, fmt.Errorf("tenant %q: id is duplicated", t.ID)
		}
		m[t.ID] = tc
	}
	return m, nil
}

func newContext(id string, pol config.PolicyConfig, issuer IssuerParams, log *zap.Logger) (*Context, error) {
	engine, err := policy.New(pol.RulesDir)
	if err != nil {
		return nil, fmt.Errorf("policy engine: %w", err)
	}
	log.Info("tenant policy engine ready",
		zap.String("tenant", id),
		zap.Int("rules", engine.RuleCount()),
	)
	if engine.RuleCount() == 0 {
		log.Warn("tenant has no policy rules — all scans will be rejected",
			zap.String("tenant", id),
		)
	}
	return &Context{ID: id, Policy: engine, Issuer: issuer}, nil
}

// mergedPolicy returns a PolicyConfig applying the tenant override on top of
// the global defaults.
func mergedPolicy(override config.TenantPolicyConfig, global config.PolicyConfig) config.PolicyConfig {
	merged := global // copy
	if override.RulesDir != "" {
		merged.RulesDir = override.RulesDir
	}
	return merged
}

// mergedIssuer returns IssuerParams that applies the tenant override on top of
// the global IssuerConfig. Empty strings in the override inherit the global value.
func mergedIssuer(override config.TenantIssuerConfig, global config.IssuerConfig) IssuerParams {
	scope := override.Scope
	if scope == "" {
		scope = global.Scope
	}
	format := normaliseFormat(override.Format)
	if format == "" {
		format = normaliseFormat(global.Format)
	}
	return IssuerParams{Scope: scope, Format: format}
}

// normaliseFormat returns the validated format string, defaulting to "sdjwt".
func normaliseFormat(s string) string {
	switch s {
	case "mdoc", "vc20", "sdjwt":
		return s
	default:
		return "sdjwt"
	}
}

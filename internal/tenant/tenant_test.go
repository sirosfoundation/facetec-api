package tenant_test

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

func init() { gin.SetMode(gin.TestMode) }

// minimalCfg returns a minimal valid config for registry construction.
func minimalCfg() *config.Config {
	return &config.Config{
		Policy: config.PolicyConfig{},
		Issuer: config.IssuerConfig{Scope: "test-scope", Format: "sdjwt"},
	}
}

// ── NewRegistry ───────────────────────────────────────────────────────────────

func TestNewRegistry_SingleTenant_DefaultKey(t *testing.T) {
	reg, err := tenant.NewRegistry(minimalCfg(), zap.NewNop())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	tc, ok := reg.Resolve("default")
	if !ok {
		t.Fatal("expected 'default' tenant to exist in single-tenant mode")
	}
	if tc.ID != "default" {
		t.Errorf("tenant ID: got %q, want \"default\"", tc.ID)
	}
}

func TestNewRegistry_SingleTenant_IssuerParams(t *testing.T) {
	cfg := minimalCfg()
	cfg.Issuer.Scope = "my-scope"
	cfg.Issuer.Format = "mdoc"

	reg, err := tenant.NewRegistry(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	tc, _ := reg.Resolve("default")
	if tc.Issuer.Scope != "my-scope" {
		t.Errorf("Issuer.Scope: got %q, want my-scope", tc.Issuer.Scope)
	}
	if tc.Issuer.Format != "mdoc" {
		t.Errorf("Issuer.Format: got %q, want mdoc", tc.Issuer.Format)
	}
}

func TestNewRegistry_MultiTenant_ResolveByID(t *testing.T) {
	cfg := minimalCfg()
	cfg.Tenants = []config.TenantConfig{
		{ID: "acme", Issuer: config.TenantIssuerConfig{Scope: "acme-scope"}},
		{ID: "gov", Issuer: config.TenantIssuerConfig{Scope: "gov-scope", Format: "mdoc"}},
	}
	reg, err := tenant.NewRegistry(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	acme, ok := reg.Resolve("acme")
	if !ok {
		t.Fatal("expected 'acme' tenant")
	}
	if acme.Issuer.Scope != "acme-scope" {
		t.Errorf("acme scope: got %q", acme.Issuer.Scope)
	}

	gov, ok := reg.Resolve("gov")
	if !ok {
		t.Fatal("expected 'gov' tenant")
	}
	if gov.Issuer.Format != "mdoc" {
		t.Errorf("gov format: got %q, want mdoc", gov.Issuer.Format)
	}
}

// TestNewRegistry_MultiTenant_UnknownIDReturnsNotFound verifies that an
// unknown tenant ID returns (nil, false) — the middleware falls back to "default".
func TestNewRegistry_MultiTenant_UnknownIDReturnsNotFound(t *testing.T) {
	cfg := minimalCfg()
	cfg.Tenants = []config.TenantConfig{
		{ID: "acme", Issuer: config.TenantIssuerConfig{Scope: "s"}},
	}
	reg, err := tenant.NewRegistry(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	_, ok := reg.Resolve("unknown")
	if ok {
		t.Error("expected Resolve(\"unknown\") to return false")
	}
}

func TestNewRegistry_MultiTenant_DuplicateIDError(t *testing.T) {
	cfg := minimalCfg()
	cfg.Tenants = []config.TenantConfig{
		{ID: "dup", Issuer: config.TenantIssuerConfig{Scope: "s1"}},
		{ID: "dup", Issuer: config.TenantIssuerConfig{Scope: "s2"}},
	}
	if _, err := tenant.NewRegistry(cfg, zap.NewNop()); err == nil {
		t.Error("expected error for duplicate tenant IDs")
	}
}

// ── Reload ────────────────────────────────────────────────────────────────────

func TestReload_ReplacesContext(t *testing.T) {
	cfg := minimalCfg()
	cfg.Issuer.Scope = "before"
	reg, err := tenant.NewRegistry(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	tc1, _ := reg.Resolve("default")
	if tc1.Issuer.Scope != "before" {
		t.Fatalf("before reload: scope %q", tc1.Issuer.Scope)
	}

	cfg2 := minimalCfg()
	cfg2.Issuer.Scope = "after"
	if err := reg.Reload(cfg2, zap.NewNop()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	tc2, _ := reg.Resolve("default")
	if tc2.Issuer.Scope != "after" {
		t.Errorf("after reload: scope %q, want after", tc2.Issuer.Scope)
	}
	// Previously resolved context is unaffected by the reload.
	if tc1.Issuer.Scope != "before" {
		t.Error("old context was mutated by Reload")
	}
}

// ── EmptyPolicies ─────────────────────────────────────────────────────────────

func TestEmptyPolicies_ReportsTenantsWithoutRules(t *testing.T) {
	// No rules_dir → policy engine loads 0 rules.
	reg, err := tenant.NewRegistry(minimalCfg(), zap.NewNop())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	empty := reg.EmptyPolicies()
	if len(empty) != 1 || empty[0] != "default" {
		t.Errorf("EmptyPolicies: got %v, want [default]", empty)
	}
}

// ── Tenant policy override inheritance ───────────────────────────────────────

func TestTenantPolicy_InheritsGlobalRulesDir(t *testing.T) {
	cfg := minimalCfg()
	cfg.Policy.RulesDir = t.TempDir()
	cfg.Tenants = []config.TenantConfig{
		{ID: "t1", Issuer: config.TenantIssuerConfig{Scope: "s"}},
	}
	reg, err := tenant.NewRegistry(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	// No per-tenant override → tenant should be constructed without error.
	if _, ok := reg.Resolve("t1"); !ok {
		t.Error("tenant t1 not found after construction with inherited policy")
	}
}

func TestTenantPolicy_OverridesGlobalRulesDir(t *testing.T) {
	cfg := minimalCfg()
	cfg.Policy.RulesDir = t.TempDir()
	tenantRules := t.TempDir()
	cfg.Tenants = []config.TenantConfig{
		{
			ID: "strict",
			Policy: config.TenantPolicyConfig{
				RulesDir: tenantRules,
			},
			Issuer: config.TenantIssuerConfig{Scope: "s"},
		},
	}
	if _, err := tenant.NewRegistry(cfg, zap.NewNop()); err != nil {
		t.Fatalf("NewRegistry with rules_dir override: %v", err)
	}
}

// ── Gin / stdlib context plumbing ─────────────────────────────────────────────

func TestGinContext_RoundTrip(t *testing.T) {
	reg, _ := tenant.NewRegistry(minimalCfg(), zap.NewNop())
	tc, _ := reg.Resolve("default")

	// Simulate what TenantAuth does inside a gin.HandlerFunc.
	c, _ := gin.CreateTestContext(nil)
	tenant.SetGin(c, tc)

	got, err := tenant.GetGin(c)
	if err != nil {
		t.Fatalf("GetGin: %v", err)
	}
	if got != tc {
		t.Error("GetGin returned a different *Context than SetGin stored")
	}
}

func TestGinContext_MissingReturnsError(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)
	if _, err := tenant.GetGin(c); err == nil {
		t.Error("expected error when no tenant context is set")
	}
}

func TestStdContext_RoundTrip(t *testing.T) {
	reg, _ := tenant.NewRegistry(minimalCfg(), zap.NewNop())
	tc, _ := reg.Resolve("default")

	ctx := tenant.WithStdContext(context.Background(), tc)
	got, ok := tenant.FromStdContext(ctx)
	if !ok {
		t.Fatal("FromStdContext returned false")
	}
	if got != tc {
		t.Error("FromStdContext returned different *Context")
	}
}

func TestStdContext_Missing(t *testing.T) {
	_, ok := tenant.FromStdContext(context.Background())
	if ok {
		t.Error("expected false for context without tenant")
	}
}

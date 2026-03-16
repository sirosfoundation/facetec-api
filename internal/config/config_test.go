package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/facetec-api/internal/config"
)

// TestLoad_Defaults verifies default values when no file and no env overrides are set.
func TestLoad_Defaults(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host: got %q, want 0.0.0.0", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port: got %d, want 8080", cfg.Server.Port)
	}
	if cfg.FaceTec.Timeout != 30*time.Second {
		t.Errorf("FaceTec.Timeout: got %v, want 30s", cfg.FaceTec.Timeout)
	}
	if cfg.Issuer.Format != "sdjwt" {
		t.Errorf("Issuer.Format: got %q, want sdjwt", cfg.Issuer.Format)
	}
	if !cfg.Security.RateLimit.Enabled {
		t.Error("Security.RateLimit.Enabled: want true by default")
	}
	if cfg.Security.RateLimit.RequestsPerMinute != 10 {
		t.Errorf("RateLimit.RequestsPerMinute: got %d, want 10", cfg.Security.RateLimit.RequestsPerMinute)
	}
}

// TestLoad_FromFile verifies that values are read from a YAML file.
func TestLoad_FromFile(t *testing.T) {
	yaml := `
server:
  host: "127.0.0.1"
  port: 9090
  public_base_url: "https://api.example.com"
facetec:
  server_url: "https://facetec.example.com"
  device_key: "devkey"
issuer:
  addr: "issuer:8090"
  scope: "photo-id"
  format: "mdoc"
policy:
  rules_dir: "/tmp/rules"
`
	path := writeTemp(t, "config.yaml", yaml)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host: got %q", cfg.Server.Host)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port: got %d", cfg.Server.Port)
	}
	if cfg.Server.PublicBaseURL != "https://api.example.com" {
		t.Errorf("Server.PublicBaseURL: got %q", cfg.Server.PublicBaseURL)
	}
	if cfg.FaceTec.ServerURL != "https://facetec.example.com" {
		t.Errorf("FaceTec.ServerURL: got %q", cfg.FaceTec.ServerURL)
	}
	if cfg.Issuer.Format != "mdoc" {
		t.Errorf("Issuer.Format: got %q", cfg.Issuer.Format)
	}
	if cfg.Policy.RulesDir != "/tmp/rules" {
		t.Errorf("Policy.RulesDir: got %q", cfg.Policy.RulesDir)
	}
}

// TestLoad_NonExistentFile verifies that a missing file returns an error.
func TestLoad_NonExistentFile(t *testing.T) {
	if _, err := config.Load("/no/such/config.yaml"); err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

// TestLoad_InvalidYAML verifies that a malformed YAML file returns an error.
func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "bad.yaml", "{invalid: yaml: [}")
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

// TestLoad_DeviceKeyPath verifies that device_key_path is read and trimmed.
func TestLoad_DeviceKeyPath(t *testing.T) {
	keyFile := writeTemp(t, "device.key", "  my-device-key\n  ")
	yaml := "facetec:\n  server_url: x\n  device_key_path: " + keyFile + "\nissuer:\n  addr: y\n  scope: z\n"
	cfgFile := writeTemp(t, "config.yaml", yaml)
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FaceTec.DeviceKey != "my-device-key" {
		t.Errorf("DeviceKey: got %q, want my-device-key", cfg.FaceTec.DeviceKey)
	}
}

// TestLoad_DeviceKeyPathError verifies that an unreadable device_key_path returns an error.
func TestLoad_DeviceKeyPathError(t *testing.T) {
	yaml := "facetec:\n  device_key_path: /no/such/key\n"
	cfgFile := writeTemp(t, "config.yaml", yaml)
	if _, err := config.Load(cfgFile); err == nil {
		t.Fatal("expected error for missing device_key_path file, got nil")
	}
}

// TestLoad_AppKeyPath verifies that app_key_path is read and trimmed.
func TestLoad_AppKeyPath(t *testing.T) {
	keyFile := writeTemp(t, "app.key", "  my-app-key\n")
	yaml := "security:\n  app_key_path: " + keyFile + "\n"
	cfgFile := writeTemp(t, "config.yaml", yaml)
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Security.AppKey != "my-app-key" {
		t.Errorf("AppKey: got %q, want my-app-key", cfg.Security.AppKey)
	}
}

// TestLoad_AppKeyPathError verifies that an unreadable app_key_path returns an error.
func TestLoad_AppKeyPathError(t *testing.T) {
	yaml := "security:\n  app_key_path: /no/such/key\n"
	cfgFile := writeTemp(t, "config.yaml", yaml)
	if _, err := config.Load(cfgFile); err == nil {
		t.Fatal("expected error for missing app_key_path file, got nil")
	}
}

// ── Validate tests ────────────────────────────────────────────────────────────

func TestValidate_MissingServerURL(t *testing.T) {
	cfg := &config.Config{
		Issuer: config.IssuerConfig{Addr: "x", Scope: "s"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing facetec.server_url")
	}
}

func TestValidate_MissingDeviceKey(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing facetec.device_key")
	}
}

func TestValidate_MissingIssuerAddr(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Scope: "s"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing issuer.addr")
	}
}

func TestValidate_MissingScope(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing issuer.scope")
	}
}

func TestValidate_ProductionWithoutAppKey(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		Logging: config.LoggingConfig{Production: true},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error: production mode without jwt.secret or app_key")
	}
}

func TestValidate_ProductionWithJWTSecret(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		Logging: config.LoggingConfig{Production: true},
		JWT:     config.JWTConfig{Secret: "shared-secret"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: jwt.secret set in production: %v", err)
	}
}

func TestValidate_MultiTenantProductionRequiresJWT(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		Logging: config.LoggingConfig{Production: true},
		Tenants: []config.TenantConfig{
			{ID: "acme", Issuer: config.TenantIssuerConfig{Scope: "s"}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error: multi-tenant production without jwt.secret")
	}
}

func TestValidate_MultiTenantWithJWT(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		Logging: config.LoggingConfig{Production: true},
		JWT:     config.JWTConfig{Secret: "shared-secret", Issuer: "https://auth.example.org"},
		Tenants: []config.TenantConfig{
			{ID: "acme", Issuer: config.TenantIssuerConfig{Scope: "s"}},
			{ID: "gov", Policy: config.TenantPolicyConfig{}, Issuer: config.TenantIssuerConfig{Scope: "s2"}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_OK(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_ProductionWithAppKey(t *testing.T) {
	cfg := &config.Config{
		FaceTec:  config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:   config.IssuerConfig{Addr: "x", Scope: "s"},
		Security: config.SecurityConfig{AppKey: "secret"},
		Logging:  config.LoggingConfig{Production: true},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAddress verifies host:port formatting.
func TestAddress(t *testing.T) {
	srv := config.ServerConfig{Host: "127.0.0.1", Port: 8443}
	if got := srv.Address(); got != "127.0.0.1:8443" {
		t.Errorf("Address: got %q, want 127.0.0.1:8443", got)
	}
}

// writeTemp creates a temp file in t.TempDir() with the given content and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeTemp: %v", err)
	}
	return path
}

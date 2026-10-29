package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/facetec-api/internal/buildmode"
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
	if cfg.FaceTec.MinChipFaceMatchLevel != 6 {
		t.Errorf("FaceTec.MinChipFaceMatchLevel: got %d, want 6", cfg.FaceTec.MinChipFaceMatchLevel)
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
	if cfg.Server.MaxConcurrentBiometric != 10 {
		t.Errorf("Server.MaxConcurrentBiometric: got %d, want 10", cfg.Server.MaxConcurrentBiometric)
	}
	if cfg.Logging.IncludePII {
		t.Error("Logging.IncludePII: want false by default")
	}
}

func TestLoad_LoggingIncludePII(t *testing.T) {
	for _, tt := range []struct {
		name string
		env  string
		yaml string
		want bool
	}{
		{"yaml opt-in", "", "true", true},
		{"env opt-in", "true", "false", true},
		{"env overrides yaml", "false", "true", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("LOG_INCLUDE_PII", tt.env)
			if tt.env == "" {
				if err := os.Unsetenv("LOG_INCLUDE_PII"); err != nil {
					t.Fatal(err)
				}
			}
			path := writeTemp(t, "config.yaml", "logging:\n  level: debug\n  include_pii: "+tt.yaml+"\n")
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Logging.IncludePII != tt.want {
				t.Errorf("Logging.IncludePII: got %v, want %v", cfg.Logging.IncludePII, tt.want)
			}
		})
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

// prodTrust is the trust configuration a real deployment gets from
// defaultConfig(): required, with a PDP. Tests that build a Config literal
// bypass defaultConfig(), so Trust.Required would be the Go zero value
// (false) -- which a production build refuses outright (#85). Tests about
// other fields take this so they assert the same thing under both builds.
func prodTrust() config.TrustConfig {
	return config.TrustConfig{Required: true, PDPURL: "https://go-trust.example.org"}
}

func TestValidate_MissingServerURL(t *testing.T) {
	cfg := &config.Config{
		Issuer: config.IssuerConfig{Addr: "x", Scope: "s"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing facetec.server_url")
	}
}

func TestValidate_IncludePIIRequiresDebugLevel(t *testing.T) {
	for _, level := range []string{"", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			cfg := &config.Config{
				Logging: config.LoggingConfig{Level: level, IncludePII: true},
			}
			if err := cfg.Validate(); err == nil {
				t.Errorf("expected error when logging.include_pii is enabled with level %q", level)
			}
		})
	}

	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		JWT:     config.JWTConfig{Secret: "shared-secret"},
		Logging: config.LoggingConfig{Level: "debug", IncludePII: true},
		Trust:   prodTrust(),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error with debug logging: %v", err)
	}
}

func TestValidate_JWKSURI(t *testing.T) {
	// A secret is configured throughout so the separate auth requirement is
	// always satisfied and only the URI is under test.
	cfg := func(uri string) *config.Config {
		return &config.Config{
			FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
			Issuer:  config.IssuerConfig{Addr: "https://x", Scope: "s"},
			JWT:     config.JWTConfig{JWKSURI: uri, Secret: "shared-secret"},
			Trust:   prodTrust(),
		}
	}

	for _, uri := range []string{
		"",
		"https://backend.example.org/.well-known/jwks.json",
		"http://localhost:8080/.well-known/jwks.json",
		"http://127.0.0.1:8080/.well-known/jwks.json",
		"http://[::1]:8080/.well-known/jwks.json",
	} {
		t.Run("accepts/"+uri, func(t *testing.T) {
			if err := cfg(uri).Validate(); err != nil {
				t.Errorf("jwt.jwks_uri %q: unexpected error: %v", uri, err)
			}
		})
	}

	// The key set decides which tokens are accepted, so fetching it over
	// plaintext would let anyone on the path mint tokens -- worse than the
	// shared secret this replaces.
	for _, uri := range []string{
		"http://backend.example.org/.well-known/jwks.json",
		"ftp://backend.example.org/jwks.json",
		"/.well-known/jwks.json",
		"backend.example.org/jwks.json",
	} {
		t.Run("rejects/"+uri, func(t *testing.T) {
			if err := cfg(uri).Validate(); err == nil {
				t.Errorf("jwt.jwks_uri %q: expected an error", uri)
			}
		})
	}
}

func TestValidate_LogFormat(t *testing.T) {
	valid := func(format string) *config.Config {
		return &config.Config{
			FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
			Issuer:  config.IssuerConfig{Addr: "https://x", Scope: "s"},
			JWT:     config.JWTConfig{Secret: "shared-secret"},
			Logging: config.LoggingConfig{Format: format},
			// Without this the production build refuses the config for a
			// reason that has nothing to do with logging.format (#85).
			Trust: prodTrust(),
		}
	}

	for _, format := range []string{"", config.LogFormatConsole, config.LogFormatJSON} {
		t.Run("accepts/"+format, func(t *testing.T) {
			if err := valid(format).Validate(); err != nil {
				t.Errorf("logging.format %q: unexpected error: %v", format, err)
			}
		})
	}

	// A typo must stop the process rather than silently fall back to console
	// and leave an operator wondering why their shipper sees no JSON.
	for _, format := range []string{"JSON", "Console", "text", "production"} {
		t.Run("rejects/"+format, func(t *testing.T) {
			if err := valid(format).Validate(); err == nil {
				t.Errorf("logging.format %q: expected an error", format)
			}
		})
	}
}

// TestValidate_JWKSURISatisfiesAuthRequirement pins that jwks_uri alone is a
// complete auth configuration -- the point of the migration is a deployment
// that holds no token-minting secret at all.
func TestValidate_JWKSURISatisfiesAuthRequirement(t *testing.T) {
	single := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
		Issuer:  config.IssuerConfig{Addr: "https://x", Scope: "s"},
		JWT:     config.JWTConfig{JWKSURI: "https://backend.example.org/jwks.json"},
		Trust:   prodTrust(),
	}
	if err := single.Validate(); err != nil {
		t.Errorf("jwks_uri alone should satisfy the auth requirement: %v", err)
	}

	multi := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
		Issuer:  config.IssuerConfig{Addr: "https://x", Scope: "s"},
		JWT:     config.JWTConfig{JWKSURI: "https://backend.example.org/jwks.json"},
		Tenants: []config.TenantConfig{{ID: "t-1"}},
		Trust:   prodTrust(),
	}
	if err := multi.Validate(); err != nil {
		t.Errorf("jwks_uri alone should satisfy multi-tenant mode: %v", err)
	}

	none := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
		Issuer:  config.IssuerConfig{Addr: "https://x", Scope: "s"},
		Trust:   prodTrust(),
	}
	if err := none.Validate(); err == nil {
		t.Error("expected an error with no jwks_uri, secret or app key")
	}
}

func TestValidate_WithoutDeviceKey(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		JWT:     config.JWTConfig{Secret: "shared-secret"},
		Trust:   prodTrust(),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: device_key should be optional: %v", err)
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

func TestValidate_RequiresAuthMechanism(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error: no jwt.secret or app_key configured")
	}
}

func TestValidate_WithJWTSecret(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		JWT:     config.JWTConfig{Secret: "shared-secret"},
		Trust:   prodTrust(),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: jwt.secret set: %v", err)
	}
}

func TestValidate_MultiTenantRequiresJWT(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		Tenants: []config.TenantConfig{
			{ID: "acme", Issuer: config.TenantIssuerConfig{Scope: "s"}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error: multi-tenant mode without jwt.secret")
	}
}

func TestValidate_MultiTenantWithJWT(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		JWT:     config.JWTConfig{Secret: "shared-secret", Issuer: "https://auth.example.org"},
		Tenants: []config.TenantConfig{
			{ID: "acme", Issuer: config.TenantIssuerConfig{Scope: "s"}},
			{ID: "gov", Policy: config.TenantPolicyConfig{}, Issuer: config.TenantIssuerConfig{Scope: "s2"}},
		},
		Trust: prodTrust(),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_OK(t *testing.T) {
	cfg := &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		JWT:     config.JWTConfig{Secret: "shared-secret"},
		Trust:   prodTrust(),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_WithAppKey(t *testing.T) {
	cfg := &config.Config{
		FaceTec:  config.FaceTecConfig{ServerURL: "https://x", DeviceKey: "k"},
		Issuer:   config.IssuerConfig{Addr: "x", Scope: "s"},
		Security: config.SecurityConfig{AppKey: "secret"},
		Trust:    prodTrust(),
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

// ── trust (eMRTD PDP) ─────────────────────────────────────────────────────────

func TestLoad_TrustDefaults(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Trust.PDPURL != "" {
		t.Errorf("Trust.PDPURL: got %q, want empty", cfg.Trust.PDPURL)
	}
	if cfg.Trust.Timeout != 5*time.Second {
		t.Errorf("Trust.Timeout: got %v, want 5s", cfg.Trust.Timeout)
	}
	if !cfg.Trust.Required {
		t.Error("Trust.Required: default must be true (fail closed)")
	}
}

func TestLoad_TrustFromYAMLAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte("trust:\n  pdp_url: https://pdp.example.org\n  timeout: 2s\n  required: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Trust.PDPURL != "https://pdp.example.org" || cfg.Trust.Timeout != 2*time.Second || cfg.Trust.Required {
		t.Errorf("unexpected trust config: %+v", cfg.Trust)
	}

	t.Setenv("TRUST_PDP_URL", "https://env.example.org")
	t.Setenv("TRUST_TIMEOUT", "750ms")
	t.Setenv("TRUST_REQUIRED", "true")
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Trust.PDPURL != "https://env.example.org" || cfg.Trust.Timeout != 750*time.Millisecond || !cfg.Trust.Required {
		t.Errorf("env should override file: %+v", cfg.Trust)
	}
}

func validBase() *config.Config {
	return &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://x"},
		Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
		JWT:     config.JWTConfig{Secret: "shared-secret"},
		Trust:   prodTrust(),
	}
}

func TestValidate_TrustRequiredNeedsPDP(t *testing.T) {
	cfg := validBase()
	cfg.Trust.Required = true
	cfg.Trust.PDPURL = "" // stated here rather than inherited from validBase()
	if err := cfg.Validate(); err == nil {
		t.Fatal("trust.required without trust.pdp_url must refuse, not skip")
	}
	cfg.Trust.PDPURL = "https://pdp.example.org"
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// trust.required: false needs no PDP -- that is the point of the development
// opt-out. Since #85 a production build refuses the setting outright, so this
// property only holds on a development build; the production side is pinned by
// TestValidate_TrustRequiredOptOut.
func TestValidate_TrustNotRequiredAllowsNoPDP(t *testing.T) {
	if buildmode.Production() {
		t.Skip("a production build refuses trust.required: false (#85)")
	}
	cfg := validBase()
	cfg.Trust.Required = false
	cfg.Trust.PDPURL = ""
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_TrustNegativeTimeout(t *testing.T) {
	cfg := validBase()
	cfg.Trust.Timeout = -time.Second
	if err := cfg.Validate(); err == nil {
		t.Error("negative trust.timeout must be rejected")
	}
}

func TestValidate_TrustPDPURLMustBeHTTPBaseURL(t *testing.T) {
	for _, bad := range []string{":", "pdp.example.org", "ftp://pdp.example.org", "https://"} {
		cfg := validBase()
		cfg.Trust.Required = true
		cfg.Trust.PDPURL = bad
		if err := cfg.Validate(); err == nil {
			t.Errorf("trust.pdp_url %q must be rejected at startup", bad)
		}
	}
}

func TestValidate_TrustPDPURLRejectsNonOrigin(t *testing.T) {
	for _, bad := range []string{"https://pdp.example/base", "https://pdp.example/base?x=y", "https://pdp.example/#f"} {
		cfg := validBase()
		cfg.Trust.PDPURL = bad
		if err := cfg.Validate(); err == nil {
			t.Errorf("trust.pdp_url %q carries a path/query/fragment and must be rejected", bad)
		}
	}
	cfg := validBase()
	cfg.Trust.PDPURL = "https://pdp.example:8443/"
	if err := cfg.Validate(); err != nil {
		t.Errorf("origin with port and trailing slash must be accepted: %v", err)
	}
}

func TestValidate_TrustPDPURLRequiresHTTPSExceptLoopback(t *testing.T) {
	for _, bad := range []string{"http://pdp.example.org", "http://10.0.0.5:8080"} {
		cfg := validBase()
		cfg.Trust.PDPURL = bad
		if err := cfg.Validate(); err == nil {
			t.Errorf("trust.pdp_url %q is plaintext to a non-loopback host and must be rejected", bad)
		}
	}
	for _, ok := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "https://pdp.example.org"} {
		cfg := validBase()
		cfg.Trust.PDPURL = ok
		if err := cfg.Validate(); err != nil {
			t.Errorf("trust.pdp_url %q must be accepted: %v", ok, err)
		}
	}
}

func TestValidate_TrustPDPURLAtMostOneTrailingSlash(t *testing.T) {
	cfg := validBase()
	cfg.Trust.PDPURL = "https://pdp.example///"
	if err := cfg.Validate(); err == nil {
		t.Error("multiple trailing slashes must be rejected")
	}
}

func TestValidate_MinChipFaceMatchLevel(t *testing.T) {
	for _, tc := range []struct {
		level int
		ok    bool
	}{{0, true}, {1, true}, {6, true}, {10, true}, {-1, false}, {11, false}} {
		cfg := &config.Config{
			FaceTec: config.FaceTecConfig{ServerURL: "https://x", MinChipFaceMatchLevel: tc.level},
			Issuer:  config.IssuerConfig{Addr: "x", Scope: "s"},
			JWT:     config.JWTConfig{Secret: "shared-secret"},
			Trust:   prodTrust(),
		}
		if err := cfg.Validate(); (err == nil) != tc.ok {
			t.Errorf("min_chip_face_match_level %d: Validate() = %v, want ok=%v", tc.level, err, tc.ok)
		}
	}
}

package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for facetec-api.
// Values may be supplied via YAML file and/or environment variables.
// Environment variables take precedence and use the prefix FACETEC_*.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	FaceTec  FaceTecConfig  `yaml:"facetec"`
	Issuer   IssuerConfig   `yaml:"issuer"`
	Policy   PolicyConfig   `yaml:"policy"`
	Session  SessionConfig  `yaml:"session"`
	Security SecurityConfig `yaml:"security"`
	Logging  LoggingConfig  `yaml:"logging"`
	// JWT holds the shared JWT validation settings for all tenant authentication.
	// All tenants use the same secret and issuer; the tenant_id claim selects the tenant.
	JWT JWTConfig `yaml:"jwt"`
	// Tenants defines per-tenant policy and issuer overrides.
	// When empty, a single "default" tenant is synthesised from the global
	// security.app_key and policy/issuer settings (backward-compatible mode).
	// envconfig is not applied to this slice — configure tenants via YAML only.
	Tenants []TenantConfig `yaml:"tenants" envconfig:"-"`
}

// ServerConfig controls the HTTP listener.
type ServerConfig struct {
	Host string `yaml:"host"           envconfig:"SERVER_HOST"`
	Port int    `yaml:"port"           envconfig:"SERVER_PORT"`
	// PublicBaseURL is the externally reachable base URL of this service, used when
	// constructing OpenID4VCI credential offer URIs returned to wallets.
	// Example: "https://facetec-api.example.org"
	// If empty the service falls back to scheme+bind address (dev only).
	PublicBaseURL string    `yaml:"public_base_url" envconfig:"SERVER_PUBLIC_BASE_URL"`
	TLS           TLSConfig `yaml:"tls"`
}

// TLSConfig enables TLS on the HTTP listener.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"   envconfig:"SERVER_TLS_ENABLED"`
	CertFile string `yaml:"cert_file" envconfig:"SERVER_TLS_CERT_FILE"`
	KeyFile  string `yaml:"key_file"  envconfig:"SERVER_TLS_KEY_FILE"`
}

// FaceTecConfig holds connection details for the FaceTec Server.
type FaceTecConfig struct {
	// ServerURL is the base URL of the FaceTec Server (required).
	ServerURL string `yaml:"server_url"      envconfig:"FACETEC_SERVER_URL"`
	// DeviceKey is the FaceTec SDK device key (optional).
	// Required only when connecting to the FaceTec Testing API; omit when using
	// your own FaceTec Server (v10+).
	DeviceKey string `yaml:"device_key"      envconfig:"FACETEC_DEVICE_KEY"`
	// DeviceKeyPath loads DeviceKey from a file (takes precedence over DeviceKey if set).
	DeviceKeyPath string        `yaml:"device_key_path" envconfig:"FACETEC_DEVICE_KEY_PATH"`
	Timeout       time.Duration `yaml:"timeout"         envconfig:"FACETEC_TIMEOUT"`
	// TLS configures the HTTPS connection to the FaceTec Server.
	TLS FaceTecTLSConfig `yaml:"tls"`
}

// FaceTecTLSConfig controls TLS for the outbound FaceTec Server connection.
type FaceTecTLSConfig struct {
	// SkipVerify disables certificate verification. Never use in production.
	SkipVerify bool `yaml:"skip_verify" envconfig:"FACETEC_TLS_SKIP_VERIFY"`
	// CAFile is a PEM file with the CA certificate to trust for the FaceTec Server.
	CAFile string `yaml:"ca_file"     envconfig:"FACETEC_TLS_CA_FILE"`
	// CertFile and KeyFile provide a client certificate for mutual TLS.
	CertFile string `yaml:"cert_file"   envconfig:"FACETEC_TLS_CERT_FILE"`
	KeyFile  string `yaml:"key_file"    envconfig:"FACETEC_TLS_KEY_FILE"`
}

// IssuerConfig holds the gRPC connection details for the vc credential issuer.
type IssuerConfig struct {
	// Addr is the gRPC address of the vc issuer (e.g. "issuer:8090").
	Addr     string `yaml:"addr"      envconfig:"ISSUER_ADDR"`
	TLS      bool   `yaml:"tls"       envconfig:"ISSUER_TLS"`
	CAFile   string `yaml:"ca_file"   envconfig:"ISSUER_CA_FILE"`
	CertFile string `yaml:"cert_file" envconfig:"ISSUER_CERT_FILE"`
	KeyFile  string `yaml:"key_file"  envconfig:"ISSUER_KEY_FILE"`
	// Scope is the credential scope passed to MakeSDJWT / MakeMDoc.
	Scope string `yaml:"scope"   envconfig:"ISSUER_SCOPE"`
	// Format selects the credential format: sdjwt (default), mdoc, or vc20.
	Format string `yaml:"format"  envconfig:"ISSUER_FORMAT"`
}

// PolicyConfig points to the directory of .spoc rule files.
// Numeric acceptance thresholds (liveness score, face match level) are encoded
// directly in the rules via SPOCP range predicates rather than as config fields.
type PolicyConfig struct {
	RulesDir string `yaml:"rules_dir" envconfig:"POLICY_RULES_DIR"`
}

// SecurityConfig controls request authentication and rate limiting.
type SecurityConfig struct {
	// AppKey is a pre-shared Bearer token required on all non-health endpoints.
	// When empty, authentication is disabled (development mode only).
	AppKey string `yaml:"app_key"      envconfig:"SECURITY_APP_KEY"`
	// AppKeyPath loads AppKey from a file (takes precedence over AppKey if set).
	AppKeyPath string `yaml:"app_key_path" envconfig:"SECURITY_APP_KEY_PATH"`
	// RateLimit controls per-IP request rate limiting on biometric endpoints.
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitConfig controls rate limiting on biometric endpoints.
type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"   envconfig:"SECURITY_RATE_LIMIT_ENABLED"`
	// RequestsPerMinute is the maximum number of requests per IP per minute.
	RequestsPerMinute int `yaml:"requests_per_minute" envconfig:"SECURITY_RATE_LIMIT_RPM"`
}

// SessionConfig controls in-memory session lifetimes.
type SessionConfig struct {
	// LivenessTTL is how long a FaceMap is retained between liveness and id-scan steps.
	LivenessTTL time.Duration `yaml:"liveness_ttl" envconfig:"SESSION_LIVENESS_TTL"`
	// OfferTTL is how long a credential offer is retained before redemption.
	OfferTTL time.Duration `yaml:"offer_ttl"    envconfig:"SESSION_OFFER_TTL"`
}

// TenantPolicyConfig holds optional per-tenant policy overrides.
type TenantPolicyConfig struct {
	// RulesDir overrides the global policy.rules_dir for this tenant.
	// If empty, the global rules directory is used.
	RulesDir string `yaml:"rules_dir"`
}

// TenantIssuerConfig holds per-tenant issuer parameter overrides.
// Empty strings fall back to the global IssuerConfig values.
type TenantIssuerConfig struct {
	// Scope overrides the global issuer.scope for this tenant.
	Scope string `yaml:"scope"`
	// Format overrides the global issuer.format (sdjwt | mdoc | vc20).
	Format string `yaml:"format"`
}

// TenantConfig defines a single tenant's policy and issuer overrides.
// Authentication is handled centrally via the shared jwt: config block;
// the tenant_id claim in the validated JWT selects which TenantConfig applies.
type TenantConfig struct {
	// ID is a unique human-readable identifier that must match the JWT tenant_id claim.
	ID string `yaml:"id"`
	// Policy holds optional per-tenant SPOCP rule and threshold overrides.
	Policy TenantPolicyConfig `yaml:"policy"`
	// Issuer holds optional per-tenant credential scope and format overrides.
	Issuer TenantIssuerConfig `yaml:"issuer"`
}

// JWTConfig holds the shared JWT validation settings used for all tenants.
// All tenants are authenticated using the same JWT infrastructure; the
// tenant_id claim in the token selects which policy engine and issuer
// parameters apply to the request.
type JWTConfig struct {
	// Secret is the HMAC shared secret used to validate JWT signatures.
	// Use SecretPath in production to avoid storing secrets in config files.
	Secret string `yaml:"secret" envconfig:"JWT_SECRET"`
	// SecretPath loads Secret from a file (takes precedence over Secret).
	SecretPath string `yaml:"secret_path" envconfig:"JWT_SECRET_PATH"`
	// Issuer is the expected iss claim. When non-empty, tokens with a different
	// issuer are rejected.
	Issuer string `yaml:"issuer" envconfig:"JWT_ISSUER"`
	// RequireAuth, when true, rejects requests that carry no valid Bearer JWT.
	// When false (default), unauthenticated requests receive the default tenant
	// context — suitable for development and gradual rollout.
	RequireAuth bool `yaml:"require_auth" envconfig:"JWT_REQUIRE_AUTH"`
}

// LoggingConfig controls log output.
type LoggingConfig struct {
	Level      string `yaml:"level"      envconfig:"LOG_LEVEL"`
	Production bool   `yaml:"production" envconfig:"LOG_PRODUCTION"`
}

// Load reads configuration from an optional YAML file and then applies environment overrides.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("config: open %q: %w", path, err)
		}
		defer func() { _ = f.Close() }()
		if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
			return nil, fmt.Errorf("config: decode %q: %w", path, err)
		}
	}
	if err := envconfig.Process("", cfg); err != nil {
		return nil, fmt.Errorf("config: process env: %w", err)
	}
	if err := cfg.loadSecrets(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate returns an error if required fields are missing or if the
// configuration is unsafe for a production deployment.
func (c *Config) Validate() error {
	if c.FaceTec.ServerURL == "" {
		return fmt.Errorf("config: facetec.server_url is required")
	}
	if c.Issuer.Addr == "" {
		return fmt.Errorf("config: issuer.addr is required")
	}

	if len(c.Tenants) == 0 {
		// Single-tenant mode: issuer scope must be set globally.
		if c.Issuer.Scope == "" {
			return fmt.Errorf("config: issuer.scope is required (or define per-tenant in the tenants: block)")
		}
		// In production, require at least one auth mechanism.
		if c.Logging.Production && c.Security.AppKey == "" && c.JWT.Secret == "" {
			return fmt.Errorf("config: jwt.secret (or legacy security.app_key) is required in production")
		}
	} else {
		// Multi-tenant mode: JWT is the only supported auth mechanism.
		// Plain per-tenant app keys are not supported — use jwt.secret.
		if c.JWT.Secret == "" && c.Logging.Production {
			return fmt.Errorf("config: jwt.secret is required in production multi-tenant mode")
		}
		// Validate each tenant entry.
		ids := make(map[string]bool, len(c.Tenants))
		for i, t := range c.Tenants {
			if t.ID == "" {
				return fmt.Errorf("config: tenants[%d]: id is required", i)
			}
			if ids[t.ID] {
				return fmt.Errorf("config: tenants[%d]: id %q is duplicated", i, t.ID)
			}
			ids[t.ID] = true
			// Every tenant must have a resolvable issuer scope.
			if t.Issuer.Scope == "" && c.Issuer.Scope == "" {
				return fmt.Errorf("config: tenant %q: issuer.scope is required (not set in tenant or global config)", t.ID)
			}
		}
	}
	return nil
}

// Address returns the combined host:port for the HTTP listener.
func (c *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func (c *Config) loadSecrets() error {
	if c.FaceTec.DeviceKeyPath != "" {
		data, err := os.ReadFile(c.FaceTec.DeviceKeyPath)
		if err != nil {
			return fmt.Errorf("config: read device_key_path: %w", err)
		}
		c.FaceTec.DeviceKey = strings.TrimSpace(string(data))
	}
	if c.Security.AppKeyPath != "" {
		data, err := os.ReadFile(c.Security.AppKeyPath)
		if err != nil {
			return fmt.Errorf("config: read app_key_path: %w", err)
		}
		c.Security.AppKey = strings.TrimSpace(string(data))
	}
	if c.JWT.SecretPath != "" {
		data, err := os.ReadFile(c.JWT.SecretPath)
		if err != nil {
			return fmt.Errorf("config: read jwt.secret_path: %w", err)
		}
		c.JWT.Secret = strings.TrimSpace(string(data))
	}
	return nil
}

func defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		FaceTec: FaceTecConfig{
			Timeout: 30 * time.Second,
		},
		Issuer: IssuerConfig{
			Format: "sdjwt",
		},
		Session: SessionConfig{
			LivenessTTL: 2 * time.Minute,
			OfferTTL:    5 * time.Minute,
		},
		Security: SecurityConfig{
			RateLimit: RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 10,
			},
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

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
}

// ServerConfig controls the HTTP listener.
type ServerConfig struct {
	Host          string    `yaml:"host"           envconfig:"SERVER_HOST"`
	Port          int       `yaml:"port"           envconfig:"SERVER_PORT"`
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
	ServerURL     string           `yaml:"server_url"      envconfig:"FACETEC_SERVER_URL"`
	// DeviceKey is the FaceTec SDK device key (required).
	DeviceKey     string           `yaml:"device_key"      envconfig:"FACETEC_DEVICE_KEY"`
	// DeviceKeyPath loads DeviceKey from a file (takes precedence over DeviceKey if set).
	DeviceKeyPath string           `yaml:"device_key_path" envconfig:"FACETEC_DEVICE_KEY_PATH"`
	Timeout       time.Duration    `yaml:"timeout"         envconfig:"FACETEC_TIMEOUT"`
	// TLS configures the HTTPS connection to the FaceTec Server.
	TLS           FaceTecTLSConfig `yaml:"tls"`
}

// FaceTecTLSConfig controls TLS for the outbound FaceTec Server connection.
type FaceTecTLSConfig struct {
	// SkipVerify disables certificate verification. Never use in production.
	SkipVerify bool   `yaml:"skip_verify" envconfig:"FACETEC_TLS_SKIP_VERIFY"`
	// CAFile is a PEM file with the CA certificate to trust for the FaceTec Server.
	CAFile     string `yaml:"ca_file"     envconfig:"FACETEC_TLS_CA_FILE"`
	// CertFile and KeyFile provide a client certificate for mutual TLS.
	CertFile   string `yaml:"cert_file"   envconfig:"FACETEC_TLS_CERT_FILE"`
	KeyFile    string `yaml:"key_file"    envconfig:"FACETEC_TLS_KEY_FILE"`
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
	Scope  string `yaml:"scope"   envconfig:"ISSUER_SCOPE"`
	// Format selects the credential format: sdjwt (default), mdoc, or vc20.
	Format string `yaml:"format"  envconfig:"ISSUER_FORMAT"`
}

// PolicyConfig points to the directory of .spoc rule files.
type PolicyConfig struct {
	RulesDir string `yaml:"rules_dir" envconfig:"POLICY_RULES_DIR"`
	// MinLivenessScore is the minimum acceptable liveness score (0–100).
	// Scans with a lower score are rejected before SPOCP rule evaluation.
	MinLivenessScore int `yaml:"min_liveness_score"  envconfig:"POLICY_MIN_LIVENESS_SCORE"`
	// MinFaceMatchLevel is the minimum acceptable face match level (0–10).
	// Scans with a lower level are rejected before SPOCP rule evaluation.
	MinFaceMatchLevel int `yaml:"min_face_match_level" envconfig:"POLICY_MIN_FACE_MATCH_LEVEL"`
}

// SecurityConfig controls request authentication and rate limiting.
type SecurityConfig struct {
	// AppKey is a pre-shared Bearer token required on all non-health endpoints.
	// When empty, authentication is disabled (development mode only).
	AppKey     string `yaml:"app_key"      envconfig:"SECURITY_APP_KEY"`
	// AppKeyPath loads AppKey from a file (takes precedence over AppKey if set).
	AppKeyPath string `yaml:"app_key_path" envconfig:"SECURITY_APP_KEY_PATH"`
	// RateLimit controls per-IP request rate limiting on biometric endpoints.
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitConfig controls rate limiting on biometric endpoints.
type RateLimitConfig struct {
	Enabled  bool    `yaml:"enabled"   envconfig:"SECURITY_RATE_LIMIT_ENABLED"`
	// RequestsPerMinute is the maximum number of requests per IP per minute.
	RequestsPerMinute int `yaml:"requests_per_minute" envconfig:"SECURITY_RATE_LIMIT_RPM"`
}

// SessionConfig controls in-memory session lifetimes.
type SessionConfig struct {
	// LivenessTTL is how long a FaceMap is retained between liveness and id-scan steps.
	LivenessTTL time.Duration `yaml:"liveness_ttl" envconfig:"SESSION_LIVENESS_TTL"`
	// OfferTTL is how long a credential offer is retained before redemption.
	OfferTTL    time.Duration `yaml:"offer_ttl"    envconfig:"SESSION_OFFER_TTL"`
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
		defer f.Close()
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
	if c.FaceTec.DeviceKey == "" {
		return fmt.Errorf("config: facetec.device_key is required (set directly or via device_key_path)")
	}
	if c.Issuer.Addr == "" {
		return fmt.Errorf("config: issuer.addr is required")
	}
	if c.Issuer.Scope == "" {
		return fmt.Errorf("config: issuer.scope is required")
	}
	if c.Logging.Production && c.Security.AppKey == "" {
		return fmt.Errorf("config: security.app_key / security.app_key_path is required when logging.production is true")
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
		Policy: PolicyConfig{
			MinLivenessScore:  80,
			MinFaceMatchLevel: 6,
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

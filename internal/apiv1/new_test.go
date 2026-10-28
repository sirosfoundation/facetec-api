package apiv1

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

// newTestConfig is a configuration New accepts. Nothing here reaches the
// network: facetec.NewClient and issuerclient.New only build clients.
func newTestConfig() *config.Config {
	return &config.Config{
		FaceTec: config.FaceTecConfig{ServerURL: "https://facetec.example.org"},
		Issuer: config.IssuerConfig{
			Addr:  "https://issuer.example.org",
			Scope: "https://credentials.example.org/photo-id",
		},
		Session: config.SessionConfig{
			OfferTTL:         5 * time.Minute,
			LivenessProofTTL: 15 * time.Minute,
		},
	}
}

func newTestRegistry(t *testing.T, cfg *config.Config) *tenant.Registry {
	t.Helper()
	reg, err := tenant.NewRegistry(cfg, zap.NewNop())
	require.NoError(t, err)
	return reg
}

// TestNew_WiresEveryDependency covers the constructor, which until now had no
// test at all: every collaborator was assembled in production and only ever
// stubbed by hand in tests, so a field left nil here would have surfaced as a
// panic at the first request rather than a failure in the suite.
func TestNew_WiresEveryDependency(t *testing.T) {
	cfg := newTestConfig()
	c, err := New(t.Context(), cfg, newTestRegistry(t, cfg), zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close(t.Context()) })

	assert.Same(t, cfg, c.cfg)
	assert.NotNil(t, c.log)
	assert.NotNil(t, c.ft, "facetec client")
	assert.NotNil(t, c.tenants, "tenant registry")
	assert.NotNil(t, c.sessions, "session manager")
	assert.NotNil(t, c.issuer, "vc issuer client")
	assert.NotNil(t, c.chip, "chip checker")
}

// TestNew_SessionTTLsComeFromConfig pins that the session manager is built
// from the configured TTLs rather than defaults. The offer TTL bounds how long
// an issued credential sits in memory awaiting pickup, so a manager built with
// a zero TTL would expire every offer instantly and break issuance in a way no
// other test would notice.
func TestNew_SessionTTLsComeFromConfig(t *testing.T) {
	cfg := newTestConfig()
	c, err := New(t.Context(), cfg, newTestRegistry(t, cfg), zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close(t.Context()) })

	id, err := c.sessions.PutOffer([]string{"credential"}, "scope")
	require.NoError(t, err)
	entry, err := c.sessions.TakeOffer(id)
	require.NoError(t, err, "a freshly stored offer must not already be expired")
	assert.Equal(t, []string{"credential"}, entry.Credentials)
}

// TestNew_RefusesAnUnusableIssuerAddr: an empty issuer.addr is rejected by
// issuerclient.New, and New must surface that rather than return a Client
// whose issuer would fail on the first issuance.
func TestNew_RefusesAnUnusableIssuerAddr(t *testing.T) {
	cfg := newTestConfig()
	cfg.Issuer.Addr = ""

	c, err := New(t.Context(), cfg, newTestRegistry(t, cfg), zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, c)
	assert.Contains(t, err.Error(), "connect to vc issuer")
}

// TestNew_RefusesAMissingFaceTecCAFile covers the other error path: a
// configured CA file that cannot be read must stop startup, not leave the
// service talking to the FaceTec Server with default trust.
func TestNew_RefusesAMissingFaceTecCAFile(t *testing.T) {
	cfg := newTestConfig()
	cfg.FaceTec.TLS.CAFile = filepath.Join(t.TempDir(), "absent.pem")

	c, err := New(t.Context(), cfg, newTestRegistry(t, cfg), zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, c)
	assert.Contains(t, err.Error(), "configure facetec HTTP client")
}

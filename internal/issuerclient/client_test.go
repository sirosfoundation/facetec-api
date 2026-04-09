package issuerclient

import "testing"

func TestNormalizeGRPCAddr(t *testing.T) {
	tests := []struct {
		addr string
		tls  bool
		want string
	}{
		// Bare host:port — no change.
		{"issuer:8090", false, "issuer:8090"},
		{"issuer:443", true, "issuer:443"},

		// HTTPS URL — strip scheme, default port.
		{"https://didrik.issuer.id.siros.org", true, "didrik.issuer.id.siros.org:443"},
		{"https://didrik.issuer.id.siros.org", false, "didrik.issuer.id.siros.org:8090"},

		// HTTPS URL with explicit port.
		{"https://issuer.example.com:9090", true, "issuer.example.com:9090"},

		// HTTP URL.
		{"http://issuer:8090", false, "issuer:8090"},

		// Bare hostname without port.
		{"issuer.example.com", true, "issuer.example.com:443"},
		{"issuer.example.com", false, "issuer.example.com:8090"},

		// Already correct host:port.
		{"10.0.0.5:8090", false, "10.0.0.5:8090"},
	}
	for _, tt := range tests {
		got := normalizeGRPCAddr(tt.addr, tt.tls)
		if got != tt.want {
			t.Errorf("normalizeGRPCAddr(%q, tls=%v) = %q, want %q", tt.addr, tt.tls, got, tt.want)
		}
	}
}

package jwks_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/sirosfoundation/facetec-api/internal/jwks"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// setServer serves whatever body the supplied function returns, counting hits.
func setServer(t *testing.T, hits *int32, body func() any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func publicSet(kid string, key *ecdsa.PrivateKey) jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: key.Public(), KeyID: kid, Algorithm: string(jose.ES256), Use: "sig",
	}}}
}

func newVerifier(t *testing.T, uri string, cacheTTL, minRefresh time.Duration) *jwks.Verifier {
	t.Helper()
	v, err := jwks.New(jwks.Config{
		URI:        uri,
		HTTPClient: &http.Client{Timeout: 2 * time.Second},
		CacheTTL:   cacheTTL,
		MinRefresh: minRefresh,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestKeyFor_FetchesAndCaches(t *testing.T) {
	var hits int32
	key := newKey(t)
	srv := setServer(t, &hits, func() any { return publicSet("kid-1", key) })

	v := newVerifier(t, srv.URL, time.Minute, time.Millisecond)
	for i := 0; i < 3; i++ {
		if _, err := v.KeyFor(t.Context(), "kid-1"); err != nil {
			t.Fatalf("KeyFor: %v", err)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("fetched %d times, want 1", n)
	}
}

// TestKeyFor_RefetchesForRotatedKid is how a key rotation at the issuer reaches
// a running process: a token arrives with a kid the cache does not hold, and the
// set is fetched again.
func TestKeyFor_RefetchesForRotatedKid(t *testing.T) {
	var hits int32
	first, second := newKey(t), newKey(t)
	current := publicSet("kid-1", first)
	srv := setServer(t, &hits, func() any { return current })

	v := newVerifier(t, srv.URL, time.Minute, time.Nanosecond)
	if _, err := v.KeyFor(t.Context(), "kid-1"); err != nil {
		t.Fatalf("KeyFor kid-1: %v", err)
	}

	current = publicSet("kid-2", second)
	if _, err := v.KeyFor(t.Context(), "kid-2"); err != nil {
		t.Fatalf("KeyFor kid-2 after rotation: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Errorf("fetched %d times, want 2 (initial + rotation)", n)
	}
}

// TestKeyFor_UnknownKidIsRateLimited guards the amplification: the kid in a
// token is attacker-controlled, so without a floor a stream of random kids
// would turn this service into a load generator against the issuer.
func TestKeyFor_UnknownKidIsRateLimited(t *testing.T) {
	var hits int32
	key := newKey(t)
	srv := setServer(t, &hits, func() any { return publicSet("kid-1", key) })

	v := newVerifier(t, srv.URL, time.Minute, time.Hour)
	if _, err := v.KeyFor(t.Context(), "kid-1"); err != nil {
		t.Fatalf("KeyFor: %v", err)
	}
	for i := 0; i < 20; i++ {
		if _, err := v.KeyFor(t.Context(), "forged-kid"); err == nil {
			t.Fatal("expected an error for an unknown kid")
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("20 unknown kids caused %d fetches, want 1 (the initial one)", n)
	}
}

func TestKeyFor_EmptyKidMatchesSingleKeySet(t *testing.T) {
	var hits int32
	key := newKey(t)
	// An issuer that has never rotated may publish a key with no kid at all.
	srv := setServer(t, &hits, func() any {
		return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: key.Public(), Algorithm: string(jose.ES256), Use: "sig",
		}}}
	})

	v := newVerifier(t, srv.URL, time.Minute, time.Nanosecond)
	if _, err := v.KeyFor(t.Context(), ""); err != nil {
		t.Errorf("empty kid against a single-key set: %v", err)
	}
}

// TestKeyFor_EmptyKidAmbiguousWithTwoKeys: once the issuer holds two keys, an
// empty kid no longer identifies one, and guessing would mean accepting a token
// verified by a key the issuer may have rotated out.
func TestKeyFor_EmptyKidAmbiguousWithTwoKeys(t *testing.T) {
	var hits int32
	a, b := newKey(t), newKey(t)
	srv := setServer(t, &hits, func() any {
		return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: a.Public(), KeyID: "kid-a", Algorithm: string(jose.ES256), Use: "sig"},
			{Key: b.Public(), KeyID: "kid-b", Algorithm: string(jose.ES256), Use: "sig"},
		}}
	})

	v := newVerifier(t, srv.URL, time.Minute, time.Nanosecond)
	if _, err := v.KeyFor(t.Context(), ""); err == nil {
		t.Error("expected an error for an empty kid against a two-key set")
	}
}

// TestFetch_DropsUnusableKeys: a set may legitimately carry keys for other
// purposes. Only public signing keys may ever be selected.
func TestFetch_DropsUnusableKeys(t *testing.T) {
	var hits int32
	sig, enc := newKey(t), newKey(t)
	srv := setServer(t, &hits, func() any {
		return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: enc.Public(), KeyID: "kid-enc", Algorithm: string(jose.ES256), Use: "enc"},
			{Key: sig.Public(), KeyID: "kid-sig", Algorithm: string(jose.ES256), Use: "sig"},
		}}
	})

	v := newVerifier(t, srv.URL, time.Minute, time.Nanosecond)
	if _, err := v.KeyFor(t.Context(), "kid-sig"); err != nil {
		t.Errorf("signing key: %v", err)
	}
	if _, err := v.KeyFor(t.Context(), "kid-enc"); err == nil {
		t.Error("an encryption key must not be usable for verification")
	}
}

// TestFetch_RejectsPrivateKey: if the issuer ever misconfigured its endpoint to
// serve private keys, this service must not quietly use them.
func TestFetch_RejectsPrivateKey(t *testing.T) {
	var hits int32
	key := newKey(t)
	srv := setServer(t, &hits, func() any {
		return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: key, KeyID: "kid-private", Algorithm: string(jose.ES256), Use: "sig",
		}}}
	})

	v := newVerifier(t, srv.URL, time.Minute, time.Nanosecond)
	if err := v.Refresh(t.Context()); err == nil {
		t.Error("a set of private keys must be refused")
	} else if !strings.Contains(err.Error(), "no usable public signing key") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetch_RejectsNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	v := newVerifier(t, srv.URL, time.Minute, time.Nanosecond)
	if err := v.Refresh(t.Context()); err == nil {
		t.Error("expected an error for a 503 key set endpoint")
	}
}

// TestKeyFor_FailsClosedWhenUnreachable: an unreachable issuer must mean "no
// key", never "accept anyway".
func TestKeyFor_FailsClosedWhenUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	v := newVerifier(t, url, time.Minute, time.Nanosecond)
	if _, err := v.KeyFor(t.Context(), "kid-1"); err == nil {
		t.Error("expected an error when the key set endpoint is unreachable")
	}
}

func TestNew_RequiresURIAndClient(t *testing.T) {
	if _, err := jwks.New(jwks.Config{HTTPClient: http.DefaultClient}); err == nil {
		t.Error("expected an error without a URI")
	}
	if _, err := jwks.New(jwks.Config{URI: "https://x/jwks.json"}); err == nil {
		t.Error("expected an error without an HTTP client")
	}
}

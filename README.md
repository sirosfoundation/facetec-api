# facetec-api

[![CI](https://github.com/sirosfoundation/facetec-api/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/facetec-api/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/sirosfoundation/facetec-api/branch/main/graph/badge.svg)](https://codecov.io/gh/sirosfoundation/facetec-api)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/facetec-api)](https://goreportcard.com/report/github.com/sirosfoundation/facetec-api)
[![Go](https://img.shields.io/badge/go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue)](LICENSE)
[![Docker](https://img.shields.io/badge/ghcr.io-facetec--api-2496ED?logo=docker&logoColor=white)](https://ghcr.io/sirosfoundation/facetec-api)

A Go microservice that bridges the [FaceTec](https://www.facetec.com/) biometric SDK (running
on a mobile device) with a verifiable-credential (VC) issuer. It acts as a security gateway:
biometric liveness and photo-ID scan results are validated against configurable SPOCP policy,
and — only on acceptance — a verifiable credential is issued through a gRPC back-end.

```
Mobile SDK  →  facetec-api  →  FaceTec Server  (liveness + ID scan)
                   │
                   ├── SPOCP policy engine  (accept / reject)
                   │
                   └──  vc issuer (gRPC)  →  SD-JWT / mDoc / VC 2.0
```

Biometric data (FaceMaps, raw scan images) **never leaves process memory** and is never written
to disk. See [PRIVACY.md](PRIVACY.md) for a full data-flow and GDPR analysis.

## Quickstart

```bash
# Build
make build

# Run with an example config (no TLS, no real FaceTec server)
cp configs/config.yaml configs/config.local.yaml
# Edit configs/config.local.yaml with your FaceTec Server URL and issuer address.
make run CONFIG=configs/config.local.yaml
```

### Requirements

| Tool | Version |
|------|---------|
| Go   | ≥ 1.25  |
| Make | any     |
| Docker (optional) | ≥ 25 |

## Configuration

Configuration is loaded from a YAML file (default: `configs/config.yaml`) and can be overridden
by environment variables. The full annotated reference is [configs/config.yaml](configs/config.yaml).

### Core settings

| YAML key | Env variable | Default | Description |
|----------|-------------|---------|-------------|
| `server.host` | `SERVER_HOST` | `0.0.0.0` | Listen address |
| `server.port` | `SERVER_PORT` | `8080` | Listen port |
| `server.public_base_url` | `SERVER_PUBLIC_BASE_URL` | *(empty)* | Externally reachable base URL; used for `credentialOfferURI` |
| `server.max_concurrent_biometric` | `SERVER_MAX_CONCURRENT_BIOMETRIC` | `10` | Max parallel biometric requests; excess get `503`. Limits peak memory from large payloads. `0` = unlimited |
| `server.tls.enabled` | `SERVER_TLS_ENABLED` | `false` | Enable TLS on the HTTP listener |
| `server.tls.cert_file` | `SERVER_TLS_CERT_FILE` | *(empty)* | TLS certificate file |
| `server.tls.key_file` | `SERVER_TLS_KEY_FILE` | *(empty)* | TLS private key file |
| `facetec.server_url` | `FACETEC_SERVER_URL` | *(required)* | FaceTec Server base URL |
| `facetec.device_key` | `FACETEC_DEVICE_KEY` | *(optional)* | FaceTec device key; sent as `X-Device-Key`. Only required by the FaceTec Testing API — omit when using your own FaceTec Server (v10+) |
| `facetec.device_key_path` | `FACETEC_DEVICE_KEY_PATH` | *(optional)* | File containing the FaceTec device key (takes precedence over `device_key`) |
| `facetec.timeout` | `FACETEC_TIMEOUT` | `30s` | HTTP timeout for FaceTec Server requests |
| `facetec.tls.skip_verify` | `FACETEC_TLS_SKIP_VERIFY` | `false` | Disable cert verification — **never use in production** |
| `facetec.tls.ca_file` | `FACETEC_TLS_CA_FILE` | *(optional)* | CA certificate for outbound FaceTec TLS |
| `facetec.tls.cert_file` | `FACETEC_TLS_CERT_FILE` | *(optional)* | Client certificate for FaceTec mTLS |
| `facetec.tls.key_file` | `FACETEC_TLS_KEY_FILE` | *(optional)* | Client private key for FaceTec mTLS |
| `issuer.addr` | `ISSUER_ADDR` | *(required)* | gRPC address of the vc issuer (e.g. `issuer:8090`) |
| `issuer.tls` | `ISSUER_TLS` | `false` | Enable TLS on the gRPC issuer connection |
| `issuer.ca_file` | `ISSUER_CA_FILE` | *(optional)* | CA certificate for the issuer gRPC connection |
| `issuer.cert_file` | `ISSUER_CERT_FILE` | *(optional)* | Client certificate for issuer mTLS |
| `issuer.key_file` | `ISSUER_KEY_FILE` | *(optional)* | Client private key for issuer mTLS |
| `issuer.scope` | `ISSUER_SCOPE` | *(required)* | Default credential scope URI |
| `issuer.format` | `ISSUER_FORMAT` | `sdjwt` | Default credential format: `sdjwt`, `mdoc`, `vc20` |
| `policy.rules_dir` | `POLICY_RULES_DIR` | *(empty)* | Directory of `.spoc` rule files |
| `session.liveness_ttl` | `SESSION_LIVENESS_TTL` | `2m` | How long a FaceMap is held in memory |
| `session.offer_ttl` | `SESSION_OFFER_TTL` | `5m` | How long a credential offer is held in memory |
| `logging.level` | `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `logging.production` | `LOG_PRODUCTION` | `false` | Enable JSON structured logging (recommended in prod) |

Numeric acceptance thresholds are encoded in the SPOCP rule files themselves rather than as
separate config keys. This keeps deployment policy in one place and allows per-tenant rule sets
to express score requirements such as liveness and face-match minima.

### Authentication

Three modes are selected automatically based on which keys are present:

| Mode | Config keys | Behaviour |
|------|------------|-----------|
| **JWT** *(recommended)* | `jwt.secret` | Validates HMAC-signed JWTs. The `tenant_id` claim selects the per-tenant policy; tokens without it use the `default` tenant. |
| **Legacy Bearer** | `security.app_key` (no JWT secret) | Constant-time comparison of a raw token. Single-tenant only. |
| **Dev / unauthenticated** | neither set | All requests are accepted. **Never use in production.** |

JWT settings:

| YAML key | Env variable | Default | Description |
|----------|-------------|---------|-------------|
| `jwt.secret` | `JWT_SECRET` | *(empty)* | HMAC shared secret for HS256/384/512 |
| `jwt.secret_path` | `JWT_SECRET_PATH` | *(optional)* | File containing the JWT secret |
| `jwt.issuer` | `JWT_ISSUER` | *(empty)* | Expected `iss` claim; leave empty to skip validation |
| `jwt.require_auth` | `JWT_REQUIRE_AUTH` | `false` | Reject requests without a valid JWT |
| `security.app_key` | `SECURITY_APP_KEY` | *(optional)* | Legacy Bearer token (set directly or via `app_key_path`) |
| `security.app_key_path` | `SECURITY_APP_KEY_PATH` | *(optional)* | File containing a legacy Bearer token |
| `security.rate_limit.enabled` | `SECURITY_RATE_LIMIT_ENABLED` | `true` | Enable per-IP rate limiting on biometric endpoints |
| `security.rate_limit.requests_per_minute` | `SECURITY_RATE_LIMIT_RPM` | `10` | Per-IP rate limit on biometric endpoints |

### Multi-tenant operation

When no `tenants:` block is present, a single `default` tenant is synthesised from the global
`policy` and `issuer` settings — existing deployments need no change.

When the `tenants:` block is present, each tenant is selected by the `tenant_id` JWT claim. A
missing or unconfigured `tenant_id` falls back to the `default` tenant (i.e., global settings),
so onboarding new tenants incrementally is safe.

Per-tenant overrides:

```yaml
tenants:
  - id: acme                          # must match JWT tenant_id claim
    issuer:
      scope: "https://credentials.acme.example.org/photo-id"
      format: sdjwt
    policy:
      rules_dir: "/etc/facetec-api/rules/acme"

  - id: gov
    issuer:
      scope: "https://credentials.gov.example.org/id-document"
      format: mdoc
    policy:
      rules_dir: "/etc/facetec-api/rules/gov"
```

## API

All `/v1/*` endpoints require a valid `Authorization: Bearer <token>` header when authentication
is configured. `/livez` and `/readyz` are always unauthenticated.

### Probes (unauthenticated)

| Method | Path | Response |
|--------|------|---------|
| `GET` | `/livez` | `200 {"status":"ok"}` — process is alive |
| `GET` | `/readyz` | `200 {"status":"ok"}` when policy rules are loaded; `503` otherwise |

### v1 API (authenticated)

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/v1/health` | Returns `200 {"status":"ok"}` — useful as a credential smoke-test |
| `POST` | `/process-request` | FaceTec-compatible requestBlob/responseBlob endpoint; augments successful matches with offer metadata |
| `POST` | `/v1/process-request` | Versioned alias of `/process-request` |
| `POST` | `/v1/session-token` | Obtain a short-lived FaceTec session token |
| `POST` | `/v1/liveness` | Submit a liveness FaceScan; returns `livenessSessionId` |
| `POST` | `/v1/id-scan` | Submit a photo ID scan; returns `transactionId` + `credentialOfferURI` |
| `GET`  | `/v1/offer/:txid` | Redeem a one-time credential offer (wallet pull) |

### Biometric flow

Two mobile-facing contracts are supported:

1. FaceTec-native processor flow via `/process-request` or `/v1/process-request`
2. Legacy split flow via `/v1/session-token`, `/v1/liveness`, and `/v1/id-scan`

The FaceTec-native flow is the recommended integration for mobile SDKs that already use the sample
`SessionRequestProcessor` pattern.

### FaceTec-native flow

```
1. POST /process-request
  → { "requestBlob": "...", "externalDatabaseRefID": "..." }
  ← { "responseBlob": "...", "result": { ... }, "transactionId": "...",
     "credentialOfferURI": "openid-credential-offer://?..." }

2. GET /v1/offer/:transactionId
  ← { "credentials": ["<signed-token>"], "scope": "..." }
```

`/process-request` preserves FaceTec's upstream response JSON. When the upstream payload represents
a successful photo-ID match and local policy accepts it, facetec-api augments that response with
`transactionId` and `credentialOfferURI`. If policy or issuance fails, the response still contains
the upstream `responseBlob` and instead adds `credentialIssueError`.

### Legacy split flow

```
1. POST /v1/session-token
   ← { "sessionToken": "…" }

2. POST /v1/liveness
   → { "sessionToken": "…", "faceScan": "<base64>", "auditTrail": […] }
   ← { "livenessSessionId": "…" }

3. POST /v1/id-scan
   → { "sessionToken": "…", "livenessSessionId": "…", "idScan": "<base64>",
       "idScanFrontImagesCompressedBase64": […], … }
   ← { "transactionId": "…", "credentialOfferURI": "openid-credential-offer://…" }

4. GET /v1/offer/:transactionId
   ← { "credentials": ["<signed-token>"], "scope": "…" }
```

Steps 2 and 3 are independently rate-limited per source IP.

For FaceTec sample-app style integrations, use `/process-request` and send the
SDK-generated `requestBlob` unchanged. The service returns FaceTec's response JSON
unchanged, and on successful photo-ID matches also attaches `transactionId` and
`credentialOfferURI` so the wallet can redeem the issued credential.

## SPOCP Policy Rules

Scan acceptance is a two-stage process:

1. **Score thresholds** — encoded directly in SPOCP range predicates such as
  `(liveness-score (* range numeric ge 080))` and
  `(face-match-level (* range numeric ge 06))`.
2. **Categorical rules** (`.spoc` files in `policy.rules_dir`) — S-expressions that encode which
  combinations of document type and verification flags are acceptable.

Rules are loaded at startup (and re-loaded on SIGHUP). If the rules directory is empty or
`policy.rules_dir` is unset, the service starts but rejects all scans and reports not-ready.

```scheme
; rules/default.spoc
; Accept passports with MRZ verification.
(facetec-scan (doc-type passport) (mrz-verified true))

; Accept e-passports with NFC chip verification.
(facetec-scan (doc-type passport) (mrz-verified true) (nfc-verified true))

; Accept driving licences with barcode verification.
(facetec-scan (doc-type dl) (mrz-verified false) (nfc-verified false) (barcode-verified true))

; Accept national ID cards (numeric thresholds from config still apply).
(facetec-scan (doc-type id_card))
```

Query fields available in every SPOCP query:

| Field | Values |
|-------|--------|
| `doc-type` | `passport`, `dl`, `id_card`, `unknown` |
| `mrz-verified` | `true`, `false` |
| `nfc-verified` | `true`, `false` |
| `barcode-verified` | `true`, `false` |

## Security

- **Biometric data never touches disk.** FaceMap templates are held exclusively in process
  memory for the duration of the liveness→id-scan window (default 2 min); backing bytes are
  zeroed with `clear()` immediately after use and again on graceful shutdown.
- **MRZ lines stripped before forwarding.** Raw MRZ lines (encoding the full identity in
  machine-readable form) are removed before any data is sent to the VC issuer.
- **No request/response body logging.** Gin runs in `gin.New()` mode; the panic-recovery handler
  is bound to `nil` to suppress recovery body dumps. `RequestLogger` records only method, path,
  status, latency, client IP, and user agent.
- **JWT authentication** with HMAC HS256/384/512; signing method is explicitly validated to
  prevent algorithm-confusion attacks. Legacy Bearer fallback uses constant-time comparison.
- **Rate limiting.** Biometric endpoints are rate-limited per source IP (default 10 rpm); stale
  IP buckets are evicted every 5 minutes to prevent unbounded memory growth.
- **Concurrency cap.** Biometric requests amplify payload size ~3-4× in memory (decoded blob,
  re-encoded forward buffer, upstream response, JSON output). `max_concurrent_biometric`
  (default 10) limits the number of in-flight biometric requests; excess callers receive `503`
  immediately instead of queuing. Combined with `GOMEMLIMIT`, this prevents OOM under sustained
  load.
- **Upstream response cap.** All FaceTec Server responses are capped at 15 MB via `io.LimitReader`
  to prevent memory exhaustion from unexpectedly large payloads.
- **Eager payload release.** Request payloads (requestBlob, faceScan, idScan) are zeroed
  immediately after forwarding to the FaceTec Server so the GC can reclaim them while the
  upstream response is still in flight.
- **Security response headers.** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Cache-Control: no-store` on every response.
- **HTTP timeouts.** `ReadHeaderTimeout: 10s`, `WriteTimeout: 90s`, `IdleTimeout: 120s`.
- **Production safety guard.** With `logging.production: true`, startup fails unless at least
  one of `jwt.secret` or `security.app_key` is set.
- **Atomic SIGHUP reload.** The tenant registry is swapped atomically on SIGHUP; in-flight
  requests are unaffected.

See [PRIVACY.md](PRIVACY.md) for a full data-flow description and GDPR analysis.

## Development

```bash
make tools          # install golangci-lint, protoc plugins
make dev            # build and run with hot config reload
make test           # run all tests
make test-coverage  # run tests with coverage profile + HTML report
make lint           # run golangci-lint
make fmt            # gofmt
make vet            # go vet
```

### Regenerating gRPC client code

The gRPC stubs under `internal/gen/issuer/apiv1_issuer/` are copied from the `vc` workspace
sibling. Regenerate them after updating the `vc` proto source:

```bash
./scripts/generate-proto.sh
```

If `protoc` is available and you want to regenerate from the proto source directly:

```bash
REGEN=1 ./scripts/generate-proto.sh
```

## Docker

```bash
make docker                        # build image
make docker-push                   # push to registry
docker compose up -d               # run with compose.yaml
```

The Docker image is built on `gcr.io/distroless/static-debian12` and runs as UID 65532
(non-root). Mount configuration and secrets as volumes or Docker secrets.

## License

Apache-2.0 — see [LICENSE](LICENSE).

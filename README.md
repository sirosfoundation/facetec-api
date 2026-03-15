# facetec-api

[![CI](https://github.com/sirosfoundation/facetec-api/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/facetec-api/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/sirosfoundation/facetec-api/branch/main/graph/badge.svg)](https://codecov.io/gh/sirosfoundation/facetec-api)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/facetec-api)](https://goreportcard.com/report/github.com/sirosfoundation/facetec-api)
[![Go](https://img.shields.io/badge/go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Docker](https://img.shields.io/badge/registry-registry.siros.org-2496ED?logo=docker&logoColor=white)](https://registry.siros.org/sirosfoundation/facetec-api)

A Go microservice that bridges the FaceTec biometric SDK (running on a mobile device) with a
verifiable-credential (VC) issuer, enforcing configurable acceptance policy via SPOCP rules.

```
Mobile SDK  →  facetec-api  →  FaceTec Server  (liveness + ID scan)
                   │
                   ├── SPOCP policy engine  (accept / reject)
                   │
                   └──  vc issuer (gRPC)  →  SD-JWT / mDoc / VC 2.0
```

## Quickstart

```bash
# Build
make build

# Run with an example config (no TLS, no real FaceTec server)
cp configs/config.yaml configs/config.local.yaml
# Edit configs/config.local.yaml with your FaceTec Server URL, device key, and issuer address.
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
by environment variables prefixed `FACETEC_*`.

See [configs/config.yaml](configs/config.yaml) for a fully annotated reference. The table below
lists the most important keys.

| YAML key | Environment variable | Default | Description |
|----------|---------------------|---------|-------------|
| `server.host` | `SERVER_HOST` | `0.0.0.0` | Listen address |
| `server.port` | `SERVER_PORT` | `8080` | Listen port |
| `server.public_base_url` | `SERVER_PUBLIC_BASE_URL` | *(empty)* | Externally reachable base URL; used for `credentialOfferURI` |
| `server.tls.enabled` | `SERVER_TLS_ENABLED` | `false` | Enable TLS |
| `facetec.server_url` | `FACETEC_SERVER_URL` | *(required)* | FaceTec Server base URL |
| `facetec.device_key_path` | `FACETEC_DEVICE_KEY_PATH` | *(optional)* | File containing FaceTec device key |
| `facetec.tls.ca_file` | `FACETEC_TLS_CA_FILE` | *(optional)* | CA certificate to trust for outbound FaceTec TLS |
| `issuer.addr` | `ISSUER_ADDR` | *(required)* | gRPC address of the vc issuer |
| `issuer.scope` | `ISSUER_SCOPE` | *(required)* | Credential scope |
| `issuer.format` | `ISSUER_FORMAT` | `sdjwt` | Credential format: `sdjwt`, `mdoc`, `vc20` |
| `policy.rules_dir` | `POLICY_RULES_DIR` | *(empty)* | Directory of `.spoc` rule files |
| `policy.min_liveness_score` | `POLICY_MIN_LIVENESS_SCORE` | `80` | Minimum liveness score 0–100 |
| `policy.min_face_match_level` | `POLICY_MIN_FACE_MATCH_LEVEL` | `6` | Minimum face-match level 0–10 |
| `security.app_key_path` | `SECURITY_APP_KEY_PATH` | *(optional)* | File containing Bearer token for API auth |
| `security.rate_limit.requests_per_minute` | `SECURITY_RATE_LIMIT_RPM` | `10` | Per-IP rate limit on biometric endpoints |
| `logging.production` | `LOG_PRODUCTION` | `false` | Enable production JSON logging (requires `app_key`) |

## API

All endpoints except `/livez` and `/readyz` require `Authorization: Bearer <app_key>` when
`security.app_key` / `security.app_key_path` is configured.

### Probes (unauthenticated)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/livez` | Liveness probe — returns `200 {"status":"ok"}` if the process is running |
| GET | `/readyz` | Readiness probe — returns `200` when policy rules are loaded and the service is operational |

### v1 API

| Method | Path | Description |
|--------|------|-------------|
| GET  | `/v1/health` | Service health |
| POST | `/v1/session-token` | Obtain a FaceTec session token |
| POST | `/v1/liveness` | Submit a liveness scan (FaceScan); returns `livenessSessionId` |
| POST | `/v1/id-scan` | Submit a photo ID scan; returns `transactionId` + `credentialOfferURI` |
| GET  | `/v1/offer/:txid` | Redeem a credential offer (one-time use) |

### Biometric flow

```
1. POST /v1/session-token           → { sessionToken }
2. POST /v1/liveness                → { livenessSessionId }
   body: { sessionToken, faceScan, [auditTrail] }
3. POST /v1/id-scan                 → { transactionId, credentialOfferURI }
   body: { sessionToken, livenessSessionId, idScan, [...] }
4. GET  /v1/offer/:transactionId    → { credentials, scope }
   (wallet polls until offer is available)
```

## SPOCP Policy Rules

Scan acceptance is a two-stage process:

1. **Numeric thresholds** (enforced in code via config): `policy.min_liveness_score` and
   `policy.min_face_match_level` — fast, explicit comparisons that cannot be bypassed.
2. **Categorical SPOCP rules** (loaded from `.spoc` files): encode which combinations of
   document type and verification flags are acceptable.

Rules are loaded from `policy.rules_dir` at startup. Each rule is an S-expression in SPOCP
advanced format. Add the directory to [`configs/config.yaml`](configs/config.yaml) and place
`.spoc` files inside.

```scheme
; rules/default.spoc
; Numeric thresholds (min_liveness_score, min_face_match_level) are enforced in
; config — rules only address document type and verification flags.

; Accept passports with MRZ verification.
(facetec-scan (doc-type passport) (mrz-verified true))

; Accept e-passports with both MRZ and NFC chip verification.
(facetec-scan (doc-type passport) (mrz-verified true) (nfc-verified true))

; Accept driving licences with barcode verification.
(facetec-scan (doc-type dl) (mrz-verified false) (nfc-verified false) (barcode-verified true))

; Accept national ID cards (numeric thresholds from config still apply).
(facetec-scan (doc-type id_card))
```

Categorical query fields (always present in every query):

| Field | Values |
|-------|--------|
| `doc-type` | `passport`, `dl`, `id_card`, `unknown` |
| `mrz-verified` | `true`, `false` |
| `nfc-verified` | `true`, `false` |
| `barcode-verified` | `true`, `false` |

## Security

- **Biometric data never touches disk.** FaceMap templates are held only in process memory for
  the duration of the liveness→id-scan window (default 2 minutes); the backing bytes are zeroed
  with `clear()` immediately after use and on service shutdown.
- **MRZ lines stripped before forwarding.** Raw MRZ lines encode the full identity in
  machine-readable form; they are removed before the document data is sent to the VC issuer.
- **No request/response body logging.** Gin runs in `gin.New()` mode with explicit middleware;
  the panic recovery handler is wired to `nil` to suppress recovery dumps.
- **Structured log scrubbing.** `RequestLogger` records only method, path, status, latency,
  client IP, and user agent — never headers or bodies.
- **Constant-time auth.** `AppKeyAuth` uses `subtle.ConstantTimeCompare` to prevent timing attacks.
- **Rate limiting.** Biometric endpoints are rate-limited per source IP (default 10 rpm) with
  a background goroutine that evicts stale IP buckets every 5 minutes.
- **Security response headers.** All responses carry `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, and `Cache-Control: no-store`.
- **HTTP timeouts.** `ReadHeaderTimeout: 10s`, `WriteTimeout: 90s`, `IdleTimeout: 120s`.
- **Production safety guard.** `logging.production: true` requires `security.app_key` to be
  set; the service will refuse to start without it.

## Development

```bash
make tools          # install golangci-lint, protoc plugins
make dev            # build and run with hot config reload
make test           # run all tests
make test-coverage  # run tests with per-function coverage report + HTML
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

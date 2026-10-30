# facetec-api

[![CI](https://github.com/sirosfoundation/facetec-api/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/facetec-api/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/sirosfoundation/facetec-api/branch/main/graph/badge.svg)](https://codecov.io/gh/sirosfoundation/facetec-api)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/facetec-api/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/facetec-api)
[![Go](https://img.shields.io/badge/go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue)](LICENSE)
[![Docker](https://img.shields.io/badge/ghcr.io-facetec--api-2496ED?logo=docker&logoColor=white)](https://ghcr.io/sirosfoundation/facetec-api)

A Go microservice that bridges the [FaceTec](https://www.facetec.com/) biometric SDK (running
on a mobile device) with a verifiable-credential (VC) issuer. It acts as a security gateway:
biometric liveness and photo-ID scan results are validated against configurable SPOCP policy,
and — only on acceptance — a verifiable credential is issued through the vc apigw's REST API.

```
Mobile SDK  →  facetec-api  →  FaceTec Server  (liveness + ID scan)
                   │
                   ├── SPOCP policy engine  (accept / reject)
                   │
                   └──  vc apigw (REST)  →  SD-JWT / mDoc / VC 2.0
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
| `facetec.min_chip_face_match_level` | `FACETEC_MIN_CHIP_FACE_MATCH_LEVEL` | `6` | Lowest match (1–10) between the live face and the photo on the document's chip that may be issued; a hard gate, independent of the SPOCP rules. `0` selects the default, so the gate cannot be switched off |
| `facetec.tls.skip_verify` | `FACETEC_TLS_SKIP_VERIFY` | `false` | Disable cert verification — **never use in production** |
| `facetec.tls.ca_file` | `FACETEC_TLS_CA_FILE` | *(optional)* | CA certificate for outbound FaceTec TLS |
| `facetec.tls.cert_file` | `FACETEC_TLS_CERT_FILE` | *(optional)* | Client certificate for FaceTec mTLS |
| `facetec.tls.key_file` | `FACETEC_TLS_KEY_FILE` | *(optional)* | Client private key for FaceTec mTLS |
| `issuer.addr` | `ISSUER_ADDR` | *(required)* | Base URL of the vc apigw, scheme included (e.g. `https://issuer.example.org`) |
| `issuer.tls` | `ISSUER_TLS` | `false` | Verify the apigw's TLS certificate against `ca_file`, and send a client certificate when one is configured. Has no effect on a plain `http://` base URL |
| `issuer.ca_file` | `ISSUER_CA_FILE` | *(optional)* | CA certificate for the apigw's TLS certificate |
| `issuer.cert_file` | `ISSUER_CERT_FILE` | *(optional)* | Client certificate for apigw mTLS |
| `issuer.key_file` | `ISSUER_KEY_FILE` | *(optional)* | Client private key for apigw mTLS |
| `issuer.api_key` | `ISSUER_API_KEY` | *(optional)* | Bearer token sent to the apigw on each request |
| `issuer.api_key_path` | `ISSUER_API_KEY_PATH` | *(optional)* | File containing the apigw Bearer token (takes precedence over `api_key`) |
| `issuer.scope` | `ISSUER_SCOPE` | *(required)* | Default credential scope URI |
| `issuer.authentic_source` | `ISSUER_AUTHENTIC_SOURCE` | `facetec-api` | Source system identifier sent to the apigw |
| `issuer.vct` | `ISSUER_VCT` | *(optional)* | Verifiable Credential Type sent with the upload |
| `issuer.format` | `ISSUER_FORMAT` | `sdjwt` | Default credential format: `sdjwt`, `mdoc`, `vc20`. `mdoc` uploads an [EWC RFC013](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc013-issue-photoid.md) Photo ID, see below |
| `issuer.issuing_authority` | `ISSUER_ISSUING_AUTHORITY` | `issuer.authentic_source` | Photo ID `issuing_authority_unicode` (`mdoc` only) |
| `issuer.issuing_country` | `ISSUER_ISSUING_COUNTRY` | scanned document's country | Photo ID `issuing_country`, ISO 3166-1 alpha-2 (`mdoc` only) |
| `policy.rules_dir` | `POLICY_RULES_DIR` | *(empty)* | Directory of `.spoc` rule files |
| `trust.pdp_url` | `TRUST_PDP_URL` | *(empty)* | Base origin of the go-trust AuthZEN PDP (must be `https`, no path; plain `http` only for localhost) that decides whether an eMRTD document signer chains to a reviewed CSCA (`POST {url}/evaluation`). Empty = unconfigured: chips are verified locally but never reported as trusted |
| `trust.timeout` | `TRUST_TIMEOUT` | `5s` | Timeout of each PDP request attempt (one retry, transport errors only) |
| `trust.required` | `TRUST_REQUIRED` | `true` | Fail closed: refuse to start without `trust.pdp_url`, hard-reject **any** document whose chip data is not trusted, and refuse to issue a credential whose identity did not come from a verified, trusted chip (`chip_data_unverified`), independent of the SPOCP rules. **A production build (`-tags production`, which the Dockerfile uses) refuses `false` outright**; a development build accepts it with a startup warning |
| `session.offer_ttl` | `SESSION_OFFER_TTL` | `5m` | How long a credential offer is held in memory |
| `session.liveness_proof_ttl` | `SESSION_LIVENESS_PROOF_TTL` | `15m` | How long FaceTec Server's liveness verdict for a `/process-request` session is held, from its liveness step to its final photo ID match result |
| `logging.level` | `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `logging.format` | `LOG_FORMAT` | `console` | Log encoding: `console` (human-readable) or `json` (one object per line, RFC3339 timestamps, for a log shipper or SIEM). An unrecognised value fails startup |
| `logging.include_pii` | `LOG_INCLUDE_PII` | `false` | Include sensitive NFC/OCR document data only when `logging.level` is `debug`; other levels prevent startup. **Never enable in production**; emits a startup warning when enabled |

`logging.format: json` writes one JSON object per line to stderr, with RFC3339 nanosecond
timestamps. It changes only the encoding: the level still comes from `logging.level`, and log
sampling is deliberately **off**, because zap samples per level and message and this service
logs every issuance under the single message `AUDIT credential_issued` — sampling would discard
audit records under load.

Ordinary debug logging does not include document identity data. For isolated test/development
environments only, set both `LOG_LEVEL=debug` and `LOG_INCLUDE_PII=true` to log parsed
document fields, including names, dates, document numbers and MRZ lines. Portraits, raw chip
data and request/response bodies remain excluded. These settings require a process restart;
SIGHUP reloads tenant settings only. Restrict access to these sensitive logs and delete them
after debugging; in production, keep `logging.include_pii: false`, including when using debug logs.

Numeric acceptance thresholds are encoded in the SPOCP rule files themselves rather than as
separate config keys. This keeps deployment policy in one place and allows per-tenant rule sets
to express score requirements such as liveness and face-match minima.

### ETSI 119 461 §4.5 Compliance

The following settings support the regulatory traceability and operator-oversight requirements
of ETSI TS 119 461 §4.5 (Identity Proofing and Verification — Remote Video).

| YAML key | Env variable | Default | Description |
|----------|-------------|---------|-------------|
| `audit.sink` | `AUDIT_SINK` | *(empty — disabled)* | Audit log output: `file`, `webhook`, or empty to disable |
| `audit.path` | `AUDIT_PATH` | *(empty)* | File path for `file` sink (append-only JSONL) |
| `audit.webhook_url` | `AUDIT_WEBHOOK_URL` | *(empty)* | Endpoint for `webhook` sink (POST, JSON, non-2xx = failure) |
| `audit.retention_days` | `AUDIT_RETENTION_DAYS` | `365` | Informational; used by external log rotation |
| `review.enabled` | `REVIEW_ENABLED` | `false` | Enable operator escalation for borderline results |
| `review.ttl` | `REVIEW_TTL` | `24h` | How long a review entry awaits operator decision before expiry |
| `review.webhook_url` | `REVIEW_WEBHOOK_URL` | *(empty)* | Endpoint notified when a new review is queued |

### Authentication

Three modes are selected automatically based on which keys are present:

| Mode | Config keys | Behaviour |
|------|------------|-----------|
| **JWT via JWKS** *(recommended)* | `jwt.jwks_uri` | Verifies ES256/ES384/EdDSA JWTs against the issuer's published public keys. This service holds nothing that can mint a token. The `tenant_id` claim selects the per-tenant policy; tokens without it use the `default` tenant. |
| **JWT via shared secret** | `jwt.secret` | Verifies HMAC-signed JWTs (HS256/384/512). Simpler, but the secret can also *issue* tokens, so both ends hold a forging key. Being migrated away from ([#12](https://github.com/sirosfoundation/facetec-api/issues/12)). |
| **Legacy Bearer** | `security.app_key` (no JWT secret) | Constant-time comparison of a raw token. Single-tenant only. |
| **Dev / unauthenticated** | neither set | All requests are accepted. **Never use in production.** |

JWT settings:

| YAML key | Env variable | Default | Description |
|----------|-------------|---------|-------------|
| `jwt.jwks_uri` | `JWT_JWKS_URI` | *(empty)* | Issuer's JSON Web Key Set endpoint, e.g. `https://backend.siros.org/.well-known/jwks.json`. Must be `https` (plain `http` only for localhost) |
| `jwt.jwks_refresh` | `JWT_JWKS_REFRESH` | `5m` | Interval of the background key set refresh |
| `jwt.secret` | `JWT_SECRET` | *(empty)* | HMAC shared secret for HS256/384/512 |
| `jwt.secret_path` | `JWT_SECRET_PATH` | *(optional)* | File containing the JWT secret |
| `jwt.issuer` | `JWT_ISSUER` | *(empty)* | Expected `iss` claim. **Required** whenever `jwt.jwks_uri` or `jwt.secret` is set |
| `jwt.audience` | `JWT_AUDIENCE` | *(empty)* | Accepted `aud` values — this service's own identifiers. **Required** whenever `jwt.jwks_uri` or `jwt.secret` is set |
| `jwt.require_auth` | `JWT_REQUIRE_AUTH` | `false` | Reject requests without a valid JWT |
| `security.app_key` | `SECURITY_APP_KEY` | *(optional)* | Legacy Bearer token (set directly or via `app_key_path`) |
| `security.app_key_path` | `SECURITY_APP_KEY_PATH` | *(optional)* | File containing a legacy Bearer token |

`jwt.jwks_uri` and `jwt.secret` may both be set during the migration: a token is verified by
whichever matches its algorithm family, so ES256 tokens from the new issuer and HS256 tokens from
the old one are both accepted while deployments roll over. Startup logs a warning while
`jwt.secret` is still configured alongside `jwt.jwks_uri` — removing it completes the migration
and leaves this service with no key capable of issuing a token.

Token validation is [go-tokenauth](https://github.com/sirosfoundation/go-tokenauth), the shared
SIROS library, rather than middleware of this service's own. The key set is fetched once at
startup, refreshed in the background every `jwt.jwks_refresh`, and re-fetched on demand when a
token presents an unknown `kid`, which is how key rotation at the issuer reaches a running
process. On-demand re-fetching is rate-limited, because the `kid` in a token is
attacker-controlled and an unthrottled refetch would make this service a load generator against
the issuer. An unreachable key set fails closed: tokens are refused, never waved through.

`jwt.audience` and `jwt.issuer` are mandatory in both JWT modes. go-tokenauth refuses to
validate a token without an audience restriction or an expected issuer rather than skipping
those checks, so a configuration missing either would start and then reject every request;
startup refuses it instead. Audience binding is what stops a token minted for another service
in the estate — correctly signed, unexpired, from the same issuer — being replayed here.
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

### Photo ID (`format: mdoc`)

With `format: mdoc`, the uploaded `document_data` holds the data elements of an
[EWC RFC013](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc013-issue-photoid.md)
Photo ID (doctype `eu.europa.ec.eudi.photoid.1`, ISO/IEC TS 23220-4 Annex C),
flat and keyed by element identifier; the vc issuer places each one in its
namespace from the scope's MDDL schema. The scope must therefore be an
`mso_mdoc` credential type with that doctype.

| Element | Namespace | Source |
|---|---|---|
| `family_name_unicode`, `given_name_unicode` | `org.iso.23220.1` | document |
| `birth_date`, `age_over_18`, `age_in_years`, `age_birth_year` | `org.iso.23220.1` | document date of birth |
| `portrait` | `org.iso.23220.1` | chip DG2 face image; JPEG 2000 is transcoded to JPEG so wallets can display it |
| `sex` (ISO/IEC 5218), `nationality` | `org.iso.23220.1` | document |
| `issue_date` | `org.iso.23220.1` | date of issuance |
| `expiry_date` | `org.iso.23220.1` | document date of expiry |
| `issuing_authority_unicode`, `issuing_country` | `org.iso.23220.1` | configuration (see above) |
| `document_number` | `org.iso.23220.1` | the attestation's document ID |
| `travel_document_number` | `org.iso.23220.photoid.1` | document number |

Being an mdoc, every element is individually selectively disclosable. The
optional `org.iso.23220.dtc.1` namespace (raw DG1/DG2/SOD) is not issued: raw
chip data never leaves this service.

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
| `GET`  | `/v1/offer/:txid` | Redeem a one-time credential offer (wallet pull) |

### Biometric flow

The one mobile-facing contract is the FaceTec-native processor flow, via `/process-request` or
`/v1/process-request`. It is the integration for mobile SDKs using FaceTec's sample
`SessionRequestProcessor` pattern, which is how FaceTec 10 drives a whole session.

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

For FaceTec sample-app style integrations, use `/process-request` and send the
SDK-generated `requestBlob` unchanged. The service returns FaceTec's response JSON
unchanged, and on successful photo-ID matches also attaches `transactionId` and
`credentialOfferURI` so the wallet can redeem the issued credential.

`/process-request` is rate-limited per source IP.

## SPOCP Policy Rules

Scan acceptance is a two-stage process:

1. **Score thresholds** — encoded directly in SPOCP range predicates such as
  `(liveness-score (* range numeric ge 080))` and
  `(face-match-level (* range numeric ge 06))`.
2. **Categorical rules** (`.spoc` files in `policy.rules_dir`) — S-expressions that encode which
  combinations of document type and verification flags are acceptable.

Rules are loaded at startup (and re-loaded on SIGHUP). If the rules directory is empty or
`policy.rules_dir` is unset, the service starts but rejects all scans and reports not-ready.

No credential is ever issued without an authenticated NFC chip
(`nfcAuthenticationStatusEnumInt` = 4 AUTHENTICATED: clone detection via Active/Chip
Authentication plus FaceTec's signature verification). `/process-request` refuses
such scans before the rules are evaluated, so a rule cannot re-admit them, and
the shipped rules require `(nfc-verified true)` as well. Passports additionally
require `(chip-trusted true)`: both checks, not either:

```scheme
; rules/default.spoc (accept rules)
; Matching is positional: every rule lists the query fields in order
; (liveness-score, face-match-level, doc-type, mrz-verified, nfc-verified,
; barcode-verified, chip-trusted) and may stop early, but never skips one.
; Accept e-passports: MRZ verified, chip authenticated AND trusted by the go-trust PDP.
; The (barcode-verified ...) placeholder is needed to reach chip-trusted.
(facetec-scan (liveness-score (* range numeric ge 080)) (face-match-level (* range numeric ge 06)) (doc-type passport) (mrz-verified true) (nfc-verified true) (barcode-verified (* set true false)) (chip-trusted true))

; Accept ID cards and driving licences with an authenticated NFC chip. "(mrz-verified)"
; with no value accepts either outcome.
(facetec-scan (liveness-score (* range numeric ge 080)) (face-match-level (* range numeric ge 06)) (doc-type id_card) (mrz-verified) (nfc-verified true))
(facetec-scan (liveness-score (* range numeric ge 080)) (face-match-level (* range numeric ge 06)) (doc-type dl) (mrz-verified) (nfc-verified true))
```

Before the SPOCP rules, `/process-request` applies hard gates that no rule can relax. A refused scan
gets a `credentialIssueErrorCode`, with a message in `credentialIssueError`.

**Liveness.** FaceTec Server 10 reports whether liveness was proven in `result.livenessProven`, on
the session's liveness step, a request before the one that completes the photo ID match.
facetec-api records that verdict under the session's `externalDatabaseRefID` (which the FaceTec
SDK sends with every request of a session) and issues nothing unless it was `true`
(`liveness_failed`). A request without `externalDatabaseRefID` cannot be tied to a liveness step
and is refused the same way. FaceTec 10 gives no liveness score, so a proven session reaches the
rules with `liveness-score` 100.

**Document expiry.** An expired document (`document_expired`), or one whose expiry date is missing
or unreadable (`document_unreadable`), is refused. A document is valid through its expiry date,
compared in UTC.

**Chip photo.** FaceTec reports two face matches: `matchLevel` against the photo printed on the
document (the rules' `face-match-level`), and `matchLevelNFCToFaceMap` against the photo on the
chip. Only the second ties the chip, and so the identity in the credential, to the person in front
of the camera; without it, a genuine document with a substituted printed photo passes every other
check. A scan whose chip match is below `facetec.min_chip_face_match_level` (default 6), or for
which FaceTec reported none, is refused with `chip_photo_mismatch`. The level is recorded as
`chip_face_match_level` in the issuance audit log.

**Chip.** A scan without an authenticated chip is refused:

| Code | FaceTec `nfcStatusEnumInt` | Meaning |
|------|----------------------------|---------|
| `nfc_not_requested` | 0 `NO_NFC_SPECIFIED_BY_TEMPLATE` | FaceTec's template for the document requests no chip read, so the user was never prompted; the document may still have a chip |
| `nfc_device_not_capable` | 1 `NFC_REQUESTED_BUT_DEVICE_NOT_CAPABLE` | the phone cannot read NFC (or it is switched off) |
| `nfc_skipped` | 2 `NFC_REQUESTED_BUT_USER_PRESSED_SKIP` | the user skipped the chip read |
| `nfc_chip_read_failed` | 3 `NFC_REQUESTED_BUT_ERROR_ACCESSING_CHIP` | the chip could not be read |
| `nfc_not_authenticated` | 4 `SUCCESS` or absent | the chip was read but not authenticated |

Query fields available in every SPOCP query:

| Field | Values |
|-------|--------|
| `doc-type` | `passport`, `dl`, `id_card`, `unknown` |
| `mrz-verified` | `true`, `false` |
| `nfc-verified` | `true`, `false` |
| `barcode-verified` | `true`, `false` |
| `chip-trusted` | `true`, `false` |

Field order in the query is: `liveness-score`, `face-match-level`, `doc-type`, `mrz-verified`,
`nfc-verified`, `barcode-verified`, `chip-trusted`. Matching is positional, so a rule that
constrains `chip-trusted` must list the fields before it (`(* set true false)` matches either value).

`nfc-verified` is FaceTec's own chip authentication (status 4: clone detection plus signature
verification against the DSC embedded in the same chip); it proves the chip is genuine hardware
holding intact data, not that the data was signed by a state we trust. `chip-trusted` is `true`
only when facetec-api itself verified the SOD signature and every data-group hash, the signed
document code matches the reported document type, **and** the go-trust PDP trusts the DSC for the issuing state
(see [ADR-002](docs/adr/002-emrtd-document-signer-trust.md)). Passports need both. Passports whose
chips lack Active/Chip Authentication (status 1) are therefore refused by design; this is a known
coverage trade-off. With `trust.required`, a scan of **any** document type that passes the NFC gate (status 4) but
whose raw chip data is missing or untrusted is refused with `chip_untrusted`. This was scoped to passports until
[#85](https://github.com/sirosfoundation/facetec-api/issues/85): ID cards are ICAO 9303 documents too, signed under
the same CSCAs, so exempting them meant issuing an ID card credential from a signer nobody vouched for. The cost is
that an ISO 18013 driving licence is refused until its chips and trust lists are supported.

**Only verified chip data is issued.** A second hard gate, at the point of issuance, refuses a credential whose
identity claims would have come from OCR of the printed page: the identity must have come from the document's chip
**and** that chip's signer must be trusted. The code is `chip_data_unverified`, distinct from `chip_untrusted`:
`chip_untrusted` says the signer is not trusted, `chip_data_unverified` says there was no verified chip identity to
issue from at all — a chip format this service does not parse, or a chip whose DG1 could not be read. OCR of a data
page is trivial to forge, and a signature over forged data is worthless without a trusted signer, which is why both
halves are required.

The gate is deliberately separate from the trust check rather than a clause inside it, so that a later change to the
trust logic cannot silently reopen the path from OCR to a credential.

### Production builds

`trust.required: false` switches off the trust check and this gate together. That is reasonable on a development
stack with no PDP and unacceptable in a deployment issuing real credentials, so it is a **build-time** decision
rather than a runtime one:

```bash
go build -tags production ./cmd/server   # refuses trust.required: false at startup
go build ./cmd/server                    # accepts it, with a startup warning
```

The Dockerfile and `make build-production` set the tag, so every container image is a production build. A build tag
is decided once by whoever builds the image and cannot be overridden by the deployment it is handed to — unlike a
config key, which is how the removed `logging.production` flag drifted into meaning three unrelated things.

**Identity from the chip.** Once the SOD signature and the data-group hashes are verified, the
credential's identity fields come from the chip, not from FaceTec's OCR of the MRZ in the photo:
names, document number, dates of birth and expiry, nationality, issuing state and sex from DG1
(the signed MRZ), refined by DG11 (full name, date of birth with century) when the chip carries
it. This holds whether or not the PDP trusts the signer, since signed chip data is never worse
than OCR. The chip is authoritative for every identity field, including the ones it leaves empty:
a holder with a single name gets no given name, an MRZ date of birth with unknown parts (e.g.
`85<<<<`) gives no `birth_date` or age claims, and an unspecified sex is issued as ISO/IEC 5218
`0` (not known); none of these is filled in from OCR. The portrait follows the same rule: it is
the SOD-verified DG2 face image, never FaceTec's `photoIDFaceCrop` from the camera image, and is
left out when DG2 was not verified. Where the OCR differed, the fields are
logged by name (never values). Documents without an ICAO chip (e.g. an ISO 18013 driving
licence) keep the OCR values and FaceTec's portrait for now (#85).

## ETSI 119 461 §4.5 Compliance

This release implements the traceability and quality controls required by
[ETSI TS 119 461](https://www.etsi.org/deliver/etsi_ts/119400_119499/119461/)
§4.5 for remote identity proofing and verification (IPV).

### Components

| Package | Purpose |
|---------|---------|
| `internal/auditlog` | Persistent IPV session audit logging (file or webhook sink) |
| `internal/evidence` | Cryptographic evidence binding — HMAC-SHA256 commitment linking session outcome to nonce |
| `internal/review` | Operator review queue with TTL, escalation webhook, and PII-safe evidence retrieval |
| `internal/quality` | Image quality assessment (face alignment, lighting, resolution) with configurable thresholds |

### Audit Log

Every IPV session (accept, reject, or escalate) is written to a persistent audit trail.
Each record contains: session ID, timestamp, tenant, outcome, liveness score, face-match level,
document type, and evidence hash. No biometric templates or PII are written to the log.

Sinks:
- **file** — Append-only JSONL at `audit.path`. Suitable for SIEM ingestion.
- **webhook** — POST JSON to `audit.webhook_url`. Non-2xx responses (including 3xx) are treated
  as delivery failures. Redirects are not followed (security hardening).

### Prometheus Metrics

Exposed at `/metrics` (Prometheus text format, unauthenticated):

| Metric | Type | Description |
|--------|------|-------------|
| `sirosid_facetec_http_requests_total` | Counter (by `method`, `path`, `status`) | HTTP requests served |
| `sirosid_facetec_http_request_duration_seconds` | Histogram (by `method`, `path`) | HTTP request latency |

`path` is the matched route pattern, never the raw URL, so a document or transaction ID in a
path never becomes a label value; requests matching no route are recorded as `unmatched`. The
probe endpoints (`/livez`, `/readyz`, `/healthz`) and `/metrics` itself are not recorded. The
endpoint also serves the standard Go runtime (`go_*`) and process (`process_*`) collectors.

There are deliberately **no IPV-outcome metrics**. Liveness scores, face-match levels and chip
face-match levels are derived biometric indicators that [PRIVACY.md](PRIVACY.md) §3 lists as
data that never leaves this service, and `/metrics` is unauthenticated. Per-tenant session
outcome counters are absent for a related reason: at low session volume, an outcome and
document type scraped per tenant approach a per-session disclosure. Publishing any of this is a
privacy decision before it is a wiring one, and needs a PRIVACY.md amendment and DPO review.

### Evidence Binding

On each decision, the service computes a SHA-256 HMAC over a unique random nonce and the
outcome string. The resulting `evidence_hash` is written into the audit log, creating a
verifiable commitment that ties the decision to a specific session without embedding PII.

### Operator Review

When enabled (`review.enabled: true`), borderline results are placed in a time-limited queue
instead of immediate rejection. An operator can inspect PII-safe evidence summaries and render
an accept/reject decision within the TTL window (default 24 h). Expired entries are reaped
automatically. The queue never retains biometric templates or session tokens.

### Quality Checks

The `internal/quality` package evaluates face alignment, lighting uniformity, and image
resolution before accepting a scan. Results are recorded in the audit log. Scans below
configured thresholds are rejected or escalated.

## Security

- **Biometric data never touches disk, and no template is ever held.** FaceScans, AuditTrail
  images and the FaceMap derived from them stay inside the opaque blobs exchanged between the
  SDK and the FaceTec Server; facetec-api relays them without decoding them. The only
  per-session state it keeps is a boolean liveness verdict.
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
- **Auth required.** Startup fails unless at least one of `jwt.jwks_uri`, `jwt.secret` or
  `security.app_key` is set.
- **No algorithm confusion.** A token's signature is verified with a key from its own algorithm
  family and no other: an ECDSA or Ed25519 token against a public key from the issuer's key set,
  an HMAC token against the shared secret. Neither key is ever offered to the other family, so
  the issuer's *published* public key cannot be used as an HMAC secret to forge a token.
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

### The vc apigw contract

`internal/issuerclient` is a plain `net/http` client; there are no generated
stubs to regenerate. Issuance is two POSTs against `issuer.addr`:

| Call | Endpoint | Purpose |
|---|---|---|
| `Upload` | `POST {issuer.addr}/api/v1/datastore` | Store the policy-approved document data |
| `PreauthOffer` | `POST {issuer.addr}/api/v1/datastore/preauth_offer` | Get the OID4VCI `credentialOfferURI` for the wallet |

Both carry `issuer.api_key` as a Bearer token when one is configured.

## Docker

```bash
make docker                        # build image
make docker-push                   # push to registry
docker compose up -d               # run with compose.yaml
```

The Docker image is built on `gcr.io/distroless/static-debian12` and runs as UID 65532
(non-root). Mount configuration and secrets as volumes or Docker secrets.

## License

BSD-2-Clause — see [LICENSE](LICENSE).

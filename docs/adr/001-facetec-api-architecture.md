# ADR-001: facetec-api Architecture

## Status

Accepted

## Context

The SIROS wallet needs to support liveness detection and photo ID verification using the FaceTec SDK
embedded in the native mobile app (go-wallet-backend/wallet-frontend). The result of a successful
scan must produce a verifiable credential through the existing `vc` issuer service.

Key constraints:
- **Privacy by design**: Biometric data (FaceScan blobs, FaceMaps) must never be written to disk.
- **Separate security zone**: The service handles raw biometric data and must be isolated from the
  broader wallet backend. It communicates with the `vc` issuer exclusively via gRPC.
- **Policy-based acceptance**: What constitutes a "good enough" scan must be configurable without
  code changes, using SPOCP rules (go-spocp).
- **Credential format flexibility**: The resulting credential must support SD-JWT, mDL (ISO 18013-5),
  and W3C VCDM 2.0, controlled by deployment configuration.

## Decision

Implement `facetec-api` as a standalone Go service following the conventions established by
`go-wallet-backend` and `vc` in this workspace.

### Component Interactions

```
Mobile App (FaceTec SDK)
        │
        │  HTTPS (device-key authenticated)
        ▼
  ┌─────────────────────┐
  │    facetec-api      │
  │  ┌───────────────┐  │
  │  │ httpserver    │  │──── POST → FaceTec Server (biometric verification)
  │  │ (gin)         │  │
  │  │ session mgr   │  │  in-memory only, TTL-evicted, no disk writes
  │  │ policy engine │  │──── go-spocp SPOCP rules (configurable .spoc files)
  │  │ apiv1/client  │  │──── gRPC → vc IssuerService (MakeSDJWT / MakeMDoc)
  │  └───────────────┘  │
  └─────────────────────┘
        │
        │  { transactionId, credentialOfferURI }
        ▼
  Wallet app redeems via go-wallet-backend / wallet-frontend
```

### Scan Flow

1. **Session Token** — `POST /session-token`: facetec-api proxies to FaceTec Server to obtain a
   short-lived session token scoping the biometric capture.

2. **Liveness Check** — `POST /liveness`: mobile app submits FaceScan blobs captured by the SDK.
   facetec-api forwards to FaceTec Server. On success, the server-side FaceMap (a derived biometric
   template, not a raw image) is stored in an in-memory liveness session with a 2-minute TTL.
   An opaque `livenessSessionId` is returned to the caller. The raw FaceScan blobs are immediately
   discarded.

3. **Photo ID Scan** — `POST /id-scan`: mobile app submits ID scan blobs and the `livenessSessionId`.
   facetec-api retrieves the stored FaceMap, combines it with the ID scan data, and forwards to
   FaceTec Server for face matching and OCR. The FaceMap is discarded after this call.

4. **Policy Evaluation** — The combined `ScanResult` (liveness score, face match level, document
   data, MRZ/NFC/barcode signals) is serialised as an S-expression and evaluated by the embedded
   go-spocp engine against rules loaded from the configured rules directory.

5. **Credential Issuance** — On policy pass, the OCR-extracted `DocumentData` (no biometrics) is
   JSON-encoded and sent to the `vc` IssuerService via gRPC. The resulting signed credential is
   stored in a second in-memory session (the credential offer), TTL 5 minutes, one-time-use.

6. **Offer Redemption** — `GET /offer/{transactionId}`: the wallet retrieves the credential.
   The session entry is atomically deleted on read.

### SPOCP Policy Format

Scan results are expressed as SPOCP S-expressions:

```
(facetec-scan
  (liveness-score "97")
  (face-match-level "8")
  (doc-type "passport")
  (mrz-verified "true")
  (nfc-verified "false"))
```

A permissive rule accepting any passport scan with liveness ≥ 80 and face match ≥ 6:

```
(facetec-scan (liveness-score "80") (face-match-level "6") (doc-type "passport"))
```

SPOCP's "less permissive" semantics mean a rule fires when the rule is less specific than the
query — i.e., when the actual scan meets or exceeds the rule's stated thresholds.

### Separation from go-wallet-backend

The mobile app communicates with facetec-api directly (separate port/domain). The resulting
`credentialOfferURI` follows OpenID4VCI and can be redeemed by the standard wallet frontend without
any awareness of the biometric origin.

## Rationale

- **go-spocp** provides a proven, lightweight policy engine already used elsewhere in the workspace.
  Externalising acceptance thresholds as rules enables per-deployment tuning without recompilation.
- **In-memory session store** (no Redis, no disk) is the simplest mechanism that satisfies the
  "never persist biometrics" constraint. The TTL prevents unbounded growth.
- **gRPC to `vc` issuer** follows the established inter-service boundary in this workspace and
  ensures biometrics never reach the credential signing service.
- **Credential format via config** avoids baking in SD-JWT as the only option; mDL and VC 2.0
  are supported by the same `vc` gRPC API.

## Consequences

- facetec-api must be deployed as a separate process/container with no persistent storage mounted.
- The FaceTec Server URL and device key are required at runtime; the service refuses to start
  without them.
- SPOCP rules in the configured directory are loaded at startup; a restart is required to update
  them (consistent with the go-spocp server pattern).
- The service forms a single point of failure for the biometric flow; it should be treated as a
  high-priority availability target.
- No biometric data is logged; log levels must be set carefully to avoid accidental capture in
  request/response debug logs.

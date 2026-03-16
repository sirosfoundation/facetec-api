# Privacy Analysis — facetec-api

> **Status:** Working document — intended as the technical basis for a formal GDPR Data
> Protection Impact Assessment (DPIA) or Records of Processing Activities (RoPA) entry.
> Legal conclusions must be reviewed by a qualified data-protection officer (DPO).

## 1. Purpose and Scope

`facetec-api` is a microservice that bridges a mobile biometric SDK (FaceTec) with a
verifiable-credential (VC) issuer. Its role is to:

1. Receive a biometric liveness scan and a photo-ID scan from a mobile device.
2. Verify liveness and face-to-document match via the FaceTec Server.
3. Evaluate the result against a configurable acceptance policy (SPOCP).
4. On policy acceptance, forward the extracted identity fields to a VC issuer and return
   a signed verifiable credential to the holder.

This document covers the data flows, data categories processed, retention periods,
technical and organisational measures (TOMs), and considerations relevant to GDPR compliance.

---

## 2. Categories of Personal Data Processed

### 2.1 Special-category data (Article 9 GDPR)

| Data element | Category | Where processed |
|---|---|---|
| **FaceScan** (base64, from mobile SDK) | Biometric data (Article 9(1)) | In transit: HTTPS to facetec-api → FaceTec Server |
| **AuditTrail** images (base64, from mobile SDK) | Biometric data | In transit: HTTPS to facetec-api → FaceTec Server |
| **FaceMap** (server-computed biometric template) | Biometric data | In process memory only — never persisted |
| **Liveness score** (float, 0.0–1.0) | Derived biometric indicator | In process memory only; logged at `Info` level without the score value |
| **Face-match level** (integer, 0–10) | Derived biometric indicator | In process memory only; logged at `Debug` level only on policy rejection |
| **ID scan image** (base64, from mobile SDK) | Biometric / documentary | In transit: HTTPS to facetec-api → FaceTec Server |
| **ID front/back images** (base64) | Biometric / documentary | In transit: HTTPS to facetec-api → FaceTec Server |

### 2.2 Ordinary personal data (Article 4(1) GDPR)

| Data element | Source | Destination |
|---|---|---|
| Given name | OCR of scanned document | VC issuer (gRPC) → included in issued credential |
| Family name | OCR | VC issuer → credential |
| Date of birth | OCR | VC issuer → credential |
| Date of expiry | OCR | VC issuer → credential |
| Nationality | OCR | VC issuer → credential |
| Sex | OCR | VC issuer → credential |
| Issuing country | OCR | VC issuer → credential |
| Document number | OCR | VC issuer → credential |
| Document type | OCR | VC issuer → credential; also used in policy evaluation |
| **MRZ lines 1–3** | OCR | Stripped before forwarding; never sent to issuer |

### 2.3 Technical / operational data (not directly personal)

| Data element | Purpose | Logged? |
|---|---|---|
| Client IP address | Rate limiting, request log | Yes — standard log fields only |
| HTTP method, path, status, latency | Operational metrics | Yes |
| User-Agent header | Operational | Yes (trimmed whitespace) |
| Session IDs (liveness, transaction) | Correlation within a single flow | No — opaque random hex values |
| Tenant ID | Operational audit | Yes |
| Document type (on policy rejection) | Debug logging | At `Debug` level only |

---

## 3. Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Mobile Device (Data Subject holds device)                                 │
│                                                                             │
│  FaceTec SDK captures:                                                      │
│    • FaceScan (biometric)                                                   │
│    • AuditTrail images (biometric)                                          │
│    • ID scan / front+back images (documentary)                              │
└───────────────────────┬─────────────────────────────────────────────────────┘
                        │ HTTPS POST (TLS required in production)
                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  facetec-api                                                                │
│                                                                             │
│  POST /v1/liveness                                                          │
│    ① Forwards FaceScan + AuditTrail ──────────────────────────────────────► FaceTec Server
│    ② Receives FaceMap (biometric template) ◄──────────────────────────────
│    ③ Stores FaceMap in RAM only (TTL = 2 min, one-time-use)                │
│                                                                             │
│  POST /v1/id-scan                                                           │
│    ④ Forwards ID scan + FaceMap from RAM ─────────────────────────────────► FaceTec Server
│    ⑤ Receives DocumentData + face-match level ◄───────────────────────────
│    ⑥ FaceMap bytes zeroed (clear()) immediately                             │
│    ⑦ DocumentData evaluated against SPOCP policy                           │
│    ⑧ MRZ lines stripped from DocumentData                                  │
│    ⑨ Stripped DocumentData forwarded ─────────────────────────────────────► VC Issuer (gRPC)
│    ⑩ Signed credential stored in RAM (TTL = 5 min, one-time-use)           │
│                                                                             │
│  GET /v1/offer/:txid                                                        │
│    ⑪ Credential returned to wallet; entry deleted from RAM                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Data that leaves facetec-api:**

| Destination | Data sent |
|---|---|
| FaceTec Server (HTTPS) | FaceScan, AuditTrail, ID scan images, FaceMap (from RAM); all raw biometric data |
| VC Issuer (gRPC) | DocumentData minus MRZ lines: name, DoB, nationality, sex, doc number, doc type, expiry, issuing country |
| Mobile wallet / client | Signed verifiable credential (opaque token; content determined by issuer) |

**Data that never leaves facetec-api:**

- FaceMap (biometric template) — only forwarded to FaceTec Server, never to issuer or client
- Liveness score — internal only
- Face-match level — internal only; logged at `Debug` level on rejection
- MRZ lines — stripped in code (`issueCredential()`) before any forwarding

---

## 4. Retention Periods

| Data | Storage location | Maximum retention | Deletion mechanism |
|---|---|---|---|
| FaceMap bytes | Process RAM (`session.Manager.liveness`) | `session.liveness_ttl` (default **2 min**) | `clear()` on use; TTL eviction; `clear()` on `Manager.Close()` |
| Liveness score | Process RAM | Same as FaceMap | Same |
| Signed credential | Process RAM (`session.Manager.offers`) | `session.offer_ttl` (default **5 min**) | Deleted atomically on first `GET /v1/offer/:txid`; TTL eviction |
| Request logs | Log sink (operator-configured) | Operator's log retention policy | No personal data in log fields; see §2.3 |
| Audit log event (`credential_issued`) | Log sink | Operator's log retention policy | Contains: tenant ID, transaction ID, doc type, format, scope — **no personal data** |

> **Note:** facetec-api has no database and no persistent storage of any kind. All data described
> above is held exclusively in process heap memory. A process restart or graceful shutdown
> zeroes and frees all biometric data.

---

## 5. Sub-processors and Third-Party Controllers

### 5.1 FaceTec Server

FaceTec operates the server-side biometric matching engine. When using FaceTec's hosted service:

- The FaceTec Server receives: FaceScan, AuditTrail, ID scan images, FaceMap.
- These are Article 9 special-category biometric data.
- FaceTec Inc. acts as a **processor** (or possibly joint controller — legal analysis required).
- A **Data Processing Agreement (DPA)** with FaceTec must be in place before processing
  production data.
- The connection uses HTTPS; `facetec.tls.skip_verify` must be `false` in production.

When a **self-hosted FaceTec Server** is used, this sub-processor relationship does not apply,
but the operator takes on processing responsibility for the biometric data sent to that server.

### 5.2 VC Issuer service

The VC issuer receives the stripped DocumentData (no MRZ, no biometric data). It acts as a
**processor** or **joint controller** depending on the deployment architecture. A DPA or
inter-controller agreement is required.

### 5.3 No other sub-processors

`facetec-api` does not use:
- Any cloud storage, database, or message queue.
- Any telemetry, analytics, or third-party monitoring SDK.
- Any CDN or reverse proxy that sees request bodies.

---

## 6. Legal Basis for Processing

Processing of biometric data under Article 9 requires an explicit legal basis from Article 9(2).

| Processing activity | Suggested legal basis | Notes |
|---|---|---|
| Biometric liveness verification | **Art. 9(2)(a)** explicit consent, or **Art. 9(2)(g)** substantial public interest | Must be determined per deployment context and jurisdiction |
| Face-to-document matching | Same as above | |
| OCR extraction of identity fields | Same as above | |
| Issuance of verifiable credential | **Art. 6(1)(b)** performance of a contract (if credential issuance is the service the subject requested), or consent | |
| Operational logging (IP, path, status) | **Art. 6(1)(f)** legitimate interest in operating a secure service | Must pass three-part test |

> **Important:** facetec-api is infrastructure — it enforces technical controls but it does not
> determine the legal basis. The **controller** (the organisation deploying facetec-api) must
> document the lawful basis and ensure it is communicated to data subjects.

---

## 7. Data Subject Rights (Articles 15–22 GDPR)

Because `facetec-api` retains no personal data beyond the sub-minute in-memory window, most
rights are technically satisfied by design:

| Right | Applicability to facetec-api |
|---|---|
| **Access (Art. 15)** | No stored personal data to provide. Audit logs contain only opaque transaction IDs. |
| **Rectification (Art. 16)** | Not applicable — no stored records. |
| **Erasure (Art. 17)** | Effectively automatic: all in-memory data is zeroed within ≤ 5 min; no persistent storage. |
| **Restriction (Art. 18)** | Not applicable — no stored records. |
| **Portability (Art. 20)** | Not applicable — no stored records. The issued credential itself (in the wallet) is portable by design. |
| **Objection (Art. 21)** | Must be handled at controller level before initiating a biometric session. |
| **Automated decision-making (Art. 22)** | Policy evaluation produces a binary accept/reject. This constitutes automated processing with legal or similarly significant effect. Appropriate safeguards and the right to human review must be provided by the controller. |

---

## 8. Data Protection by Design and by Default (Article 25)

The following technical controls are implemented in code:

| Control | Implementation |
|---|---|
| **Data minimisation** | Only fields required for credential issuance are extracted from OCR output. MRZ lines (containing full identity in machine-readable form) are stripped before forwarding. |
| **Storage limitation** | Biometric data is never written to disk. RAM retention is bounded by configurable short TTLs with fallback eviction. |
| **Explicit zeroing** | `clear(faceMap)` is called on the `[]byte` FaceMap immediately after use (deferred in `SubmitIDScan`), and again by `Manager.Close()` on every in-memory entry at shutdown. |
| **No body logging** | Gin middleware never logs request or response bodies. The panic-recovery handler is bound to `nil` to prevent biometric data appearing in crash dumps. |
| **Structured logs scrubbed** | Log fields are explicitly enumerated: method, path, status, latency, IP, user-agent. Biometric scores are absent from Info-level logs. |
| **One-time-use sessions** | Liveness entries and credential offers are deleted on first access (`TakeLiveness`, `TakeOffer`). An attacker cannot replay a session ID. |
| **Rate limiting** | Biometric endpoints are rate-limited per source IP to slow automated bulk enumeration or scraping. |
| **Short-lived sessions** | Default TTL of 2 min for liveness sessions limits the exposure window if a session ID is intercepted. |
| **Audit trail without PII** | The `AUDIT credential_issued` log event records tenant ID, transaction ID, doc type, credential format, and scope — no name, date of birth, or other identity fields. |
| **TLS enforcement** | The listener supports TLS (`server.tls.enabled`). The connection to FaceTec Server uses TLS with configurable CA pinning; `skip_verify` is blocked if deployment validation checks detect production mode. |
| **Authentication** | JWT-based authentication required for all `/v1/*` endpoints in production; algorithm confusion attacks are mitigated by explicit `jwt.WithValidMethods`. |

---

## 9. Records of Processing Activity (RoPA) Entry

The following is a template RoPA entry for the controller to complete.

| Field | Value |
|---|---|
| **Processing activity name** | Biometric identity verification for verifiable credential issuance |
| **Controller** | *(deploying organisation — to be completed)* |
| **DPO contact** | *(to be completed)* |
| **Purpose** | Verify that a natural person is live and matches a government-issued identity document; issue a verifiable credential attesting to verified identity fields |
| **Legal basis** | *(to be completed by DPO — see §6)* |
| **Data subjects** | Natural persons who voluntarily initiate an identity verification session |
| **Data categories** | Biometric data (liveness scan, ID scan images, FaceMap); identity fields extracted from document (name, DoB, nationality, sex, doc number, doc type) |
| **Recipients** | FaceTec Server (biometric engine); VC Issuer service (identity fields minus MRZ); data subject's wallet (signed credential) |
| **Third country transfers** | Dependent on where FaceTec Server and VC Issuer are hosted. If FaceTec hosted service is used, transfer to USA — adequacy decision or SCCs required. |
| **Retention** | In-memory only; ≤ 5 min maximum; zeroed on use |
| **TOMs** | Memory-only storage, explicit zeroing, no body logging, rate limiting, TLS, JWT auth, data minimisation, MRZ stripping — see §8 |
| **Assessment required (DPIA)** | **Yes** — Article 35(3)(b): systematic processing of biometric data on a large scale. DPIA must be completed before go-live. |

---

## 10. DPIA Triggers and Considerations

A full DPIA under Article 35 is **required** because:

- The processing involves **biometric data** processed to uniquely identify a natural person
  (Article 35(3)(b)).
- The processing may be at **large scale** depending on deployment volume (WP248 criterion).

Key items a DPIA must address for this service:

1. **Necessity and proportionality:** Is biometric liveness verification proportionate to the
   assurance level required? Are less intrusive alternatives available?
2. **FaceTec as (joint) controller or processor:** The FaceTec Server receives raw biometric
   material. The legal relationship must be documented and a DPA executed.
3. **Data subject information:** The privacy notice served to users before the biometric session
   must clearly describe the data collected, who receives it, and the legal basis.
4. **Consent mechanism:** If consent is the chosen basis under Art. 9(2)(a), granular, freely
   given, specific, informed, and unambiguous consent must be collected and evidenced.
5. **Automated decision-making:** Policy rejection is an automated decision that may prevent
   a person from obtaining credentials. A human review process must be available.
6. **Cross-border transfer:** If FaceTec's hosted service is used, biometric data is transferred
   to the United States. An adequacy decision (if any) or Standard Contractual Clauses must be in
   place. A Transfer Impact Assessment (TIA) is recommended.
7. **Incident response:** Because facetec-api holds no persistent data, a breach of the running
   process leaks at most one 2-minute FaceMap. The incident response plan should reflect this
   bounded exposure.
8. **Residual risks:** Even with the mitigations in §8, the FaceTec Server and VC Issuer
   potentially store data. Their retention and security practices must be independently assessed.

---

## 11. Open Issues and Recommendations

| # | Issue | Recommendation |
|---|---|---|
| 1 | FaceTec Server may log or retain biometric data independently | Obtain and review FaceTec Server privacy documentation; include in DPA; prefer self-hosted deployment |
| 2 | Liveness score is logged at `Info` level (numeric value absent but event is logged) | If log correlation with other events could re-identify subjects, consider gating liveness log event to `Debug` level |
| 3 | Client IP in logs may be sufficient to indirectly identify a subject | Evaluate pseudonymisation of IP (e.g., last-octet removal) if biometric sessions can be correlated with IP over time |
| 4 | `GET /v1/offer/:txid` is authenticated (token required) but the transaction ID in the offer URI may be guessable | Transaction IDs are 128-bit random hex; guessing is computationally infeasible, but short TTL (5 min) and one-time-use provide defence-in-depth |
| 5 | ID scan and front/back images (full document photographs) are forwarded to FaceTec Server | These images may contain more information than the OCR-extracted fields. Assess whether FaceTec Server's handling of raw document images meets the controller's obligations |
| 6 | No explicit mechanism for cross-tenant data isolation at the process level | Tenants share a single process, rate limiter, and log sink. Consider whether tenant isolation requirements demand process-level or infrastructure-level separation |
| 7 | Audit log contains `tenant_id` but not `subject_id` | Adding a pseudonymous subject reference (e.g., hash of document number) would improve auditability without PII exposure — evaluate per deployment |

---

*Last updated: 2026-03-15. Review when any of the following change: data flows, sub-processors,
legal basis, applicable national law, or FaceTec SDK/Server version.*

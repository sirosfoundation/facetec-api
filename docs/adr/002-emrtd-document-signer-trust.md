# ADR-002: eMRTD document-signer trust is decided by a go-trust PDP

## Status

Accepted

## Context

Passport chips (ICAO 9303 eMRTD) carry an EF.SOD, a CMS signature by a Document Signer
Certificate (DSC) over hashes of the data groups. FaceTec's SDK checks those hashes against the
DSC embedded in the same chip and does clone detection (`nfcAuthenticationStatusEnumInt`:
0 N/A, 1 NOT_SUPPORTED_BY_DOCUMENT, 2 NOT_SUPPORTED_BY_SDK, 3 FAILED, 4 AUTHENTICATED,
5 FAILED_DUE_TO_SIGNATURE_VERIFICATION). That proves integrity only: nothing checks the DSC
against a Country Signing CA (CSCA), so a forger with their own DSC passes. `nfc-verified`
therefore cannot be the basis for issuing a credential.

## Decision

Split the work across three roles (shared contract for the emrtd effort):

| Role | Component | Responsibility |
|------|-----------|----------------|
| PEP | facetec-api (`internal/emrtd`) | Parse the SOD from `documentData.nfcValues.rawData`, verify the CMS signature with the embedded DSC, verify every presented data group against the SOD, cross-check DG1 against the scanned MRZ fields and issuing state, normalise the issuing state to ISO alpha-3, then ask the PDP. Never uses FaceTec's `signingCertificate` / `wasSignedDataValidated`. gmrtd's embedded master lists are not used as trust. |
| PDP | go-trust `emrtd` registry | Decide whether the DSC chains to an anchor in the reviewed CSCA list for the claimed state, evaluated at the SOD signing time. Does not see the SOD. |
| Anchor list | emrtd-trust-anchors repo | The reviewed CSCA list and its maintenance tooling. |

The PEP calls `POST /evaluation` (AuthZEN) with subject `{key, <alpha-3>}`, resource
`{x5c, <alpha-3>, [DSC, other SOD certs...]}`, action `emrtd-document-signer` and, when the SOD
carries one, `context.signing_time`. The signing time is document-specific (the time this holder's SOD was signed), so it is treated as personal-data-adjacent metadata (PRIVACY.md §5.3); it is sent at full precision because validity boundaries are exact to the second and truncating or omitting it could change a decision. Certificates from the SOD other than the DSC are untrusted
intermediates, never anchors. The signer-asserted `signing_time` is signed by the DSC itself and so
is attacker-controlled when a DSC key is expired or compromised; the PEP therefore only forwards it
when it is not in the future (10 minute skew), not after the DG1-bound document expiry and not more
than 11 years before it (`signing_time_implausible` otherwise). This bounds, but cannot eliminate,
backdating: the PDP and the reviewed CSCA list remain the authority. Only `decision == true` **with** an anchor fingerprint
(`csca_sha256`) counts as trusted; transport errors (one retry), timeouts, non-200, malformed
bodies and denials all mean NOT trusted.

The outcome is surfaced to SPOCP as `chip-trusted` (last query field), independent of
`nfc-verified`, and recorded in the audit log together with `chip_auth_status`. The default
passport rules (accept and review) require **both** `(nfc-verified true)` and `(chip-trusted true)`;
ID cards and driving licences require `(nfc-verified true)` only.

The two checks answer different questions. FaceTec status 4 (AUTHENTICATED) proves clone
detection succeeded (Active/Chip Authentication) and that FaceTec's signature verification
passed, i.e. the chip is genuine hardware holding unaltered data. `chip-trusted` proves the DSC
chains to our reviewed CSCA list. Neither implies the other: a forger's own chip can be
authentic-looking but untrusted, and a copied genuine SOD fails clone detection.

Independent of policy, `/process-request` requires status 4 for every document type and refuses
anything else (`nfc_not_authenticated`, or the more specific `nfc_*` codes) before trust is even
consulted; failed authentication (3, 5) is covered by that refusal. With `trust.required`
(default true) a passport scan (or one with no reported document type) that passes that gate but
whose raw chip data is missing or untrusted is rejected (`chip_untrusted`); ID cards and driving
licences are not covered by this hard rejection and are left to policy (`nfc-verified`), and the service refuses to start without `trust.pdp_url`.

Known trade-off: many genuine passports lack Active/Chip Authentication (status 1). Under this
rule they are refused by design, accepting reduced coverage for clone resistance.

## Consequences

- Passports from states without a reviewed CSCA are rejected until an anchor is approved.
- The PDP is on the issuance path: its availability bounds passport issuance (fails closed).
- The PDP sees only the SOD certificates, the issuing-state code and the document-specific SOD signing time, which is personal-data-adjacent metadata (see PRIVACY.md §5.3).
- Local checks are deliberately strict (exactly one SignerInfo, DG1 mandatory, every presented
  DG must be covered by the SOD, document number and both dates must be present in the scan), so
  some malformed-but-genuine chips are refused rather than waved through.
- The legacy `/v1/id-scan` path carries no raw chip data, so `chip-trusted` is always false there
  and the default passport rule rejects it (with `trust.required`, the path is refused outright).

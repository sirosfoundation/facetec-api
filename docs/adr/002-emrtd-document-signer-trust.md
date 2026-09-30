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
carries one, `context.signing_time`. Certificates from the SOD other than the DSC are untrusted
intermediates, never anchors. Only `decision == true` **with** an anchor fingerprint
(`csca_sha256`) counts as trusted; transport errors (one retry), timeouts, non-200, malformed
bodies and denials all mean NOT trusted.

The outcome is surfaced to SPOCP as `chip-trusted` (last query field), independent of
`nfc-verified`, and recorded in the audit log together with `chip_auth_status`. The default
passport rule requires `(chip-trusted true)`. Independent of policy, status 3 or 5 is rejected in
code, and with `trust.required` (default true) any scan that presented chip data which is not
trusted is rejected and the service refuses to start without `trust.pdp_url`.

Status 1 (no Active/Chip Authentication on the chip) is permitted: many genuine passports lack
it. It is a weaker clone-detection signal and is recorded in the audit log so it can be reviewed.

## Consequences

- Passports from states without a reviewed CSCA are rejected until an anchor is approved.
- The PDP is on the issuance path: its availability bounds passport issuance (fails closed).
- The PDP sees only certificates and a country code (see PRIVACY.md §5.3).
- Local checks are deliberately strict (exactly one SignerInfo, DG1 mandatory, every presented
  DG must be covered by the SOD, document number and both dates must be present in the scan), so
  some malformed-but-genuine chips are refused rather than waved through.
- The legacy `/v1/id-scan` path carries no raw chip data, so `chip-trusted` is always false there
  and the default passport rule rejects it.

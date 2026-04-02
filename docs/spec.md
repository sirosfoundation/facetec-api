# FaceTec Web Service

This service interfaces between the FaceTec SDK in native mobile apps, FaceTec Server, and the vc
issuing service (SUNET/vc). Its purpose is to apply local business and policy logic to successful
FaceTec scans and turn accepted results into redeemable credential offers.

https://dev.facetec.com/photo-id-match-guide?section=photo-id-scan#getting-started

The facetec SDK will be integrated into the native app frontend of go-wallet-backend based on wallet-frontend but the factec SDK will be isolated from the other parts of the wallet frontend and can for all intents and purposes be treated as a separate application.

Privacy is the primary concern. No biometric data will ever be stored on disk and every measure should be taken to make the attack surface of biometric data as small as possible. Biometrics will only be kept for as long as is absolutely necessary to complete a full scan+document validation flow. The facetec webservice (this project) should be treated as a separate security zone and will communicate with the vc issuer via gRPC interfaces. 

The preferred mobile integration is FaceTec's `SessionRequestProcessor` pattern. The native app
submits `requestBlob` to facetec-api `/process-request`; facetec-api forwards it to FaceTec Server
and returns the upstream `responseBlob` unchanged. When the upstream result represents a successful
photo-ID match and local policy accepts it, facetec-api also returns a `transactionId` and
`credentialOfferURI` that the calling application can pass into the wallet's OpenID4VCI flow.

The legacy split API (`/v1/session-token`, `/v1/liveness`, `/v1/id-scan`) remains available for
clients that have not yet moved to the preferred `requestBlob`/`responseBlob` contract.

The facetec webservice is responsible for business logic for

- deciding what is an acceptable successful scan+liveness check. This should use spocp-based (go-spocp) rules
- format of the created credential - should be configurable

Implement the code in golang and use go-spocp, go-wallet-backend and other projects in this workspace as inspiration for how to construct the service.

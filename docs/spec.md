# FactTect Web Service

This is an implementation of a webservice for interfacing with the facetec SDK in mobile devices and the facetec server. The purpose if the webservice is to provice business logic for generating documents into the vc issuing service (SUNET/vc). 

https://dev.facetec.com/photo-id-match-guide?section=photo-id-scan#getting-started

The facetec SDK will be integrated into the native app frontend of go-wallet-backend based on wallet-frontend but the factec SDK will be isolated from the other parts of the wallet frontend and can for all intents and purposes be treated as a separate application.

Privacy is the primary concern. No biometric data will ever be stored on disk and every measure should be taken to make the attack surface of biometric data as small as possible. Biometrics will only be kept for as long as is absolutely necessary to complete a full scan+document validation flow. The facetec webservice (this project) should be treated as a separate security zone and will communicate with the vc issuer via gRPC interfaces. 

The intended flow is that the user initiates a liveness scan+document check as described in the getting started guide above and after applying business rules the facetec webservice should create a document tied to a transaction identifer that the calling application can dereference as a credential offer from the issuer.

The facetec webservice is responsible for business logic for 

- deciding what is an acceptable successful scan+liveness check. This should use spocp-based (go-spocp) rules
- format of the created credential - should be configurable

Implement the code in golang and use go-spocp, go-wallet-backend and other projects in this workspace as inspiration for how to construct the service.

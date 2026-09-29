at_sod.b64: base64 of a real-world EF.SOD (Austrian passport sample) taken
verbatim from the test data of github.com/gmrtd/gmrtd v1.2.0
(passiveauth/passive_auth_test.go, "AT"). It contains only certificates and
data-group hashes, no personal data. gmrtd is MIT licensed; its notice is in
LICENSE-gmrtd.txt and applies to this file. Its document signer chains to an
Austrian CSCA present in gmrtd's embedded master lists, so it exercises the
full passive-authentication path of VerifyPassportChip. Certificate validity is
evaluated at the SOD signing time, so the long-expired signer still verifies.

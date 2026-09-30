// Package emrtd implements the policy enforcement point (PEP) side of eMRTD
// (ICAO 9303) passive authentication for chip data relayed by the FaceTec
// Server.
//
// The work is split in two halves, see docs/adr/002-emrtd-document-signer-trust.md:
//
//   - [Verify] is purely local: it parses EF.SOD, verifies the CMS signature
//     with the Document Signer Certificate (DSC) embedded in the SOD, verifies
//     every presented data group against the SOD hashes and cross-checks DG1
//     (the MRZ) against the document data that will end up in the credential.
//   - [Checker] then asks a go-trust PDP (AuthZEN) whether that DSC chains to a
//     reviewed CSCA for the claimed issuing state.
//
// FaceTec's own signingCertificate / wasSignedDataValidated values are never
// consulted: FaceTec only checks the SOD against the DSC embedded in the same
// chip, which proves integrity but not authenticity.
//
// The embedded CSCA master lists of gmrtd are deliberately NOT used as trust.
package emrtd

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso3166"
	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/oid"
)

// Reason codes reported in Result.Reason / ChipTrustReason. They are stable,
// machine-readable identifiers suitable for audit records.
const (
	ReasonOK              = "ok"
	ReasonNoChipData      = "no_chip_data"
	ReasonSODMalformed    = "sod_malformed"
	ReasonDGMalformed     = "dg_malformed"
	ReasonSODSignature    = "sod_signature_invalid"
	ReasonDGHashMismatch  = "dg_hash_mismatch"
	ReasonDGNotInSOD      = "dg_not_in_sod"
	ReasonDG1Missing      = "dg1_missing"
	ReasonMRZMismatch     = "mrz_mismatch"
	ReasonUnknownIssuer   = "unknown_issuing_state"
	ReasonPDPUnconfigured = "pdp_unconfigured"
	ReasonPDPError        = "pdp_error"
	ReasonPDPMalformed    = "pdp_malformed_response"
	ReasonPDPDeniedPrefix = "pdp_denied:"

	maxDataGroupBytes = 4 << 20
	sodKey            = "SOD"
	dg1Key            = "DG1"
)

var dgKeyRe = regexp.MustCompile(`^DG([0-9]{1,2})$`)

// Claimed carries the document fields FaceTec reported (and that the credential
// will be built from). They are cross-checked against the chip's DG1.
type Claimed struct {
	GivenName      string
	FamilyName     string
	DocumentNumber string
	DateOfBirth    string // YYYY-MM-DD
	DateOfExpiry   string // YYYY-MM-DD
	Nationality    string
	IssuingCountry string
	Sex            string // M/F/X (or MALE/FEMALE)
	DocumentType   string // passport, id_card, dl (empty: not checked)
}

// Result is the outcome of local passive authentication.
type Result struct {
	// OK is true only when every local check passed. It says nothing about
	// whether the DSC is trusted: that is the PDP's decision.
	OK bool
	// Reason is ReasonOK or the first failing check's reason code.
	Reason string
	// Detail is a human-readable explanation for logs (never contains PII).
	Detail string

	// DSC is the DER of the Document Signer Certificate that verified the SOD.
	DSC []byte
	// ExtraCerts are the other certificates carried in the SOD (untrusted
	// intermediates, never anchors).
	ExtraCerts [][]byte
	// IssuingState is the ISO 3166-1 alpha-3 code normalised from DG1.
	IssuingState string
	// SigningTime is the SOD signingTime attribute, nil when absent/unparsable.
	SigningTime *time.Time
	// DataGroups lists the data group numbers whose hashes were verified.
	DataGroups []int
}

// DSCFingerprint returns the hex SHA-256 of the DSC, or "".
func (r *Result) DSCFingerprint() string {
	if len(r.DSC) == 0 {
		return ""
	}
	sum := sha256.Sum256(r.DSC)
	return hex.EncodeToString(sum[:])
}

func fail(reason string, format string, args ...any) *Result {
	return &Result{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// Verify performs local passive authentication on FaceTec's
// documentData.nfcValues.rawData (keys "SOD", "DG1", "DG2", ... with base64
// values). It never returns OK without a verified SOD signature, verified DG1
// and a resolvable issuing state.
func Verify(raw map[string]string, claimed Claimed) *Result {
	if len(raw) == 0 || raw[sodKey] == "" {
		return fail(ReasonNoChipData, "no SOD in NFC raw data")
	}

	sodBytes, err := decodeDG(raw[sodKey])
	if err != nil {
		return fail(ReasonSODMalformed, "decode SOD: %v", err)
	}
	sod, err := document.NewSOD(sodBytes)
	if err != nil || sod == nil || sod.SD == nil || sod.LdsSecurityObject == nil {
		return fail(ReasonSODMalformed, "parse SOD: %v", err)
	}

	dsc, extras, signingTime, err := verifySODSignature(sod)
	if err != nil {
		return fail(ReasonSODSignature, "%v", err)
	}

	dgs, reason, err := verifyDataGroups(sod, raw)
	if err != nil {
		return fail(reason, "%v", err)
	}

	dg1Bytes, err := decodeDG(raw[dg1Key])
	if err != nil || len(dg1Bytes) == 0 {
		return fail(ReasonDG1Missing, "DG1 absent from chip data")
	}
	dg1, err := document.NewDG1(dg1Bytes)
	if err != nil || dg1 == nil || dg1.Mrz == nil {
		// gmrtd errors can embed raw MRZ fields (check-digit failures), so the
		// cause is deliberately not propagated.
		return fail(ReasonDGMalformed, "DG1 is not a valid MRZ")
	}

	state, err := NormalizeCountry(dg1.Mrz.IssuingState)
	if err != nil {
		return fail(ReasonUnknownIssuer, "DG1 issuing state %q is not a known ISO 3166-1 alpha-3 code", dg1.Mrz.IssuingState)
	}

	if err := crossCheckMRZ(dg1, claimed); err != nil {
		return fail(ReasonMRZMismatch, "%v", err)
	}

	return &Result{
		OK:           true,
		Reason:       ReasonOK,
		DSC:          dsc,
		ExtraCerts:   extras,
		IssuingState: state,
		SigningTime:  signingTime,
		DataGroups:   dgs,
	}
}

func decodeDG(b64 string) ([]byte, error) {
	if len(b64) > base64.StdEncoding.EncodedLen(maxDataGroupBytes) {
		return nil, errors.New("data group too large")
	}
	return base64.StdEncoding.DecodeString(b64)
}

// verifySODSignature verifies the single SignerInfo of the SOD with the DSC
// embedded in it. It deliberately does not chain the DSC to anything: that is
// the PDP's job. The DSC validity period is likewise left to the PDP, which
// evaluates it at the signing time we pass along.
func verifySODSignature(sod *document.SOD) (dsc []byte, extras [][]byte, signingTime *time.Time, err error) {
	sd := sod.SD
	if len(sd.SignerInfos) != 1 {
		return nil, nil, nil, fmt.Errorf("SOD has %d SignerInfos, want exactly 1", len(sd.SignerInfos))
	}
	si := &sd.SignerInfos[0]

	pool := &cms.GenericCertPool{}
	if err := pool.Add(sd.Certificates.Bytes); err != nil {
		return nil, nil, nil, fmt.Errorf("parse embedded certificates: %w", err)
	}
	all := pool.All()
	if len(all) == 0 {
		return nil, nil, nil, errors.New("SOD carries no certificates")
	}

	signer, err := selectSigner(pool, all, si)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := verifySignerInfo(sd, si, signer); err != nil {
		return nil, nil, nil, err
	}
	signingTime = signingTimeOf(si)

	dsc = bytes.Clone(signer.Raw)
	for i := range all {
		if !bytes.Equal(all[i].Raw, signer.Raw) {
			extras = append(extras, bytes.Clone(all[i].Raw))
		}
	}
	return dsc, extras, signingTime, nil
}

// verifySignerInfo checks the CMS authenticated attributes (RFC 5652 5.4):
// contentType and messageDigest are mandatory and bind the signature to
// eContent; then it verifies the signature over them with the signer's key.
func verifySignerInfo(sd *cms.SignedData, si *cms.SignerInfo, signer *cms.Certificate) error {
	if len(si.AuthenticatedAttributes) == 0 {
		return errors.New("SignerInfo without authenticated attributes is not supported")
	}
	aaType := si.AuthenticatedAttributes.ByOID(oid.OidContentType)
	aaDigest := si.AuthenticatedAttributes.ByOID(oid.OidMessageDigest)
	if aaType == nil || aaDigest == nil {
		return errors.New("missing contentType/messageDigest authenticated attribute")
	}
	var aaTypeOID asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(aaType.Values.Bytes, &aaTypeOID); err != nil || len(rest) != 0 {
		return errors.New("malformed contentType attribute")
	}
	if !aaTypeOID.Equal(sd.Content.EContentType) {
		return errors.New("contentType attribute differs from eContentType")
	}
	var aaDigestBytes []byte
	if rest, err := asn1.Unmarshal(aaDigest.Values.Bytes, &aaDigestBytes); err != nil || len(rest) != 0 {
		return errors.New("malformed messageDigest attribute")
	}
	hasher := cms.DefaultCryptoHasher{}
	contentHash, err := hasher.CryptoHashByOid(si.DigestAlgorithm.Algorithm, sd.Content.EContent)
	if err != nil {
		return fmt.Errorf("hash eContent: %w", err)
	}
	if !bytes.Equal(contentHash, aaDigestBytes) {
		return errors.New("messageDigest does not match eContent")
	}

	signed := si.AuthenticatedAttributes.SetOfAsnBytes()
	digest, err := hasher.CryptoHashByOid(si.DigestAlgorithm.Algorithm, signed)
	if err != nil {
		return fmt.Errorf("hash signed attributes: %w", err)
	}
	if err := cms.VerifySignature(signer.TbsCertificate.SubjectPublicKeyInfo.FullBytes,
		si.DigestAlgorithm.Algorithm, digest, si.DigestEncryptionAlgorithm.Algorithm, si.EncryptedDigest); err != nil {
		return fmt.Errorf("SOD signature does not verify with the embedded DSC: %w", err)
	}
	return nil
}

// signingTimeOf returns the optional CMS signingTime attribute, or nil.
func signingTimeOf(si *cms.SignerInfo) *time.Time {
	a := si.AuthenticatedAttributes.ByOID(oid.OidSigningTime)
	if a == nil {
		return nil
	}
	var st time.Time
	if rest, err := asn1.Unmarshal(a.Values.Bytes, &st); err != nil || len(rest) != 0 {
		return nil
	}
	st = st.UTC()
	return &st
}

// selectSigner picks the embedded certificate named by the SignerIdentifier.
// When it does not select exactly one certificate but the SOD embeds a single
// certificate, that one is used (several real-world passports encode the SID
// issuer differently): safe because its key must still verify the signature
// and the PDP must still trust it.
func selectSigner(pool *cms.GenericCertPool, all []cms.Certificate, si *cms.SignerInfo) (*cms.Certificate, error) {
	var matches []cms.Certificate
	switch {
	case si.Sid.Class == asn1.ClassContextSpecific && si.Sid.Tag == 0:
		matches = pool.BySKI(si.Sid.Bytes)
	case si.Sid.Class == asn1.ClassUniversal && si.Sid.Tag == asn1.TagSequence:
		m, err := pool.ByIssuerAndSerial(si.Sid.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("match signer identifier: %w", err)
		}
		matches = m
	default:
		return nil, errors.New("unsupported SignerIdentifier")
	}
	if len(matches) == 1 {
		return &matches[0], nil
	}
	if len(all) == 1 {
		return &all[0], nil
	}
	return nil, fmt.Errorf("signer identifier matched %d of %d embedded certificates", len(matches), len(all))
}

// presentedDGNumbers returns the sorted numbers of the DGn keys in raw.
func presentedDGNumbers(raw map[string]string) []int {
	var nums []int
	for k := range raw {
		if k == sodKey {
			continue
		}
		m := dgKeyRe.FindStringSubmatch(k)
		if m == nil {
			continue // unrelated key (e.g. EF.COM); not chip data we rely on
		}
		n, _ := strconv.Atoi(m[1])
		nums = append(nums, n)
	}
	slices.Sort(nums)
	return nums
}

// verifyDataGroups checks every presented DGn against the SOD hash list. A
// presented data group that the SOD does not cover is rejected (data
// injection), as is any hash mismatch.
func verifyDataGroups(sod *document.SOD, raw map[string]string) (verified []int, reason string, err error) {
	hasher := cms.DefaultCryptoHasher{}
	alg := sod.LdsSecurityObject.HashAlgorithm.Algorithm

	nums := presentedDGNumbers(raw)
	if len(nums) == 0 {
		return nil, ReasonDG1Missing, errors.New("no data groups presented")
	}
	for _, n := range nums {
		data, derr := decodeDG(raw["DG"+strconv.Itoa(n)])
		if derr != nil || len(data) == 0 {
			return nil, ReasonDGMalformed, fmt.Errorf("DG%d is not valid base64 data", n)
		}
		want := sod.DgHash(n)
		if len(want) == 0 {
			return nil, ReasonDGNotInSOD, fmt.Errorf("DG%d is not covered by the SOD", n)
		}
		got, herr := hasher.CryptoHashByOid(alg, data)
		if herr != nil {
			return nil, ReasonSODMalformed, fmt.Errorf("hash DG%d: %w", n, herr)
		}
		if !bytes.Equal(got, want) {
			return nil, ReasonDGHashMismatch, fmt.Errorf("DG%d hash does not match the SOD", n)
		}
		verified = append(verified, n)
	}
	return verified, "", nil
}

// NormalizeCountry maps an MRZ issuing-state / nationality code to ISO 3166-1
// alpha-3. ICAO 9303 uses "D" for Germany; everything else must already be a
// known alpha-3 code. Unknown codes are an error (fail closed).
func NormalizeCountry(code string) (string, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "D" {
		return "DEU", nil
	}
	if c := iso3166.ByAlpha3(code); c != nil && len(code) == 3 {
		return c.Alpha3, nil
	}
	return "", fmt.Errorf("unknown country code %q", code)
}

// resolveClaimedCountry maps a FaceTec-reported country (alpha-3, alpha-2 or
// English name) to alpha-3.
func resolveClaimedCountry(s string) (string, error) {
	s = strings.TrimSpace(s)
	if a3, err := NormalizeCountry(s); err == nil {
		return a3, nil
	}
	if len(s) == 2 {
		if c := iso3166.ByAlpha2(s); c != nil {
			return c.Alpha3, nil
		}
	}
	for i := range iso3166.Countries {
		if strings.EqualFold(iso3166.Countries[i].Name, s) {
			return iso3166.Countries[i].Alpha3, nil
		}
	}
	return "", fmt.Errorf("unknown country %q", s)
}

// crossCheckMRZ compares DG1 with the fields FaceTec reported. Document
// number, date of birth and date of expiry are mandatory in the claim (they
// bind the chip to the credential); the remaining fields are compared when
// the claim carries them. The error never echoes personal data.
func crossCheckMRZ(dg1 *document.DG1, c Claimed) error {
	m := dg1.Mrz

	if c.DocumentNumber == "" || c.DateOfBirth == "" || c.DateOfExpiry == "" {
		return errors.New("claimed document number/date of birth/date of expiry missing")
	}
	if !equalAlnum(m.DocumentNumber, c.DocumentNumber) {
		return errors.New("document number differs between chip and scan")
	}
	if !sameMRZDate(m.DateOfBirth, c.DateOfBirth, true) {
		return errors.New("date of birth differs between chip and scan")
	}
	if !sameMRZDate(m.DateOfExpiry, c.DateOfExpiry, false) {
		return errors.New("date of expiry differs between chip and scan")
	}
	if err := crossCheckNames(m, c); err != nil {
		return err
	}
	if err := crossCheckDocumentType(m, c.DocumentType); err != nil {
		return err
	}
	if c.Sex != "" && normalizeSex(m.Sex) != normalizeSex(c.Sex) {
		return errors.New("sex differs between chip and scan")
	}
	if c.Nationality != "" && !sameCountry(m.Nationality, c.Nationality) {
		return errors.New("nationality differs between chip and scan")
	}
	if c.IssuingCountry != "" && !sameCountry(m.IssuingState, c.IssuingCountry) {
		return errors.New("issuing state differs between chip and scan")
	}
	return nil
}

// crossCheckDocumentType binds the document type the policy will see to the
// signed MRZ document code (ICAO 9303: P = passport, I/A/C = identity card).
// Other claimed types (e.g. dl) are not eMRTDs and are not checked.
func crossCheckDocumentType(m *mrz.MRZ, claimed string) error {
	code := strings.ToUpper(strings.TrimSpace(m.DocumentCode))
	switch claimed {
	case "passport":
		if !strings.HasPrefix(code, "P") {
			return errors.New("document type differs between chip and scan")
		}
	case "id_card":
		if code == "" || !strings.ContainsAny(code[:1], "IAC") {
			return errors.New("document type differs between chip and scan")
		}
	}
	return nil
}

// normalizeSex maps an MRZ sex marker or a claimed sex string to M, F or X
// (unspecified, including the MRZ filler '<').
func normalizeSex(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "M", "MALE":
		return "M"
	case "F", "FEMALE":
		return "F"
	default:
		return "X"
	}
}

// crossCheckNames compares the holder name fields the claim carries.
func crossCheckNames(m *mrz.MRZ, c Claimed) error {
	if m.NameOfHolder == nil {
		return nil
	}
	if c.FamilyName != "" && !equalAlpha(m.NameOfHolder.Primary, c.FamilyName) {
		return errors.New("family name differs between chip and scan")
	}
	if c.GivenName != "" && !equalAlpha(m.NameOfHolder.Secondary, c.GivenName) {
		return errors.New("given name differs between chip and scan")
	}
	return nil
}

// sameCountry reports whether an MRZ country code and a claimed country
// denote the same state. Unresolvable values never match (fail closed).
func sameCountry(mrzCode, claimed string) bool {
	want, err := NormalizeCountry(mrzCode)
	if err != nil {
		return false
	}
	got, err := resolveClaimedCountry(claimed)
	return err == nil && want == got
}

// now is the clock used to resolve the MRZ century (overridable in tests).
var now = time.Now

// sameMRZDate compares an MRZ YYMMDD date with a YYYY-MM-DD claim. The MRZ
// does not encode the century, so it is resolved explicitly (fail closed):
// a date of birth is never in the future (the latest century that is not in the
// future wins, so holders older than 100 are refused); an expiry date is
// taken as 20YY, since no chip document expires in the 1900s.
func sameMRZDate(mrzDate, iso string, birth bool) bool {
	if len(mrzDate) != 6 || len(iso) != 10 || iso[4] != '-' || iso[7] != '-' {
		return false
	}
	if mrzDate[2:] != iso[5:7]+iso[8:10] || mrzDate[:2] != iso[2:4] {
		return false
	}
	claimed, err := time.Parse("2006-01-02", iso) // rejects impossible calendar dates
	if err != nil {
		return false
	}
	century := 2000
	if birth {
		// Resolve the century from the MRZ date: a birth date is never in the future.
		t, err := time.Parse("2006-01-02", "20"+mrzDate[:2]+"-"+iso[5:7]+"-"+iso[8:10])
		if err != nil || t.After(now()) {
			century = 1900
		}
	}
	return claimed.Year() == century+int(mrzDate[0]-'0')*10+int(mrzDate[1]-'0')
}

func equalAlnum(a, b string) bool { return fold(a, true) == fold(b, true) && fold(a, true) != "" }

func equalAlpha(a, b string) bool { return fold(a, false) == fold(b, false) }

// fold upper-cases and keeps only A-Z (and 0-9 when digits is true), which is
// the MRZ repertoire ('<' and spaces in names, filler characters, etc. drop).
func fold(s string, digits bool) string {
	var sb strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (digits && r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

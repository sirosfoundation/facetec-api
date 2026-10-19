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
	ReasonOK             = "ok"
	ReasonNoChipData     = "no_chip_data"
	ReasonSODMalformed   = "sod_malformed"
	ReasonDGMalformed    = "dg_malformed"
	ReasonSODSignature   = "sod_signature_invalid"
	ReasonDGHashMismatch = "dg_hash_mismatch"
	ReasonDGNotInSOD     = "dg_not_in_sod"
	ReasonDG1Missing     = "dg1_missing"
	ReasonUnknownIssuer  = "unknown_issuing_state"
	ReasonSigningTime    = "signing_time_implausible"
	// ReasonDocTypeMismatch: the signed DG1 document code contradicts the
	// document type FaceTec reported. Callers refuse such scans outright, since
	// the reported type selects which policy rule (and trust scope) applies.
	ReasonDocTypeMismatch = "doc_type_mismatch"
	ReasonPDPUnconfigured = "pdp_unconfigured"
	ReasonPDPError        = "pdp_error"
	ReasonPDPMalformed    = "pdp_malformed_response"
	ReasonPDPDeniedPrefix = "pdp_denied:"

	// signingTimeSkew tolerates clock drift when rejecting future SOD signing times.
	signingTimeSkew = 10 * time.Minute
	// maxDocumentValidity bounds how long before its expiry a document can have
	// been signed (passports are valid for at most 10 years; margin included).
	maxDocumentValidity = 11 * 365 * 24 * time.Hour

	isoDate = "2006-01-02"

	maxDataGroupBytes = 4 << 20
	sodKey            = "SOD"
	dg1Key            = "DG1"
	dg11Key           = "DG11"
)

var dgKeyRe = regexp.MustCompile(`^DG([0-9]{1,2})$`)

// Claimed carries the document fields FaceTec reported from OCR. Verify
// compares them with the chip's DG1 for diagnostics (Result.Mismatches); only
// the document type must agree, because it selects the policy rule. The
// credential is built from the chip's own values (Result.Identity).
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
	// Identity is the holder's identity as signed on the chip (DG1, refined by
	// DG11 when present). Set only when OK.
	Identity *Identity
	// Mismatches names the fields where FaceTec's OCR differed from the chip
	// ("family_name", "date_of_birth", ...). Diagnostic only, never values.
	Mismatches []string
}

// Identity is the holder's identity read from the chip, after the SOD
// signature and the data-group hashes were verified. Names and dates come from
// DG1 (the signed MRZ); DG11, when the chip carries it, supplies the full,
// untruncated name and the date of birth with its century. A field the chip
// does not carry in usable form is empty.
type Identity struct {
	FamilyName     string
	GivenName      string
	DocumentNumber string
	DateOfBirth    string // YYYY-MM-DD
	DateOfExpiry   string // YYYY-MM-DD
	// Nationality and IssuingState are the MRZ codes as signed (ISO 3166-1
	// alpha-3, or an ICAO code such as "D").
	Nationality  string
	IssuingState string
	Sex          string // M, F or X; empty when unspecified
	// DocumentCode is the MRZ document code, e.g. "P" or "ID".
	DocumentCode string
	// FromDG11 lists the fields DG11 supplied ("name", "date_of_birth").
	FromDG11 []string
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

	// The reported document type selects the policy rule (and trust scope),
	// so it must agree with the signed document code.
	if err := crossCheckDocumentType(dg1.Mrz, claimed.DocumentType); err != nil {
		return fail(ReasonDocTypeMismatch, "%v", err)
	}

	identity, err := identityFromChip(dg1, raw, dgs)
	if err != nil {
		return fail(ReasonDGMalformed, "%v", err)
	}
	if err := plausibleSigningTime(signingTime, identity.DateOfExpiry); err != nil {
		return fail(ReasonSigningTime, "%v", err)
	}

	return &Result{
		Identity:     identity,
		Mismatches:   mrzMismatches(dg1, claimed),
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

// plausibleSigningTime bounds the signer-asserted CMS signingTime, which the
// PDP uses as the certificate validation time. The attribute is covered by the
// DSC's own signature, so a holder of an expired DSC key could backdate it into
// the certificate's validity window; it therefore has to be consistent with
// facts we already hold: not in the future (beyond a small clock skew), and,
// relative to the DG1-bound expiry date, not after it and not more than
// maxDocumentValidity before it. A nil signing time is fine (the PDP then
// evaluates at the current time).
func plausibleSigningTime(st *time.Time, expiryISO string) error {
	if st == nil {
		return nil
	}
	if st.After(now().Add(signingTimeSkew)) {
		return errors.New("SOD signing time is in the future")
	}
	expiry, err := time.Parse(isoDate, expiryISO)
	if err != nil {
		return errors.New("cannot bound SOD signing time without a valid expiry date")
	}
	if st.After(expiry.Add(24 * time.Hour)) {
		return errors.New("SOD signing time is after the document expiry")
	}
	if st.Before(expiry.Add(-maxDocumentValidity)) {
		return errors.New("SOD signing time is implausibly long before the document expiry")
	}
	return nil
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

// mrzMismatches lists the fields where FaceTec's OCR (the claim) differs from
// the chip's DG1. The credential is built from the chip, so these no longer
// fail verification; they are reported for diagnostics (an OCR misread of the
// MRZ, typically a '<' filler read as a letter). A field the claim leaves
// empty is not compared. Only field names are returned, never values.
func mrzMismatches(dg1 *document.DG1, c Claimed) []string {
	m := dg1.Mrz
	var out []string
	if c.DocumentNumber != "" && !equalAlnum(m.DocumentNumber, c.DocumentNumber) {
		out = append(out, "document_number")
	}
	if c.DateOfBirth != "" && !sameMRZDate(m.DateOfBirth, c.DateOfBirth, true) {
		out = append(out, "date_of_birth")
	}
	if c.DateOfExpiry != "" && !sameMRZDate(m.DateOfExpiry, c.DateOfExpiry, false) {
		out = append(out, "date_of_expiry")
	}
	if m.NameOfHolder != nil {
		if c.FamilyName != "" && !equalAlpha(m.NameOfHolder.Primary, c.FamilyName) {
			out = append(out, "family_name")
		}
		if c.GivenName != "" && !equalAlpha(m.NameOfHolder.Secondary, c.GivenName) {
			out = append(out, "given_name")
		}
	}
	if c.Sex != "" && normalizeSex(m.Sex) != normalizeSex(c.Sex) {
		out = append(out, "sex")
	}
	if c.Nationality != "" && !sameCountry(m.Nationality, c.Nationality) {
		out = append(out, "nationality")
	}
	if c.IssuingCountry != "" && !sameCountry(m.IssuingState, c.IssuingCountry) {
		out = append(out, "issuing_country")
	}
	return out
}

// identityFromChip reads the holder's identity from the verified DG1, refined
// by DG11 when the chip presented it (its hash was verified with the other
// data groups). DG1's expiry date is required: it bounds the SOD signing time
// and gates issuance. Other unusable DG1 values are left empty; DG11 problems
// are ignored, since DG1 is complete on its own.
func identityFromChip(dg1 *document.DG1, raw map[string]string, verifiedDGs []int) (*Identity, error) {
	m := dg1.Mrz
	id := &Identity{
		DocumentNumber: strings.TrimSpace(strings.Trim(m.DocumentNumber, "<")),
		Nationality:    strings.TrimSpace(m.Nationality),
		IssuingState:   strings.TrimSpace(m.IssuingState),
		Sex:            chipSex(m.Sex),
		DocumentCode:   strings.TrimSpace(strings.Trim(m.DocumentCode, "<")),
	}
	if m.NameOfHolder != nil {
		id.FamilyName = cleanName(m.NameOfHolder.Primary)
		id.GivenName = cleanName(m.NameOfHolder.Secondary)
	}
	if dob, ok := mrzDateToISO(m.DateOfBirth, true); ok {
		id.DateOfBirth = dob
	}
	expiry, ok := mrzDateToISO(m.DateOfExpiry, false)
	if !ok {
		return nil, errors.New("DG1 date of expiry is not a valid date")
	}
	id.DateOfExpiry = expiry

	if slices.Contains(verifiedDGs, 11) {
		if b, err := decodeDG(raw[dg11Key]); err == nil {
			if dg11, err := document.NewDG11(b); err == nil && dg11 != nil {
				refineFromDG11(id, dg11.Details)
			}
		}
	}
	return id, nil
}

// refineFromDG11 applies DG11's full name and full date of birth. The DG11
// name is the holder's name in full where DG1 truncates it to fit the MRZ; its
// date of birth carries the century DG1's YYMMDD lacks. A DG11 date of birth
// that contradicts DG1's is ignored (DG1 is the mandatory, always-present one).
func refineFromDG11(id *Identity, d document.PersonDetails) {
	if d.NameOfHolder != nil {
		family, given := cleanName(d.NameOfHolder.Primary), cleanName(d.NameOfHolder.Secondary)
		if family != "" {
			id.FamilyName, id.GivenName = family, given
			id.FromDG11 = append(id.FromDG11, "name")
		}
	}
	if full := strings.TrimSpace(d.FullDateOfBirth); len(full) == 8 {
		iso := full[:4] + "-" + full[4:6] + "-" + full[6:]
		if _, err := time.Parse(isoDate, iso); err == nil && (id.DateOfBirth == "" || id.DateOfBirth[2:] == iso[2:]) {
			id.DateOfBirth = iso
			id.FromDG11 = append(id.FromDG11, "date_of_birth")
		}
	}
}

// cleanName turns an MRZ name component (gmrtd has already replaced '<' with
// spaces) into single-space-separated words.
func cleanName(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "<", " ")), " ")
}

// chipSex maps the MRZ sex field to M, F or X; '<' (unspecified) is empty.
func chipSex(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "M":
		return "M"
	case "F":
		return "F"
	case "X":
		return "X"
	default:
		return ""
	}
}

// errDocTypeMismatch is returned when the claimed document type contradicts the
// signed MRZ document code.
var errDocTypeMismatch = errors.New("document type differs between chip and scan")

// crossCheckDocumentType binds the document type the policy will see to the
// signed MRZ document code (ICAO 9303: P = passport, I/A/C = identity card).
// An empty claim is not checked; every other claimed type must match.
func crossCheckDocumentType(m *mrz.MRZ, claimed string) error {
	code := strings.ToUpper(strings.TrimSpace(m.DocumentCode))
	switch claimed {
	case "passport":
		if !strings.HasPrefix(code, "P") {
			return errDocTypeMismatch
		}
	case "id_card":
		if code == "" || !strings.ContainsAny(code[:1], "IAC") {
			return errDocTypeMismatch
		}
	default:
		// A parsed ICAO DG1 is a passport or an ID card; any other non-empty
		// claimed type (dl, unknown, ...) contradicts it.
		if claimed != "" {
			return errDocTypeMismatch
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

// mrzDateToISO converts an MRZ YYMMDD date to YYYY-MM-DD, resolving the
// century the same way sameMRZDate does: a date of birth is never in the future
// (the latest century that is not in the future wins); an expiry date is 20YY.
// It reports false for an incomplete or impossible date (e.g. "85<<<<").
func mrzDateToISO(mrzDate string, birth bool) (string, bool) {
	if len(mrzDate) != 6 {
		return "", false
	}
	century := "20"
	if birth {
		t, err := time.Parse(isoDate, "20"+mrzDate[:2]+"-"+mrzDate[2:4]+"-"+mrzDate[4:6])
		if err != nil || t.After(now()) {
			century = "19"
		}
	}
	iso := century + mrzDate[:2] + "-" + mrzDate[2:4] + "-" + mrzDate[4:6]
	if _, err := time.Parse(isoDate, iso); err != nil {
		return "", false
	}
	return iso, true
}

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
	claimed, err := time.Parse(isoDate, iso) // rejects impossible calendar dates
	if err != nil {
		return false
	}
	century := 2000
	if birth {
		// Resolve the century from the MRZ date: a birth date is never in the future.
		t, err := time.Parse(isoDate, "20"+mrzDate[:2]+"-"+iso[5:7]+"-"+iso[8:10])
		if err != nil || t.After(now()) {
			century = 1900
		}
	}
	return claimed.Year() == century+int(mrzDate[0]-'0')*10+int(mrzDate[1]-'0')
}

func equalAlnum(a, b string) bool {
	return representable(b, true) && fold(a, true) == fold(b, true) && fold(a, true) != ""
}

// equalAlpha compares names over the MRZ repertoire. A claim that folds to
// nothing (e.g. a non-Latin name) never matches: DG1 cannot vouch for it.
func equalAlpha(a, b string) bool {
	return representable(b, false) && fold(b, false) != "" && fold(a, false) == fold(b, false)
}

// representable reports whether every character of a claimed value is one the
// MRZ normalisation (fold) keeps: letters, and digits when digits is true
// (document numbers: nothing else is allowed, since the claimed string is what
// gets issued). Names may additionally contain spaces, '<' and the usual
// name punctuation, which the MRZ renders as fillers.
// Anything else (e.g. a digit suffix on a name) would be silently dropped by
// fold, letting an altered claim ride on a chip-bound match while the original
// string is what gets issued, so it never matches.
func representable(s string, digits bool) bool {
	for _, r := range strings.ToUpper(s) {
		switch {
		case r >= 'A' && r <= 'Z':
		case digits && r >= '0' && r <= '9':
		case !digits && (r == ' ' || r == '<' || r == '-' || r == '\'' || r == '.' || r == ','):
			// Name punctuation: the MRZ renders it as a filler.
		default:
			return false
		}
	}
	return true
}

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

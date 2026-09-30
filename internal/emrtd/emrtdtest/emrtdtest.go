// Package emrtdtest builds synthetic, self-consistent eMRTD chip data (EF.SOD,
// EF.DG1, EF.DG2) signed by a throw-away CSCA/DSC pair, for tests only. No
// real person's data is involved.
package emrtdtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// Options tweak the generated chip for negative tests.
type Options struct {
	// Country is the DSC/CSCA issuer C (alpha-2). Default "SE".
	Country string
	// IssuingState is the MRZ issuing state. Default "SWE".
	IssuingState string
	// Nationality is the MRZ nationality. Default "SWE".
	Nationality string
	// SigningTime, when non-zero, is added as the CMS signingTime attribute.
	SigningTime time.Time
	// WrongSigner signs with a key that does not match the embedded DSC.
	WrongSigner bool
	// TamperContent alters eContent after signing (messageDigest mismatch).
	TamperContent bool
	// SIDBySKI identifies the signer by subjectKeyIdentifier instead of
	// issuerAndSerialNumber.
	SIDBySKI bool
	// BadSID makes the SID match no embedded certificate.
	BadSID bool
	// SoleCert keeps the DSC the only embedded certificate even with BadSID.
	SoleCert bool
	// ExtraCert embeds the CSCA certificate in the SOD as an extra certificate.
	ExtraCert bool
	// OmitDG1 leaves DG1 out of the SOD hash list (and the chip data).
	OmitDG1 bool
	// MalformedDG1 makes DG1 an unparsable structure that the SOD nevertheless
	// covers (hash and signature are valid).
	MalformedDG1 bool
	// DocumentCode is the two-character MRZ document code. Default "P<".
	DocumentCode string
	// TwoSigners emits two SignerInfos.
	TwoSigners bool
}

// Chip is generated chip data plus the certificates involved.
type Chip struct {
	// Raw is documentData.nfcValues.rawData ("SOD", "DG1", "DG2").
	Raw map[string]string
	// DSC and CSCA are the DER certificates.
	DSC, CSCA []byte
	// Person-ish fields encoded in the MRZ (fictitious).
	DocumentNumber, DateOfBirth, DateOfExpiry string // dates as YYYY-MM-DD
	FamilyName, GivenName                     string
}

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidLDS        = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidContent    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidDigest     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigTime    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func raw(class, tag int, compound bool, content []byte) []byte {
	return must(asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: content}))
}

func seq(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return raw(asn1.ClassUniversal, asn1.TagSequence, true, b)
}

func set(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return raw(asn1.ClassUniversal, asn1.TagSet, true, b)
}

func der(v any) []byte { return must(asn1.Marshal(v)) }

func sha256Alg() []byte { return der(algID{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}) }

func attr(oid asn1.ObjectIdentifier, value []byte) []byte {
	return seq(der(oid), set(value))
}

// New generates a fresh chip.
func New(o Options) *Chip {
	if o.Country == "" {
		o.Country = "SE"
	}
	if o.IssuingState == "" {
		o.IssuingState = "SWE"
	}
	if o.Nationality == "" {
		o.Nationality = "SWE"
	}
	c := &Chip{
		DocumentNumber: "AB1234567",
		DateOfBirth:    "1985-03-07",
		DateOfExpiry:   "2031-09-30",
		FamilyName:     "ERIKSSON",
		GivenName:      "ANNA MARIA",
	}

	cscaKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	dscKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	otherKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	now := time.Now()
	cscaTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Country: []string{o.Country}, CommonName: "Test CSCA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	cscaDER := must(x509.CreateCertificate(rand.Reader, cscaTmpl, cscaTmpl, &cscaKey.PublicKey, cscaKey))
	csca := must(x509.ParseCertificate(cscaDER))
	dscTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{Country: []string{o.Country}, CommonName: "Test DSC"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{9, 8, 7, 6},
	}
	dscDER := must(x509.CreateCertificate(rand.Reader, dscTmpl, csca, &dscKey.PublicKey, cscaKey))
	dsc := must(x509.ParseCertificate(dscDER))
	c.DSC, c.CSCA = dscDER, cscaDER

	mrz := buildTD3(o, c)
	dg1 := tlv(0x61, append([]byte{0x5F, 0x1F, byte(len(mrz))}, []byte(mrz)...))
	if o.MalformedDG1 {
		dg1 = []byte{0x61, 0x02, 0x01, 0x02}
	}
	dg2 := append([]byte{0x75, 0x10}, []byte("fake-face-image!")...)

	hashes := [][]byte{seq(der(2), der(hash(dg2)))}
	rawData := map[string]string{"DG2": base64.StdEncoding.EncodeToString(dg2)}
	if !o.OmitDG1 {
		hashes = append([][]byte{seq(der(1), der(hash(dg1)))}, hashes...)
		rawData["DG1"] = base64.StdEncoding.EncodeToString(dg1)
	}
	lds := seq(der(0), sha256Alg(), seq(hashes...))

	signKey := dscKey
	if o.WrongSigner {
		signKey = otherKey
	}
	signer := func() []byte {
		attrs := attr(oidContent, der(oidLDS))
		if !o.SigningTime.IsZero() {
			attrs = append(attrs, attr(oidSigTime, der(o.SigningTime.UTC()))...)
		}
		attrs = append(attrs, attr(oidDigest, der(hash(lds)))...)
		toSign := raw2set(attrs)
		sig := must(ecdsa.SignASN1(rand.Reader, signKey, hash(toSign)))

		var sid []byte
		switch {
		case o.BadSID:
			sid = seq(der(pkix.Name{CommonName: "nobody"}.ToRDNSequence()), der(big.NewInt(1)))
		case o.SIDBySKI:
			sid = raw(asn1.ClassContextSpecific, 0, false, dsc.SubjectKeyId)
		default:
			sid = seq(dsc.RawIssuer, der(dsc.SerialNumber))
		}
		return seq(der(1), sid, sha256Alg(), raw(asn1.ClassContextSpecific, 0, true, attrs),
			seq(der(oidECDSA256)), der(sig))
	}

	signerInfos := signer()
	if o.TwoSigners {
		signerInfos = append(signerInfos, signer()...)
	}

	content := lds
	if o.TamperContent {
		content = append([]byte{}, lds...)
		content[len(content)-1] ^= 0x01 // a DG2 hash byte: eContent differs from the signed messageDigest
	}
	eci := seq(der(oidLDS), raw(asn1.ClassContextSpecific, 0, true, der(content)))
	certs := dscDER
	if o.ExtraCert {
		certs = append(append([]byte{}, dscDER...), cscaDER...)
	}
	if o.BadSID && !o.SoleCert {
		// the only way for the SID to match nothing while two certs are
		// embedded is to also embed the CSCA (no sole-cert fallback)
		certs = append(append([]byte{}, dscDER...), cscaDER...)
	}
	signedData := seq(der(3), set(sha256Alg()), eci,
		raw(asn1.ClassContextSpecific, 0, true, certs),
		set(signerInfos))
	ci := seq(der(oidSignedData), raw(asn1.ClassContextSpecific, 0, true, signedData))
	sod := raw(asn1.ClassApplication, 23, true, ci)
	rawData["SOD"] = base64.StdEncoding.EncodeToString(sod)
	c.Raw = rawData
	return c
}

// raw2set wraps already-encoded attributes in a SET OF (tag 0x31), the form
// CMS signs (RFC 5652 5.4).
func raw2set(attrs []byte) []byte {
	return raw(asn1.ClassUniversal, asn1.TagSet, true, attrs)
}

func hash(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func tlv(tag byte, content []byte) []byte {
	if len(content) < 128 {
		return append([]byte{tag, byte(len(content))}, content...)
	}
	return append([]byte{tag, 0x81, byte(len(content))}, content...)
}

func buildTD3(o Options, c *Chip) string {
	pad := func(s string, n int) string { return s + strings.Repeat("<", n-len(s)) }
	yymmdd := func(iso string) string { return iso[2:4] + iso[5:7] + iso[8:10] }
	name := c.FamilyName + "<<" + strings.ReplaceAll(c.GivenName, " ", "<")
	issuing := o.IssuingState
	if issuing == "D" {
		issuing = "D<<"
	}
	code := o.DocumentCode
	if code == "" {
		code = "P<"
	}
	l1 := code + pad(issuing, 3) + pad(name, 39)
	doc := pad(c.DocumentNumber, 9)
	dob, exp := yymmdd(c.DateOfBirth), yymmdd(c.DateOfExpiry)
	opt := pad("", 14)
	l2 := doc + cd(doc) + pad(o.Nationality, 3) + dob + cd(dob) + "F" + exp + cd(exp) + opt + cd(opt)
	composite := l2[0:10] + l2[13:20] + l2[21:43]
	return l1 + l2 + cd(composite)
}

// cd computes the ICAO 9303 check digit (weights 7,3,1).
func cd(s string) string {
	w := []int{7, 3, 1}
	sum := 0
	for i, r := range s {
		v := 0
		switch {
		case r >= '0' && r <= '9':
			v = int(r - '0')
		case r >= 'A' && r <= 'Z':
			v = int(r-'A') + 10
		}
		sum += v * w[i%3]
	}
	return strconv.Itoa(sum % 10)
}

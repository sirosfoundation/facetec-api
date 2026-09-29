package facetec

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
)

// austrianSOD returns the base64 EF.SOD of a real Austrian passport sample
// (see testdata/README.md). Its document signer chains to an Austrian CSCA in
// gmrtd's embedded master lists.
func austrianSOD(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/at_sod.b64")
	if err != nil {
		t.Fatalf("read SOD fixture: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func austrianChip(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{nfcRawSODKey: austrianSOD(t)}
}

func TestVerifyPassportChip_RequiresDG1AndDG2(t *testing.T) {
	// The Austrian SOD chains to a trusted CSCA. A chip that omits DG1 and
	// DG2 is rejected for that, which is only reached after the chain verifies.
	for _, country := range []string{"AT", "AUT", "Austria"} {
		err := VerifyPassportChip(nil, austrianChip(t), country)
		if err == nil || !strings.Contains(err.Error(), "DG1 and DG2 are missing") {
			t.Errorf("country %s: error = %v", country, err)
		}
	}
}

func TestVerifyPassportChip_CountryMismatch(t *testing.T) {
	err := VerifyPassportChip(nil, austrianChip(t), "SWE")
	if err == nil || !strings.Contains(err.Error(), "does not match countryCode SE") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyPassportChip_UnknownCountry(t *testing.T) {
	err := VerifyPassportChip(nil, austrianChip(t), "Narnia")
	if err == nil || !strings.Contains(err.Error(), "unknown country code") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyPassportChip_MissingSOD(t *testing.T) {
	for name, raw := range map[string]map[string]string{
		"nil map":     nil,
		"empty map":   {},
		"only DG1":    {"DG1": base64.StdEncoding.EncodeToString([]byte("x"))},
		"blank value": {nfcRawSODKey: "  "},
	} {
		err := VerifyPassportChip(nil, raw, "AUT")
		if err == nil || !strings.Contains(err.Error(), "EF.SOD: missing") {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestVerifyPassportChip_MalformedSOD(t *testing.T) {
	cases := map[string]string{
		"not base64":  "%%%not-base64%%%",
		"garbage":     base64.StdEncoding.EncodeToString([]byte("definitely not a CMS SignedData")),
		"oversize":    strings.Repeat("A", base64.StdEncoding.EncodedLen(maxNFCRawFileBytes)+4),
		"empty bytes": base64.StdEncoding.EncodeToString(nil),
	}
	for name, sod := range cases {
		err := VerifyPassportChip(nil, map[string]string{nfcRawSODKey: sod}, "AUT")
		if err == nil || !strings.Contains(err.Error(), "EF.SOD") {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestVerifyPassportChip_TamperedSignatureRejected(t *testing.T) {
	sodBytes, err := base64.StdEncoding.DecodeString(austrianSOD(t))
	if err != nil {
		t.Fatal(err)
	}
	// The SignerInfo's encryptedDigest is the trailing element of the SOD, so
	// flipping the last byte corrupts the signature and nothing else.
	sodBytes[len(sodBytes)-1] ^= 0x01
	raw := map[string]string{nfcRawSODKey: base64.StdEncoding.EncodeToString(sodBytes)}
	err = VerifyPassportChip(nil, raw, "AUT")
	if err == nil || !strings.Contains(err.Error(), "not a trusted CSCA") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyPassportChip_DataGroupHashMismatch(t *testing.T) {
	raw := austrianChip(t)
	raw["DG2"] = base64.StdEncoding.EncodeToString([]byte("not the DG2 the SOD signed"))
	err := VerifyPassportChip(nil, raw, "AUT")
	if err == nil || !strings.Contains(err.Error(), "DG2 hash does not match") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyPassportChip_IgnoresOtherDataGroups(t *testing.T) {
	// Only DG1 and DG2 are authenticated. A data group the SOD does not cover
	// is ignored, same as EF.COM.
	raw := austrianChip(t)
	raw["DG16"] = base64.StdEncoding.EncodeToString([]byte("injected"))
	err := VerifyPassportChip(nil, raw, "AUT")
	if err == nil || !strings.Contains(err.Error(), "DG1 and DG2 are missing") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "DG16") {
		t.Fatalf("other data group rejected: %v", err)
	}
}

func TestVerifyPassportChip_MalformedDataGroup(t *testing.T) {
	raw := austrianChip(t)
	raw["DG1"] = "***"
	err := VerifyPassportChip(nil, raw, "AUT")
	if err == nil || !strings.Contains(err.Error(), "DG1: invalid base64") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyPassportChip_IgnoresNonDataGroupKeys(t *testing.T) {
	raw := austrianChip(t)
	raw["COM"] = base64.StdEncoding.EncodeToString([]byte("EF.COM is not hashed by the SOD"))
	raw["vendorNote"] = "anything"
	err := VerifyPassportChip(nil, raw, "AUT")
	if err == nil || !strings.Contains(err.Error(), "DG1 and DG2 are missing") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "COM") || strings.Contains(err.Error(), "vendorNote") {
		t.Fatalf("non-data-group key rejected: %v", err)
	}
}

func TestVerifyPassportChip_NoCSCAForCountry(t *testing.T) {
	trusted, err := trustedCSCACerts()
	if err != nil {
		t.Fatal(err)
	}
	// A trust store that only knows Swedish CSCAs cannot vouch for Austria.
	pool := &cms.GenericCertPool{}
	pool.AddCerts(trusted.ByIssuerCountry("SE"))
	err = verifyPassportChip(nil, austrianChip(t), "AUT", pool)
	if err == nil || !strings.Contains(err.Error(), "no trusted CSCA for AT") {
		t.Fatalf("error = %v", err)
	}
}

// TestVerifyPassportChip_WrongCSCAForCountryRejected keeps every Austrian
// CSCA except the one that actually issued the sample's document signer.
// The name lookup would still succeed (same country, same CA names); only
// signature verification of the DSC against the CSCA public key can tell
// these apart.
func TestVerifyPassportChip_WrongCSCAForCountryRejected(t *testing.T) {
	sodBytes, err := base64.StdEncoding.DecodeString(austrianSOD(t))
	if err != nil {
		t.Fatal(err)
	}
	sod, err := document.NewSOD(sodBytes)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := cms.ParseCertificates(sod.SD.Certificates.Bytes)
	if err != nil || len(embedded) == 0 {
		t.Fatalf("embedded certs: %v (%d)", err, len(embedded))
	}
	aki, err := embedded[0].TbsCertificate.Extensions.AuthorityKeyIdentifier()
	if err != nil || aki == nil {
		t.Fatalf("DSC authority key identifier: %v", err)
	}

	trusted, err := trustedCSCACerts()
	if err != nil {
		t.Fatal(err)
	}
	pool := &cms.GenericCertPool{}
	removed := 0
	for _, c := range trusted.ByIssuerCountry("AT") {
		ski, err := c.TbsCertificate.Extensions.SubjectKeyIdentifier()
		if err == nil && ski != nil && bytes.Equal(*ski, aki.KeyIdentifier) {
			removed++
			continue
		}
		pool.AddCerts([]cms.Certificate{c})
	}
	if removed == 0 || pool.Count() == 0 {
		t.Fatalf("fixture no longer exercises the test: removed=%d remaining=%d", removed, pool.Count())
	}

	err = verifyPassportChip(nil, austrianChip(t), "AUT", pool)
	if err == nil || !strings.Contains(err.Error(), "not a trusted CSCA for AT") {
		t.Fatalf("error = %v", err)
	}
}

func TestExtractScanResult_NFCRawData(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	results["documentData"] = `{
		"mrzValues": {"groups": [{"fields": [
			{"fieldKey": "countryCode", "value": "AUT"},
			{"fieldKey": "firstName", "value": "ANNA"}
		]}]},
		"templateInfo": {"templateType": "Passport", "documentCountry": "Austria"},
		"nfcValues": {"rawData": {
			"SOD": "U09E",
			"DG1": "REcx",
			"DG2": 42
		}}
	}`
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	got := result.IDScan.DocumentData.NFCRawData
	if got["SOD"] != "U09E" || got["DG1"] != "REcx" {
		t.Errorf("NFCRawData = %v", got)
	}
	if _, present := got["DG2"]; present {
		t.Errorf("non-string rawData value should be dropped: %v", got)
	}
	if result.IDScan.DocumentData.IssuingCountry != "AUT" {
		t.Errorf("IssuingCountry = %q", result.IDScan.DocumentData.IssuingCountry)
	}
}

func TestExtractScanResult_NFCRawDataAbsent(t *testing.T) {
	p := realPayload()
	results := p["idScanResultsSoFar"].(map[string]any)
	results["documentData"] = `{
		"mrzValues": {"groups": [{"fields": [
			{"fieldKey": "countryCode", "value": "AUT"}
		]}]},
		"templateInfo": {"templateType": "Passport"}
	}`
	result, ok, err := ExtractScanResult(p)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if result.IDScan.DocumentData.NFCRawData != nil {
		t.Errorf("NFCRawData = %v, want nil", result.IDScan.DocumentData.NFCRawData)
	}
}

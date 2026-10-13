package emrtd

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/facetec-api/internal/emrtd/emrtdtest"
)

func claimedFor(c *emrtdtest.Chip) Claimed {
	return Claimed{
		GivenName:      c.GivenName,
		FamilyName:     c.FamilyName,
		DocumentNumber: c.DocumentNumber,
		DateOfBirth:    c.DateOfBirth,
		DateOfExpiry:   c.DateOfExpiry,
		Nationality:    "SWE",
		IssuingCountry: "Sweden",
	}
}

func TestVerify_OK(t *testing.T) {
	st := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	c := emrtdtest.New(emrtdtest.Options{SigningTime: st, ExtraCert: true})
	res := Verify(c.Raw, claimedFor(c))
	require.True(t, res.OK, res.Detail)
	assert.Equal(t, ReasonOK, res.Reason)
	assert.Equal(t, c.DSC, res.DSC)
	assert.Equal(t, [][]byte{c.CSCA}, res.ExtraCerts, "extra certs are carried but never the DSC")
	assert.Equal(t, "SWE", res.IssuingState)
	require.NotNil(t, res.SigningTime)
	assert.True(t, st.Equal(*res.SigningTime))
	assert.Equal(t, []int{1, 2}, res.DataGroups)
	assert.Len(t, res.DSCFingerprint(), 64)
}

func TestVerify_NoSigningTime(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	res := Verify(c.Raw, claimedFor(c))
	require.True(t, res.OK, res.Detail)
	assert.Nil(t, res.SigningTime)
	assert.Empty(t, res.ExtraCerts)
}

func TestVerify_SIDBySKI(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{SIDBySKI: true, ExtraCert: true})
	res := Verify(c.Raw, claimedFor(c))
	require.True(t, res.OK, res.Detail)
	assert.Equal(t, c.DSC, res.DSC)
}

func TestVerify_SoleCertFallbackWhenSIDDoesNotMatch(t *testing.T) {
	// One embedded certificate: a SID that matches nothing still selects it;
	// safe because the key must verify the signature and the PDP must trust it.
	c := emrtdtest.New(emrtdtest.Options{BadSID: true, SoleCert: true})
	res := Verify(c.Raw, claimedFor(c))
	require.True(t, res.OK, res.Detail)
	assert.Equal(t, c.DSC, res.DSC)
}

func TestVerify_SIDMatchesNothingWithTwoCerts(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{BadSID: true})
	res := Verify(c.Raw, claimedFor(c))
	assert.False(t, res.OK)
	assert.Equal(t, ReasonSODSignature, res.Reason)
}

func TestVerify_GermanyD(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{Country: "DE", IssuingState: "D", Nationality: "D"})
	cl := claimedFor(c)
	cl.Nationality, cl.IssuingCountry = "DEU", "D"
	res := Verify(c.Raw, cl)
	require.True(t, res.OK, res.Detail)
	assert.Equal(t, "DEU", res.IssuingState)
}

func TestVerify_NoChipData(t *testing.T) {
	for _, raw := range []map[string]string{nil, {}, {"DG1": "AA=="}} {
		res := Verify(raw, Claimed{})
		assert.False(t, res.OK)
		assert.Equal(t, ReasonNoChipData, res.Reason)
	}
}

func TestVerify_SODMalformed(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	bad := map[string]string{"SOD": "!!!not-base64", "DG1": c.Raw["DG1"]}
	assert.Equal(t, ReasonSODMalformed, Verify(bad, claimedFor(c)).Reason)

	bad["SOD"] = base64.StdEncoding.EncodeToString([]byte("definitely not a SOD"))
	assert.Equal(t, ReasonSODMalformed, Verify(bad, claimedFor(c)).Reason)

	bad["SOD"] = strings.Repeat("A", base64.StdEncoding.EncodedLen(maxDataGroupBytes)+8)
	assert.Equal(t, ReasonSODMalformed, Verify(bad, claimedFor(c)).Reason)
}

func TestVerify_TamperedSODSignature(t *testing.T) {
	for name, o := range map[string]emrtdtest.Options{
		"signed by another key":        {WrongSigner: true},
		"eContent altered post-sign":   {TamperContent: true},
		"two signer infos unsupported": {TwoSigners: true},
	} {
		t.Run(name, func(t *testing.T) {
			c := emrtdtest.New(o)
			res := Verify(c.Raw, claimedFor(c))
			assert.False(t, res.OK)
			assert.Equal(t, ReasonSODSignature, res.Reason)
		})
	}
}

func TestVerify_TamperedSODBytes(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	sod, err := base64.StdEncoding.DecodeString(c.Raw["SOD"])
	require.NoError(t, err)
	// Flip a bit inside the signature (last bytes of the structure).
	sod[len(sod)-3] ^= 0x01
	c.Raw["SOD"] = base64.StdEncoding.EncodeToString(sod)
	res := Verify(c.Raw, claimedFor(c))
	assert.False(t, res.OK)
	assert.Contains(t, []string{ReasonSODSignature, ReasonSODMalformed}, res.Reason)
}

func TestVerify_TamperedDataGroup(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	dg2, _ := base64.StdEncoding.DecodeString(c.Raw["DG2"])
	dg2[len(dg2)-1] ^= 0xff
	c.Raw["DG2"] = base64.StdEncoding.EncodeToString(dg2)
	res := Verify(c.Raw, claimedFor(c))
	assert.False(t, res.OK)
	assert.Equal(t, ReasonDGHashMismatch, res.Reason)
}

func TestVerify_DataGroupNotInSOD(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	c.Raw["DG3"] = base64.StdEncoding.EncodeToString([]byte("injected"))
	res := Verify(c.Raw, claimedFor(c))
	assert.False(t, res.OK)
	assert.Equal(t, ReasonDGNotInSOD, res.Reason)
}

func TestVerify_DataGroupMalformed(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	c.Raw["DG2"] = "%%%"
	assert.Equal(t, ReasonDGMalformed, Verify(c.Raw, claimedFor(c)).Reason)
}

func TestVerify_NoDataGroupsPresented(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	res := Verify(map[string]string{"SOD": c.Raw["SOD"], "EFCOM": "AA=="}, claimedFor(c))
	assert.Equal(t, ReasonDG1Missing, res.Reason)
}

func TestVerify_DG1Missing(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{OmitDG1: true})
	res := Verify(c.Raw, claimedFor(c))
	assert.False(t, res.OK)
	assert.Equal(t, ReasonDG1Missing, res.Reason)
}

func TestVerify_DG1Unparsable(t *testing.T) {
	// A DG1 that is covered by the SOD (hash ok) but is not a valid MRZ.
	c := emrtdtest.New(emrtdtest.Options{MalformedDG1: true})
	res := Verify(c.Raw, claimedFor(c))
	assert.False(t, res.OK)
	assert.Equal(t, ReasonDGMalformed, res.Reason)
	assert.Equal(t, "DG1 is not a valid MRZ", res.Detail, "parser errors may embed MRZ data")
}

func TestVerify_UnknownIssuingState(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{IssuingState: "XXX"})
	res := Verify(c.Raw, claimedFor(c))
	assert.False(t, res.OK)
	assert.Equal(t, ReasonUnknownIssuer, res.Reason)
}

// An OCR value that differs from the chip no longer fails verification: the
// credential is built from the chip (#83). The difference is reported by field
// name only, for diagnostics.
func TestVerify_OCRMismatchesAreReportedNotFatal(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Claimed)
		field  string // "" when nothing is compared
	}{
		"document number":   {func(c *Claimed) { c.DocumentNumber = "ZZ9999999" }, "document_number"},
		"date of birth":     {func(c *Claimed) { c.DateOfBirth = "1985-03-08" }, "date_of_birth"},
		"date of expiry":    {func(c *Claimed) { c.DateOfExpiry = "2031-10-01" }, "date_of_expiry"},
		"family name":       {func(c *Claimed) { c.FamilyName = "SVENSSON" }, "family_name"},
		"given name":        {func(c *Claimed) { c.GivenName = "KARIN" }, "given_name"},
		"nationality":       {func(c *Claimed) { c.Nationality = "NOR" }, "nationality"},
		"issuing country":   {func(c *Claimed) { c.IssuingCountry = "Norway" }, "issuing_country"},
		"unknown country":   {func(c *Claimed) { c.IssuingCountry = "Atlantis" }, "issuing_country"},
		"malformed date":    {func(c *Claimed) { c.DateOfBirth = "07 MAR 1985" }, "date_of_birth"},
		"bad nationality":   {func(c *Claimed) { c.Nationality = "??" }, "nationality"},
		"sex":               {func(c *Claimed) { c.Sex = "M" }, "sex"},
		"name digit suffix": {func(c *Claimed) { c.FamilyName = c.FamilyName + "123" }, "family_name"},
		"doc number suffix": {func(c *Claimed) { c.DocumentNumber = c.DocumentNumber + "#!" }, "document_number"},
		"doc number comma":  {func(c *Claimed) { c.DocumentNumber = c.DocumentNumber + "," }, "document_number"},
		"doc number space":  {func(c *Claimed) { c.DocumentNumber = c.DocumentNumber + " " }, "document_number"},
		"non-latin given":   {func(c *Claimed) { c.GivenName = "Анна" }, "given_name"},
		// The tester's case: an MRZ '<' filler read as a letter.
		"filler read as K": {func(c *Claimed) { c.FamilyName = c.FamilyName + "K" }, "family_name"},
		"missing doc no":   {func(c *Claimed) { c.DocumentNumber = "" }, ""},
		"missing dob":      {func(c *Claimed) { c.DateOfBirth = "" }, ""},
		"missing expiry":   {func(c *Claimed) { c.DateOfExpiry = "" }, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := emrtdtest.New(emrtdtest.Options{})
			cl := claimedFor(c)
			tc.mutate(&cl)
			res := Verify(c.Raw, cl)
			require.True(t, res.OK, res.Detail)
			if tc.field == "" {
				assert.Empty(t, res.Mismatches)
			} else {
				assert.Equal(t, []string{tc.field}, res.Mismatches)
			}
			// The identity is the chip's, whatever the OCR said.
			assert.Equal(t, c.FamilyName, res.Identity.FamilyName)
			assert.Equal(t, c.GivenName, res.Identity.GivenName)
			assert.Equal(t, c.DocumentNumber, res.Identity.DocumentNumber)
			assert.Equal(t, c.DateOfBirth, res.Identity.DateOfBirth)
		})
	}
}

func TestVerify_IdentityFromDG1(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	res := Verify(c.Raw, claimedFor(c))
	require.True(t, res.OK, res.Detail)
	assert.Equal(t, &Identity{
		FamilyName:     "ERIKSSON",
		GivenName:      "ANNA MARIA",
		DocumentNumber: "AB1234567",
		DateOfBirth:    "1985-03-07",
		DateOfExpiry:   "2031-09-30",
		Nationality:    "SWE",
		IssuingState:   "SWE",
		Sex:            "F",
		DocumentCode:   "P",
	}, res.Identity)
	assert.Empty(t, res.Mismatches)
}

func TestVerify_IdentitySexUnspecified(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{DG1Sex: "<"})
	res := Verify(c.Raw, claimedFor(c))
	require.True(t, res.OK, res.Detail)
	assert.Empty(t, res.Identity.Sex)
}

// DG11 carries the name in full where DG1 may truncate it, and the date of
// birth with its century.
func TestVerify_IdentityRefinedByDG11(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{
		DG11Name:            "ERIKSSON<LINDQVIST<<ANNA<MARIA<SOFIA",
		DG11FullDateOfBirth: "19850307",
	})
	res := Verify(c.Raw, claimedFor(c))
	require.True(t, res.OK, res.Detail)
	assert.Contains(t, res.DataGroups, 11)
	assert.Equal(t, "ERIKSSON LINDQVIST", res.Identity.FamilyName)
	assert.Equal(t, "ANNA MARIA SOFIA", res.Identity.GivenName)
	assert.Equal(t, "1985-03-07", res.Identity.DateOfBirth)
	assert.Equal(t, []string{"name", "date_of_birth"}, res.Identity.FromDG11)
}

func TestVerify_DG11DateOfBirthContradictingDG1IsIgnored(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{DG11FullDateOfBirth: "19850308"})
	res := Verify(c.Raw, claimedFor(c))
	require.True(t, res.OK, res.Detail)
	assert.Equal(t, "1985-03-07", res.Identity.DateOfBirth)
	assert.Empty(t, res.Identity.FromDG11)
}

func TestMRZDateToISO(t *testing.T) {
	now = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = time.Now })
	cases := []struct {
		mrz   string
		birth bool
		want  string
		ok    bool
	}{
		{"850307", true, "1985-03-07", true},
		{"200307", true, "2020-03-07", true},
		{"261014", true, "1926-10-14", true}, // tomorrow in 2026 is the future: previous century
		{"310930", false, "2031-09-30", true},
		{"85<<<<", true, "", false},
		{"850230", true, "", false},
		{"8503", true, "", false},
	}
	for _, tc := range cases {
		got, ok := mrzDateToISO(tc.mrz, tc.birth)
		assert.Equal(t, tc.ok, ok, tc.mrz)
		assert.Equal(t, tc.want, got, tc.mrz)
	}
}

func TestVerify_OptionalClaimsMayBeAbsent(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	res := Verify(c.Raw, Claimed{DocumentNumber: c.DocumentNumber, DateOfBirth: c.DateOfBirth, DateOfExpiry: c.DateOfExpiry})
	assert.True(t, res.OK, res.Detail)
}

func TestVerify_NameToleratesMRZFiller(t *testing.T) {
	c := emrtdtest.New(emrtdtest.Options{})
	cl := claimedFor(c)
	cl.GivenName = "Anna-Maria"
	cl.FamilyName = "eriksson"
	assert.True(t, Verify(c.Raw, cl).OK)
}

// The real-world AT SOD (gmrtd test data, MIT) must verify with its own
// embedded DSC even though the DSC is long expired: validity is the PDP's call.
func TestVerifySODSignature_RealWorldAT(t *testing.T) {
	b64, err := os.ReadFile("testdata/at_sod.b64")
	require.NoError(t, err)
	res := Verify(map[string]string{"SOD": strings.TrimSpace(string(b64)), "DG1": "AA=="}, Claimed{})
	// DG1 is bogus so verification stops at the data groups, but only AFTER the
	// signature verified: a signature failure would report sod_signature_invalid.
	assert.NotEqual(t, ReasonSODSignature, res.Reason)
	assert.NotEqual(t, ReasonSODMalformed, res.Reason)
}

func TestNormalizeCountry(t *testing.T) {
	for in, want := range map[string]string{"D": "DEU", "swe": "SWE", " NLD ": "NLD"} {
		got, err := NormalizeCountry(in)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	for _, in := range []string{"", "XX", "UTO", "SE", "DEUU"} {
		_, err := NormalizeCountry(in)
		assert.Error(t, err, in)
	}
}

func TestResolveClaimedCountry(t *testing.T) {
	for in, want := range map[string]string{"SE": "SWE", "Sweden": "SWE", "SWE": "SWE", "d": "DEU", "netherlands": "NLD"} {
		got, err := resolveClaimedCountry(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got)
	}
	_, err := resolveClaimedCountry("Narnia")
	assert.Error(t, err)
}

func TestSameMRZDate(t *testing.T) {
	now = func() time.Time { return time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = time.Now })
	assert.True(t, sameMRZDate("850307", "1985-03-07", true))
	assert.False(t, sameMRZDate("850307", "1985-03-08", true))
	assert.False(t, sameMRZDate("85030", "1985-03-07", true))
	assert.False(t, sameMRZDate("850307", "19850307", true))
	assert.False(t, sameMRZDate("850307", "1985/03/07", true))
	// Century: birth dates are never in the future, expiries are 20YY.
	assert.True(t, sameMRZDate("100307", "2010-03-07", true))
	assert.False(t, sameMRZDate("100307", "1910-03-07", true))
	assert.False(t, sameMRZDate("300307", "2030-03-07", true), "future birth resolves to 1930")
	assert.True(t, sameMRZDate("300307", "1930-03-07", true))
	assert.True(t, sameMRZDate("310930", "2031-09-30", false))
	assert.False(t, sameMRZDate("310930", "2131-09-30", false))
	assert.False(t, sameMRZDate("310930", "1931-09-30", false))
	assert.False(t, sameMRZDate("310230", "2031-02-30", false), "impossible expiry date")
	assert.False(t, sameMRZDate("ab0307", "2010-03-07", true))
	assert.False(t, sameMRZDate("100230", "2010-02-30", true), "invalid calendar date")
}

func TestDSCFingerprint_Empty(t *testing.T) {
	assert.Equal(t, "", (&Result{}).DSCFingerprint())
}

func TestVerify_SexMatches(t *testing.T) {
	for _, s := range []string{"F", "f", "FEMALE", ""} {
		c := emrtdtest.New(emrtdtest.Options{})
		cl := claimedFor(c)
		cl.Sex = s
		assert.True(t, Verify(c.Raw, cl).OK, "sex %q", s)
	}
}

func TestNormalizeSex(t *testing.T) {
	assert.Equal(t, "M", normalizeSex(" male "))
	assert.Equal(t, "F", normalizeSex("F"))
	assert.Equal(t, "X", normalizeSex("<"))
	assert.Equal(t, "X", normalizeSex("X"))
}

func TestVerify_DocumentTypeBoundToMRZCode(t *testing.T) {
	cases := []struct {
		code, claimed string
		ok            bool
	}{
		{"P<", "passport", true},
		{"PD", "passport", true},
		{"I<", "passport", false},
		{"P<", "id_card", false},
		{"I<", "id_card", true},
		{"A<", "id_card", true},
		{"C<", "id_card", true},
		{"P<", "dl", false},
		{"I<", "dl", false},
		{"P<", "unknown", false},
		{"P<", "", true},
	}
	for _, tc := range cases {
		c := emrtdtest.New(emrtdtest.Options{DocumentCode: tc.code})
		cl := claimedFor(c)
		cl.DocumentType = tc.claimed
		res := Verify(c.Raw, cl)
		assert.Equal(t, tc.ok, res.OK, "%s vs %s", tc.code, tc.claimed)
		if !tc.ok {
			assert.Equal(t, ReasonDocTypeMismatch, res.Reason)
		}
	}
}

func TestVerify_SigningTimePlausibility(t *testing.T) {
	now = func() time.Time { return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = time.Now })
	cases := map[string]struct {
		st time.Time
		ok bool
	}{
		"issued years ago":   {time.Date(2022, 1, 5, 0, 0, 0, 0, time.UTC), true},
		"just now":           {time.Date(2026, 9, 30, 11, 55, 0, 0, time.UTC), true},
		"future":             {time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), false},
		"after expiry":       {time.Date(2031, 10, 5, 0, 0, 0, 0, time.UTC), false},
		"decades before":     {time.Date(2005, 1, 1, 0, 0, 0, 0, time.UTC), false},
		"just inside window": {time.Date(2020, 10, 10, 0, 0, 0, 0, time.UTC), true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := emrtdtest.New(emrtdtest.Options{SigningTime: tc.st})
			res := Verify(c.Raw, claimedFor(c))
			assert.Equal(t, tc.ok, res.OK, res.Detail)
			if !tc.ok {
				assert.Equal(t, ReasonSigningTime, res.Reason)
			}
		})
	}
}

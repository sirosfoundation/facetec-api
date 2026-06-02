package apiv1

import (
	"testing"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
)

// TestMapDocumentData_NetherlandsPassport covers the canonical case from the
// real-world Netherlands passport sample provided during development.
func TestMapDocumentData_NetherlandsPassport(t *testing.T) {
	doc := facetec.DocumentData{
		GivenName:      "JESSE",
		FamilyName:     "VAN MUIJDEN",
		DateOfBirth:    "1987-02-18",
		Nationality:    "NLD",
		DateOfExpiry:   "2034-05-20",
		DocumentNumber: "NVPRR6HD3",
		IssuingCountry: "NLD",
		Sex:            "M",
		DocumentType:   "passport",
		MRZLine1:       "P<NLDVAN<MUIJDEN<<JESSE<<<<<<<<<<<<<<<<<<<<<",
		MRZLine2:       "NVPRR6HD36NLD8702182M3405204<<<<<<<<<<<<<<<2",
		Portrait:       "base64photodata",
	}

	got := MapDocumentData(doc)

	assertEqual(t, "GivenName", "JESSE", got.GivenName)
	assertEqual(t, "FamilyName", "VAN MUIJDEN", got.FamilyName)
	assertEqual(t, "BirthDate", "18-02-1987", got.BirthDate)
	assertEqual(t, "Nationality", "NL", got.Nationality)
	assertEqual(t, "ExpiryDate", "20-05-2034", got.ExpiryDate)
	assertEqual(t, "DocumentNumber", "NVPRR6HD3", got.DocumentNumber)
	assertEqual(t, "IssuingCountry", "NL", got.IssuingCountry)
	assertInt(t, "Sex", 1, got.Sex)
	assertEqual(t, "Portrait", "base64photodata", got.Portrait)
}

// TestMapDocumentData_Empty verifies that a completely empty DocumentData maps
// to a CredentialClaims with zero/empty values and no panic.
func TestMapDocumentData_Empty(t *testing.T) {
	got := MapDocumentData(facetec.DocumentData{})

	assertEqual(t, "GivenName", "", got.GivenName)
	assertEqual(t, "FamilyName", "", got.FamilyName)
	assertEqual(t, "BirthDate", "", got.BirthDate)
	assertEqual(t, "Nationality", "", got.Nationality)
	assertEqual(t, "ExpiryDate", "", got.ExpiryDate)
	assertEqual(t, "DocumentNumber", "", got.DocumentNumber)
	assertEqual(t, "IssuingCountry", "", got.IssuingCountry)
	assertInt(t, "Sex", 0, got.Sex)
	assertEqual(t, "Portrait", "", got.Portrait)
}

// TestMapDocumentData_MRZFieldsExcluded verifies that MRZ lines are never
// forwarded to the issuer regardless of their content.
func TestMapDocumentData_MRZFieldsExcluded(t *testing.T) {
	doc := facetec.DocumentData{
		MRZLine1: "P<NLDVAN<MUIJDEN<<JESSE<<<<<<<<<<<<<<<<<<<<<",
		MRZLine2: "NVPRR6HD36NLD8702182M3405204<<<<<<<<<<<<<<<2",
		MRZLine3: "extraline",
	}
	got := MapDocumentData(doc)
	// CredentialClaims has no MRZ fields — compile-time guarantee.
	// Verify the claims struct doesn't carry the MRZ data by confirming all
	// credential fields are empty (the MRZ fields simply don't exist in the output).
	assertEqual(t, "DocumentNumber", "", got.DocumentNumber)
	assertEqual(t, "GivenName", "", got.GivenName)
}

// TestMapDocumentData_NoPortrait checks that an absent portrait yields an empty
// field (omitempty keeps it out of JSON output).
func TestMapDocumentData_NoPortrait(t *testing.T) {
	doc := facetec.DocumentData{GivenName: "TEST"}
	got := MapDocumentData(doc)
	assertEqual(t, "Portrait", "", got.Portrait)
}

func TestReformatDateToDDMMYYYY(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"1987-02-18", "18-02-1987"},
		{"2034-05-20", "20-05-2034"},
		{"1990-01-15", "15-01-1990"},
		{"2000-12-31", "31-12-2000"},
		// Already non-ISO formats are returned unchanged.
		{"18 FEB 1987", "18 FEB 1987"},
		{"not-a-date", "not-a-date"},
	}
	for _, tt := range tests {
		got := reformatDateToDDMMYYYY(tt.input)
		if got != tt.want {
			t.Errorf("reformatDateToDDMMYYYY(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMapSexToISO5218(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"M", 1},
		{"m", 1},
		{"MALE", 1},
		{"male", 1},
		{"F", 2},
		{"f", 2},
		{"FEMALE", 2},
		{"female", 2},
		{"X", 0}, // MRZ "X" = unspecified/other → ISO 5218 code 0 (not known)
		{"", 0},
		{"U", 0},
		{"unknown", 0},
	}
	for _, tt := range tests {
		got := mapSexToISO5218(tt.input)
		if got != tt.want {
			t.Errorf("mapSexToISO5218(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestToISO3166Alpha2(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Common European alpha-3 codes.
		{"NLD", "NL"},
		{"DEU", "DE"},
		{"FRA", "FR"},
		{"GBR", "GB"},
		{"BEL", "BE"},
		{"SWE", "SE"},
		{"NOR", "NO"},
		{"ESP", "ES"},
		// Already alpha-2 — passed through uppercased.
		{"NL", "NL"},
		{"de", "DE"},
		{"gb", "GB"},
		// Case-insensitive alpha-3.
		{"nld", "NL"},
		{"Deu", "DE"},
		// Unknown codes returned unchanged (uppercased).
		{"XXX", "XXX"},
		{"", ""},
		// Non-European.
		{"USA", "US"},
		{"AUS", "AU"},
		{"JPN", "JP"},
		{"SAU", "SA"},
		// Human-readable country names (FaceTec templateInfo.documentCountry).
		{"Sweden", "SE"},
		{"Netherlands", "NL"},
		{"Germany", "DE"},
		{"United Kingdom", "GB"},
		{"United States", "US"},
		{"Czech Republic", "CZ"},
	}
	for _, tt := range tests {
		got := toISO3166Alpha2(tt.input)
		if got != tt.want {
			t.Errorf("toISO3166Alpha2(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// helpers

func assertEqual(t *testing.T, field, want, got string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", field, got, want)
	}
}

func assertInt(t *testing.T, field string, want, got int) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %d, want %d", field, got, want)
	}
}

package apiv1

import (
	"strings"
	"time"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
)

// CredentialClaims is the minimised, issuer-ready representation of an identity document.
// Field names and formats follow the credential schema expected by the vc apigw.
// Only the fields required for credential issuance are present; MRZ lines and
// internal FaceTec metadata are excluded by design.
type CredentialClaims struct {
	GivenName      string `json:"given_name"`
	FamilyName     string `json:"family_name"`
	BirthDate      string `json:"birth_date"`        // DD-MM-YYYY
	Nationality    string `json:"nationality"`        // ISO 3166-1 alpha-2
	ExpiryDate     string `json:"expiry_date"`        // DD-MM-YYYY
	DocumentNumber string `json:"document_number"`
	IssuingCountry string `json:"issuing_country"`    // ISO 3166-1 alpha-2
	Sex            int    `json:"sex"`                // ISO 5218: 0=unknown, 1=male, 2=female, 9=not applicable
	Portrait       string `json:"portrait,omitempty"` // base64 face photo from the ID document
}

// MapDocumentData converts a DocumentData (FaceTec internal representation) to the
// minimised CredentialClaims format expected by the vc apigw. Dates are reformatted
// from YYYY-MM-DD to DD-MM-YYYY; country codes are normalised to ISO 3166-1 alpha-2;
// sex is mapped to an ISO 5218 integer.
func MapDocumentData(doc facetec.DocumentData) CredentialClaims {
	return CredentialClaims{
		GivenName:      doc.GivenName,
		FamilyName:     doc.FamilyName,
		BirthDate:      reformatDateToDDMMYYYY(doc.DateOfBirth),
		Nationality:    toISO3166Alpha2(doc.Nationality),
		ExpiryDate:     reformatDateToDDMMYYYY(doc.DateOfExpiry),
		DocumentNumber: doc.DocumentNumber,
		IssuingCountry: toISO3166Alpha2(doc.IssuingCountry),
		Sex:            mapSexToISO5218(doc.Sex),
		Portrait:       doc.Portrait,
	}
}

// reformatDateToDDMMYYYY converts a YYYY-MM-DD date string to DD-MM-YYYY.
// Returns the input unchanged when it cannot be parsed.
func reformatDateToDDMMYYYY(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return s
	}
	return t.Format("02-01-2006")
}

// mapSexToISO5218 maps a sex string to an ISO/IEC 5218 integer code:
// 0 = not known, 1 = male, 2 = female, 9 = not applicable.
// MRZ/document "X" means unspecified/other, which maps to 0 (not known)
// rather than 9 (not applicable).
func mapSexToISO5218(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "M", "MALE":
		return 1
	case "F", "FEMALE":
		return 2
	default:
		return 0
	}
}

// toISO3166Alpha2 converts an ISO 3166-1 alpha-3 country code or a human-readable
// country name (as returned by FaceTec templateInfo.documentCountry) to alpha-2.
// Already-2-letter codes are returned as-is (uppercased). Unknown codes are
// returned unchanged.
func toISO3166Alpha2(code string) string {
	code = strings.TrimSpace(strings.ToUpper(code))
	if len(code) == 2 {
		return code
	}
	if a2, ok := iso3166Alpha3ToAlpha2[code]; ok {
		return a2
	}
	if a2, ok := countryNameToAlpha2[code]; ok {
		return a2
	}
	return code
}

// countryNameToAlpha2 maps uppercased English country names (as used by FaceTec
// templateInfo.documentCountry) to ISO 3166-1 alpha-2 codes.
var countryNameToAlpha2 = map[string]string{
	// Europe
	"AUSTRIA": "AT", "BELGIUM": "BE", "BULGARIA": "BG", "CROATIA": "HR",
	"CYPRUS": "CY", "CZECHIA": "CZ", "CZECH REPUBLIC": "CZ", "DENMARK": "DK",
	"ESTONIA": "EE", "FINLAND": "FI", "FRANCE": "FR", "GERMANY": "DE",
	"GREECE": "GR", "HUNGARY": "HU", "ICELAND": "IS", "IRELAND": "IE",
	"ITALY": "IT", "LATVIA": "LV", "LIECHTENSTEIN": "LI", "LITHUANIA": "LT",
	"LUXEMBOURG": "LU", "MALTA": "MT", "NETHERLANDS": "NL", "NORWAY": "NO",
	"POLAND": "PL", "PORTUGAL": "PT", "ROMANIA": "RO", "SLOVAKIA": "SK",
	"SLOVENIA": "SI", "SPAIN": "ES", "SWEDEN": "SE", "SWITZERLAND": "CH",
	"UKRAINE": "UA", "UNITED KINGDOM": "GB",
	// Americas
	"ARGENTINA": "AR", "BRAZIL": "BR", "CANADA": "CA", "CHILE": "CL",
	"COLOMBIA": "CO", "MEXICO": "MX", "UNITED STATES": "US",
	// Africa
	"EGYPT": "EG", "MOROCCO": "MA", "NIGERIA": "NG", "SOUTH AFRICA": "ZA",
	// Asia-Pacific
	"AUSTRALIA": "AU", "CHINA": "CN", "INDIA": "IN", "INDONESIA": "ID",
	"JAPAN": "JP", "MALAYSIA": "MY", "NEW ZEALAND": "NZ", "PAKISTAN": "PK",
	"PHILIPPINES": "PH", "SINGAPORE": "SG", "SOUTH KOREA": "KR", "THAILAND": "TH",
	"VIETNAM": "VN",
	// Middle East
	"IRAN": "IR", "IRAQ": "IQ", "ISRAEL": "IL", "JORDAN": "JO", "KUWAIT": "KW",
	"LEBANON": "LB", "OMAN": "OM", "QATAR": "QA", "SAUDI ARABIA": "SA",
	"TURKEY": "TR", "UNITED ARAB EMIRATES": "AE",
	// CIS
	"BELARUS": "BY", "KAZAKHSTAN": "KZ", "RUSSIA": "RU",
}

// iso3166Alpha3ToAlpha2 maps ISO 3166-1 alpha-3 codes to alpha-2 for countries
// commonly found on passports and national identity documents.
var iso3166Alpha3ToAlpha2 = map[string]string{
	// Europe
	"AUT": "AT", "BEL": "BE", "BGR": "BG", "CHE": "CH", "CYP": "CY",
	"CZE": "CZ", "DEU": "DE", "DNK": "DK", "ESP": "ES", "EST": "EE",
	"FIN": "FI", "FRA": "FR", "GBR": "GB", "GRC": "GR", "HRV": "HR",
	"HUN": "HU", "IRL": "IE", "ISL": "IS", "ITA": "IT", "LIE": "LI",
	"LTU": "LT", "LUX": "LU", "LVA": "LV", "MLT": "MT", "NLD": "NL",
	"NOR": "NO", "POL": "PL", "PRT": "PT", "ROU": "RO", "SVK": "SK",
	"SVN": "SI", "SWE": "SE", "UKR": "UA",
	// Americas
	"ARG": "AR", "BRA": "BR", "CAN": "CA", "CHL": "CL", "COL": "CO",
	"MEX": "MX", "USA": "US",
	// Africa
	"EGY": "EG", "MAR": "MA", "NGA": "NG", "ZAF": "ZA",
	// Asia-Pacific
	"AUS": "AU", "CHN": "CN", "IDN": "ID", "IND": "IN", "JPN": "JP",
	"KOR": "KR", "MYS": "MY", "NZL": "NZ", "PAK": "PK", "PHL": "PH",
	"SGP": "SG", "THA": "TH", "VNM": "VN",
	// Middle East
	"ARE": "AE", "IRN": "IR", "IRQ": "IQ", "ISR": "IL", "JOR": "JO",
	"KWT": "KW", "LBN": "LB", "OMN": "OM", "QAT": "QA", "SAU": "SA",
	"TUR": "TR",
	// CIS
	"BLR": "BY", "KAZ": "KZ", "RUS": "RU",
}

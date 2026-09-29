package facetec

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso3166"
	"go.uber.org/zap"
)

const (
	// nfcRawSODKey is the documentData.nfcValues.rawData key holding the
	// base64-encoded EF.SOD file.
	nfcRawSODKey = "SOD"

	maxNFCRawFileBytes = 4 * 1024 * 1024 // Maximum NFC raw file size: 4 MiB
)

// VerifyPassportChip performs ICAO 9303 passive authentication on the chip
// files FaceTec returns under documentData.nfcValues.rawData, and checks that
// the document signer chains to a CSCA we trust for the passport's country.
// log may be nil.
//
// nfcRaw maps FaceTec rawData keys ("SOD", "DG1", "DG2", ...) to base64 file
// contents. countryCode is the document's countryCode field (ISO 3166 alpha-2,
// alpha-3, or English country name).
//
// The checks are, in order:
//
//  1. EF.SOD is present and parses as a CMS SignedData over an LDSSecurityObject.
//  2. The Document Signer Certificate (DSC) embedded in the SOD was issued for
//     the passport's country, and that country matches countryCode.
//  3. The SOD signature verifies with the embedded DSC, and the DSC verifies
//     with a CSCA from gmrtd's master lists for that country (gmrtd
//     cms.SignedData.Verify, which calls cms.Certificate.Verify). gmrtd
//     enforces CSCA basicConstraints/keyUsage/pathLen and validity periods
//     evaluated at the SOD signing time.
//  4. DG1 (the MRZ) and DG2 (the portrait) are present, covered by the SOD,
//     and hash to the values it records. ICAO 9303 requires both, and the
//     credential is issued from them. Other rawData keys are ignored.
func VerifyPassportChip(log *zap.Logger, nfcRaw map[string]string, countryCode string) error {
	trusted, err := trustedCSCACerts()
	if err != nil {
		return fmt.Errorf("facetec: CSCA trust store: %w", err)
	}
	return verifyPassportChip(log, nfcRaw, countryCode, trusted)
}

func verifyPassportChip(log *zap.Logger, nfcRaw map[string]string, countryCode string, trusted cms.CertPool) error {
	if log == nil {
		log = zap.NewNop()
	}

	documentCountry, err := countryAlpha2(countryCode)
	if err != nil {
		return fmt.Errorf("facetec: passport countryCode: %w", err)
	}

	sod, err := parseSOD(nfcRaw)
	if err != nil {
		return fmt.Errorf("facetec: passport EF.SOD: %w", err)
	}

	signerCountry, err := sod.CertCountryAlpha2()
	if err != nil {
		return fmt.Errorf("facetec: passport document signer country: %w", err)
	}
	if !strings.EqualFold(signerCountry, documentCountry) {
		return fmt.Errorf("facetec: passport document signer country %s does not match countryCode %s", signerCountry, documentCountry)
	}

	// Restrict candidate CSCAs to the passport's country, as gmrtd's own
	// passiveauth does, so a CSCA from another state can never vouch for it.
	countryPool := &cms.GenericCertPool{}
	countryPool.AddCerts(trusted.ByIssuerCountry(documentCountry))
	if countryPool.Count() < 1 {
		return fmt.Errorf("facetec: no trusted CSCA for %s", documentCountry)
	}

	chain, err := sod.SD.Verify(countryPool)
	if err != nil {
		return fmt.Errorf("facetec: passport signer is not a trusted CSCA for %s: %w", documentCountry, err)
	}
	if len(chain) < 2 {
		// SignedData.Verify always returns DSC followed by the CSCA that signed
		// it; anything shorter means no chain to a trust anchor was built.
		return fmt.Errorf("facetec: passport signer chain is incomplete (%d certificates)", len(chain))
	}

	// DG1 and DG2 are mandatory under ICAO 9303 Part 10.
	// https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf
	if err := verifyDataGroupHashes(sod, nfcRaw); err != nil {
		return fmt.Errorf("facetec: passport data groups: %w", err)
	}

	log.Debug("passport chip passively authenticated",
		zap.String("country", documentCountry),
		zap.String("dsc_sha256", fingerprint(chain[0])),
		zap.String("csca_sha256", fingerprint(chain[len(chain)-1])),
	)
	return nil
}

// parseSOD decodes and parses the EF.SOD entry of nfcRaw.
func parseSOD(nfcRaw map[string]string) (*document.SOD, error) {
	sodB64, ok := nfcRaw[nfcRawSODKey]
	if !ok || strings.TrimSpace(sodB64) == "" {
		return nil, fmt.Errorf("missing from NFC raw data")
	}
	sodBytes, err := decodeNFCRawFile(sodB64)
	if err != nil {
		return nil, err
	}
	sod, err := document.NewSOD(sodBytes)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if sod == nil || sod.SD == nil || sod.LdsSecurityObject == nil {
		return nil, fmt.Errorf("parse: no security object")
	}
	return sod, nil
}

// verifyDataGroupHashes checks DG1 and DG2 against the hashes the SOD records.
// A hash mismatch is reported before a missing file, so a presented but
// altered data group is not hidden by the other one being absent.
func verifyDataGroupHashes(sod *document.SOD, nfcRaw map[string]string) error {
	hasher := cms.DefaultCryptoHasher{}
	hashAlg := sod.LdsSecurityObject.HashAlgorithm.Algorithm

	var missing []string
	for _, dg := range []int{1, 2} {
		b64 := strings.TrimSpace(nfcRaw[fmt.Sprintf("DG%d", dg)])
		if b64 == "" {
			missing = append(missing, fmt.Sprintf("DG%d", dg))
			continue
		}
		data, err := decodeNFCRawFile(b64)
		if err != nil {
			return fmt.Errorf("DG%d: %w", dg, err)
		}
		want := sod.DgHash(dg)
		if len(want) == 0 {
			return fmt.Errorf("DG%d is not covered by the SOD", dg)
		}
		got, err := hasher.CryptoHashByOid(hashAlg, data)
		if err != nil {
			return fmt.Errorf("DG%d: hash: %w", dg, err)
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("DG%d hash does not match the SOD", dg)
		}
	}
	switch len(missing) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("%s is missing", missing[0])
	default:
		return fmt.Errorf("%s are missing", strings.Join(missing, " and "))
	}
}

func decodeNFCRawFile(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, fmt.Errorf("empty")
	}
	if base64.StdEncoding.DecodedLen(len(b64)) > maxNFCRawFileBytes {
		return nil, fmt.Errorf("exceeds maximum size")
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty")
	}
	return data, nil
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func countryAlpha2(code string) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", fmt.Errorf("country code is empty")
	}
	if c := iso3166.ByAlpha2(code); c != nil {
		return c.Alpha2, nil
	}
	if c := iso3166.ByAlpha3(code); c != nil {
		return c.Alpha2, nil
	}
	for i := range iso3166.Countries {
		if strings.EqualFold(iso3166.Countries[i].Name, code) {
			return iso3166.Countries[i].Alpha2, nil
		}
	}
	return "", fmt.Errorf("unknown country code %q", code)
}

var (
	trustedOnce sync.Once
	trustedPool cms.CertPool
	trustedErr  error
)

// trustedCSCACerts returns gmrtd's embedded CSCA master lists (German BSI and
// Dutch NPKD master lists plus Indonesia's 2010-series CSCAs).
func trustedCSCACerts() (cms.CertPool, error) {
	trustedOnce.Do(func() {
		trustedPool, trustedErr = cms.DefaultMasterList()
	})
	return trustedPool, trustedErr
}

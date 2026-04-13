package facetec

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// ProcessRequestRequest matches FaceTec's middleware-friendly request shape.
// The request blob is opaque to this service and is forwarded as-is.
type ProcessRequestRequest struct {
	RequestBlob           string `json:"requestBlob" binding:"required"`
	ExternalDatabaseRefID string `json:"externalDatabaseRefID,omitempty"`
}

// ProcessRequestResponse wraps the upstream FaceTec payload and any
// credential-issuance metadata produced by facetec-api.
type ProcessRequestResponse struct {
	Payload              map[string]any
	TransactionID        string
	CredentialOfferURL   string
	CredentialIssueError string
}

// ExtractScanResult translates a successful FaceTec Server v10 process-request
// response into the internal ScanResult shape used by policy evaluation and
// issuance. It returns ok=false when the payload does not represent a
// successful photo-ID match.
//
// The FaceTec Server v10 response has:
//   - success (bool) at the top level
//   - idScanResultsSoFar.matchLevel (int) for face match confidence
//   - idScanResultsSoFar.mrzStatusEnumInt (int) — 2 = passed
//   - idScanResultsSoFar.nfcAuthenticationStatusEnumInt (int) — 1 = passed
//   - idScanResultsSoFar.barcodeStatusEnumInt (int) — 2 = passed
//   - documentData (object or JSON string) at the top level
func ExtractScanResult(payload map[string]any) (*ScanResult, bool, error) {
	// Top-level success flag.
	success, ok, err := lookupBool(payload["success"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: process-request success: %w", err)
	}
	if !ok || !success {
		return nil, false, nil
	}

	// idScanResultsSoFar contains match and verification details.
	resultsValue, ok := payload["idScanResultsSoFar"]
	if !ok || resultsValue == nil {
		return nil, false, nil
	}
	results, ok := resultsValue.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("facetec: idScanResultsSoFar is %T, want object", resultsValue)
	}

	matchLevel, ok, err := lookupInt(results["matchLevel"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: matchLevel: %w", err)
	}
	if !ok {
		return nil, false, nil
	}

	// documentData lives inside idScanResultsSoFar.
	documentData, ok, err := extractDocumentData(results["documentData"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: documentData: %w", err)
	}
	if !ok {
		return nil, false, nil
	}

	// FaceTec v10 verification status enums:
	//   mrzStatusEnumInt:               2 = passed
	//   nfcAuthenticationStatusEnumInt:  1 = passed
	//   barcodeStatusEnumInt:            2 = passed
	mrzStatus, _, _ := lookupInt(results["mrzStatusEnumInt"])
	nfcAuthStatus, _, _ := lookupInt(results["nfcAuthenticationStatusEnumInt"])
	barcodeStatus, _, _ := lookupInt(results["barcodeStatusEnumInt"])

	return &ScanResult{
		Liveness: LivenessCheckResult{
			Success:       true,
			LivenessScore: 1.0, // liveness is implicit in a successful process-request
		},
		IDScan: IDScanResult{
			Success:         true,
			FaceMatchLevel:  matchLevel,
			DocumentData:    documentData,
			MRZVerified:     mrzStatus == 2,
			NFCVerified:     nfcAuthStatus == 1,
			BarcodeVerified: barcodeStatus == 2,
		},
	}, true, nil
}

func extractDocumentData(value any) (DocumentData, bool, error) {
	switch typed := value.(type) {
	case nil:
		return DocumentData{}, false, nil
	case map[string]any:
		return parseDocumentDataMap(typed)
	case string:
		if typed == "" {
			return DocumentData{}, false, nil
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(typed), &raw); err != nil {
			return DocumentData{}, false, err
		}
		return parseDocumentDataMap(raw)
	default:
		return DocumentData{}, false, fmt.Errorf("unsupported type %T", value)
	}
}

// parseDocumentDataMap inspects a JSON-decoded map and parses it as either the
// FaceTec grouped-fields format (has "mrzValues" or "scannedValues" keys) or a
// flat DocumentData map.
func parseDocumentDataMap(m map[string]any) (DocumentData, bool, error) {
	if _, ok := m["mrzValues"]; ok {
		return parseFaceTecGroupedFields(m)
	}
	if _, ok := m["scannedValues"]; ok {
		return parseFaceTecGroupedFields(m)
	}
	// Flat format (backward compat / testing).
	var docData DocumentData
	if err := remarshalInto(m, &docData); err != nil {
		return DocumentData{}, false, err
	}
	return docData, true, nil
}

// parseFaceTecGroupedFields converts FaceTec's grouped-fields documentData
// into our flat DocumentData struct.
//
// The grouped-fields format looks like:
//
//	{
//	  "mrzValues": { "groups": [{ "fields": [{ "fieldKey": "firstName", "value": "JESSE" }, ...] }] },
//	  "scannedValues": { "groups": [{ "fields": [{ "fieldKey": "firstName", "value": "JESSE" }, ...] }] },
//	  "templateInfo": { "templateType": "Passport", "documentCountry": "Netherlands" }
//	}
//
// Fields are extracted from mrzValues first, then scannedValues as fallback.
func parseFaceTecGroupedFields(m map[string]any) (DocumentData, bool, error) {
	// Collect all field values from groups, preferring mrzValues over scannedValues.
	fields := make(map[string]string)
	for _, section := range []string{"scannedValues", "mrzValues"} {
		sectionVal, ok := m[section]
		if !ok || sectionVal == nil {
			continue
		}
		sectionMap, ok := sectionVal.(map[string]any)
		if !ok {
			continue
		}
		groupsVal, ok := sectionMap["groups"]
		if !ok {
			continue
		}
		groups, ok := groupsVal.([]any)
		if !ok {
			continue
		}
		for _, g := range groups {
			groupMap, ok := g.(map[string]any)
			if !ok {
				continue
			}
			fieldsVal, ok := groupMap["fields"]
			if !ok {
				continue
			}
			fieldList, ok := fieldsVal.([]any)
			if !ok {
				continue
			}
			for _, f := range fieldList {
				fMap, ok := f.(map[string]any)
				if !ok {
					continue
				}
				key, _ := fMap["fieldKey"].(string)
				val, _ := fMap["value"].(string)
				if key != "" && val != "" {
					fields[key] = val
				}
			}
		}
	}

	// templateInfo
	var docType, docCountry string
	if ti, ok := m["templateInfo"].(map[string]any); ok {
		docType, _ = ti["templateType"].(string)
		docCountry, _ = ti["documentCountry"].(string)
	}

	dd := DocumentData{
		GivenName:      fields["firstName"],
		FamilyName:     fields["lastName"],
		DocumentNumber: fields["idNumber"],
		DateOfBirth:    normalizeFaceTecDate(fields["dateOfBirth"]),
		DateOfExpiry:   normalizeFaceTecDate(fields["dateOfExpiration"]),
		Nationality:    fields["nationality"],
		Sex:            normalizeSex(fields["sex"]),
		IssuingCountry: firstNonEmpty(fields["countryCode"], docCountry),
		DocumentType:   normalizeDocumentType(docType),
		MRZLine1:       fields["mrzLine1"],
		MRZLine2:       fields["mrzLine2"],
		MRZLine3:       fields["mrzLine3"],
	}
	return dd, true, nil
}

// normalizeFaceTecDate converts FaceTec date formats to YYYY-MM-DD.
// Known formats: "18 FEB/FEB 1987", "18/02/1987", "1987-02-18", "18 FEB 1987".
func normalizeFaceTecDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Already in YYYY-MM-DD format.
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return s
	}

	// FaceTec dual-language format: "18 FEB/FEB 1987" → take first month.
	if idx := strings.Index(s, "/"); idx > 0 {
		// Find the surrounding space boundaries to isolate the month pair.
		// Pattern: "DD MON1/MON2 YYYY"
		parts := strings.Fields(s)
		for i, p := range parts {
			if strings.Contains(p, "/") {
				parts[i] = p[:strings.Index(p, "/")]
				break
			}
		}
		s = strings.Join(parts, " ")
	}

	// Try "02 Jan 2006" (DD MON YYYY).
	for _, layout := range []string{"02 Jan 2006", "02 January 2006", "2 Jan 2006", "02/01/2006", "01/02/2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Format("2006-01-02")
		}
	}

	// Return as-is if we can't parse it; downstream will see the raw value.
	return s
}

func normalizeSex(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	switch s {
	case "M", "MALE":
		return "M"
	case "F", "FEMALE":
		return "F"
	default:
		return s
	}
}

func normalizeDocumentType(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "passport":
		return "passport"
	case "driver's license", "drivers license", "dl":
		return "dl"
	case "id card", "id_card", "identity card":
		return "id_card"
	default:
		return s
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func remarshalInto(src any, dst any) error {
	buf, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, dst)
}

func lookupBool(value any) (bool, bool, error) {
	switch typed := value.(type) {
	case nil:
		return false, false, nil
	case bool:
		return typed, true, nil
	case string:
		parsed, err := strconv.ParseBool(typed)
		if err != nil {
			return false, false, fmt.Errorf("parse bool %q: %w", typed, err)
		}
		return parsed, true, nil
	default:
		return false, false, fmt.Errorf("unsupported type %T", value)
	}
}

func lookupInt(value any) (int, bool, error) {
	switch typed := value.(type) {
	case nil:
		return 0, false, nil
	case int:
		return typed, true, nil
	case int64:
		return int(typed), true, nil
	case float64:
		if typed != math.Trunc(typed) {
			return 0, false, fmt.Errorf("non-integer float %v", typed)
		}
		return int(typed), true, nil
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false, fmt.Errorf("parse int %q: %w", typed.String(), err)
		}
		return int(parsed), true, nil
	case string:
		parsed, err := strconv.Atoi(typed)
		if err != nil {
			return 0, false, fmt.Errorf("parse int %q: %w", typed, err)
		}
		return parsed, true, nil
	default:
		return 0, false, fmt.Errorf("unsupported type %T", value)
	}
}

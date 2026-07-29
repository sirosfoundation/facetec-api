package facetec

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gmrtd/gmrtd/document"
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
	Payload                map[string]any
	TransactionID          string
	CredentialOfferURL     string
	CredentialIssueError   string
	CredentialIssueErrCode string
}

// photoIDNextStepComplete is the value of idScanResultsSoFar.photoIDNextStepEnumInt
// meaning the FaceTec Server considers the Photo ID Match session complete —
// no further SDK steps (front/back retry, NFC, user confirmation) are expected.
// Other documented values: 0 = FRONT_RETRY, 1 = BACK, 2 = BACK_RETRY,
// 3 = USER_CONFIRM, 5 = NFC.
const photoIDNextStepComplete = 4

// ExtractScanResult translates a successful FaceTec Server v10 process-request
// response into the internal ScanResult shape used by policy evaluation and
// issuance. It returns ok=false when the payload does not yet represent a
// complete photo-ID scan (e.g. an earlier step in the session).
//
// The FaceTec Server v10 response has:
//   - idScanResultsSoFar.photoIDNextStepEnumInt (int) — 4 = COMPLETE; the
//     top-level "success" field does NOT indicate whether the ID scan
//     matched (per FaceTec's docs, "Your Team is responsible for processing
//     the Response Properties and determining how to proceed based on Your
//     Team's Business Requirements" — there is no single pass/fail boolean
//     for a photo-ID match). A fully successful scan can and does report
//     top-level "success": false while every idScanResultsSoFar property
//     indicates a perfect match; gating on it here previously caused
//     legitimate successful scans to be silently dropped.
//   - idScanResultsSoFar.matchLevel (int) for face match confidence
//   - idScanResultsSoFar.mrzStatusEnumInt (int) — 2 = SUCCESS
//   - idScanResultsSoFar.nfcAuthenticationStatusEnumInt (int) — 4 = AUTHENTICATED
//   - idScanResultsSoFar.barcodeStatusEnumInt (int) — 3 = SUCCESS
//   - documentData (object or JSON string) inside idScanResultsSoFar
func ExtractScanResult(payload map[string]any) (*ScanResult, bool, error) {
	// idScanResultsSoFar contains match and verification details. Its absence
	// means this response belongs to an earlier step of the session (e.g. the
	// liveness-only step) that doesn't carry a scan result yet.
	resultsValue, ok := payload["idScanResultsSoFar"]
	if !ok || resultsValue == nil {
		return nil, false, nil
	}
	results, ok := resultsValue.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("facetec: idScanResultsSoFar is %T, want object", resultsValue)
	}

	// photoIDNextStepEnumInt is FaceTec's actual signal for "this result is
	// final and ready to evaluate" — 4 = COMPLETE. Other values (FRONT_RETRY,
	// BACK, BACK_RETRY, USER_CONFIRM, NFC) mean the SDK still has another step
	// to perform, so there's nothing to evaluate yet.
	nextStep, ok, err := lookupInt(results["photoIDNextStepEnumInt"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: photoIDNextStepEnumInt: %w", err)
	}
	if !ok || nextStep != photoIDNextStepComplete {
		return nil, false, nil
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

	// FaceTec v10 verification status enums (per FaceTec's Photo ID Match
	// response-properties reference):
	//   mrzStatusEnumInt:               2 = SUCCESS
	//   nfcAuthenticationStatusEnumInt: 4 = AUTHENTICATED
	//   barcodeStatusEnumInt:           3 = SUCCESS
	mrzStatus, _, _ := lookupInt(results["mrzStatusEnumInt"])
	nfcAuthStatus, _, _ := lookupInt(results["nfcAuthenticationStatusEnumInt"])
	barcodeStatus, _, _ := lookupInt(results["barcodeStatusEnumInt"])

	// documentData.Portrait is normally already populated by
	// parseFaceTecGroupedFields (extracted from the NFC chip's DG2 face
	// image -- see extractPortraitFromDG2). Some FaceTec configurations may
	// additionally return a separate, pre-cropped face photo directly under
	// "photoIDFaceCrop"; prefer that when present, since it's already
	// cropped/normalized, but don't clobber the NFC-derived portrait with an
	// empty string when it's absent (confirmed absent in this deployment's
	// FaceTec Server responses as of 2026-07-29).
	if portrait, ok := lookupString(results["photoIDFaceCrop"]); ok {
		documentData.Portrait = portrait
	} else if portrait, ok := lookupString(payload["photoIDFaceCrop"]); ok {
		documentData.Portrait = portrait
	}

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
			NFCVerified:     nfcAuthStatus == 4,
			BarcodeVerified: barcodeStatus == 3,
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
		Portrait:       extractPortraitFromDG2(m),
	}
	return dd, true, nil
}

// extractPortraitFromDG2 extracts the face image embedded in the NFC chip's
// DG2 (Encoded Identification Features — Face) data group, when present.
//
// FaceTec Server's NFC read surfaces the raw, undecoded chip files under
// documentData.nfcValues.rawData, keyed by data group name (e.g. "DG1",
// "DG2", "SOD"). There is no separate pre-cropped face-photo field in this
// deployment's responses (confirmed by inspecting real scan payloads) — DG2
// is the only source of a portrait image. DG2's value is the base64-encoded
// raw EF.DG2 file (ICAO 9303 BER-TLV, application tag 0x75), which is parsed
// with gmrtd to pull out the embedded JPEG/JP2 image bytes.
//
// Returns "" if nfcValues/rawData/DG2 is absent (e.g. NFC wasn't read, or
// the chip has no DG2) or fails to parse.
func extractPortraitFromDG2(documentData map[string]any) string {
	nfcValues, ok := documentData["nfcValues"].(map[string]any)
	if !ok {
		return ""
	}
	rawData, ok := nfcValues["rawData"].(map[string]any)
	if !ok {
		return ""
	}
	dg2B64, ok := rawData["DG2"].(string)
	if !ok || dg2B64 == "" {
		return ""
	}
	dg2Bytes, err := base64.StdEncoding.DecodeString(dg2B64)
	if err != nil {
		return ""
	}
	dg2, err := document.NewDG2(dg2Bytes)
	if err != nil || len(dg2.Images) == 0 || len(dg2.Images[0].Image) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(dg2.Images[0].Image)
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

// lookupString returns (value, true) when value is a non-empty string, and
// ("", false) for nil, empty string, or any non-string type.
func lookupString(value any) (string, bool) {
	s, ok := value.(string)
	return s, ok && s != ""
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

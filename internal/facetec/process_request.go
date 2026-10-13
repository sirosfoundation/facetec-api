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
//   - idScanResultsSoFar.nfcStatusEnumInt (int) — why the chip was or was not read (see NFCStatus*)
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
	nextStep, ok, err := lookupEnumInt(results["photoIDNextStepEnumInt"])
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

	// matchLevelNFCToFaceMap compares the live FaceMap with the photo on the
	// document's chip (matchLevel compares it with the printed photo). Absent
	// is kept apart from 0; a present value of the wrong type is an error
	// (fail closed).
	var chipFaceMatchLevel *int
	if level, present, err := lookupInt(results["matchLevelNFCToFaceMap"]); err != nil {
		return nil, false, fmt.Errorf("facetec: matchLevelNFCToFaceMap: %w", err)
	} else if present {
		chipFaceMatchLevel = &level
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
	//
	// A present-but-wrongly-typed value is an error (fail closed): silently
	// reading it as 0 would turn e.g. a FAILED (3) chip authentication into
	// "not applicable".
	mrzStatus, _, err := lookupEnumInt(results["mrzStatusEnumInt"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: mrzStatusEnumInt: %w", err)
	}
	nfcAuthStatus, _, err := lookupEnumInt(results["nfcAuthenticationStatusEnumInt"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: nfcAuthenticationStatusEnumInt: %w", err)
	}
	// Only 0-5 are defined; an unknown (possibly new failure) state must not
	// slip past the hard chip-auth gate as "neither verified nor failed".
	if nfcAuthStatus < 0 || nfcAuthStatus > 5 {
		return nil, false, fmt.Errorf("facetec: nfcAuthenticationStatusEnumInt: unknown value %d", nfcAuthStatus)
	}
	barcodeStatus, _, err := lookupEnumInt(results["barcodeStatusEnumInt"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: barcodeStatusEnumInt: %w", err)
	}

	// nfcStatusEnumInt only selects which rejection a scan without an
	// authenticated chip gets (the issuance gate itself is NFCVerified), but
	// a value that is present and unreadable is still an error rather than
	// silently becoming "unknown".
	nfcStatus, ok, err := lookupEnumInt(results["nfcStatusEnumInt"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: nfcStatusEnumInt: %w", err)
	}
	if !ok {
		nfcStatus = NFCStatusUnknown
	}

	// documentData.Portrait is normally already populated by
	// parseFaceTecGroupedFields (extracted from the NFC chip's DG2 face
	// image -- see extractPortraitFromDG2). Some FaceTec configurations may
	// additionally return a separate, pre-cropped face photo directly under
	// "photoIDFaceCrop"; prefer that when present, since it's already
	// cropped/normalized, but don't clobber the NFC-derived portrait with an
	// empty string when it's absent (confirmed absent in this deployment's
	// FaceTec Server responses as of 2026-07-29).
	chipPortrait := extractPortraitFromDG2(documentDataMap(results["documentData"]))
	if portrait, ok := lookupString(results["photoIDFaceCrop"]); ok {
		documentData.Portrait = portrait
	} else if portrait, ok := lookupString(payload["photoIDFaceCrop"]); ok {
		documentData.Portrait = portrait
	}

	// Liveness is deliberately left unset (not proven). The response that
	// completes the photo ID match does not say whether liveness was proven:
	// FaceTec Server reports that in result.livenessProven on the session's
	// liveness step, an earlier request (see LivenessProven). The caller
	// fills Liveness in from that verdict.
	return &ScanResult{
		IDScan: IDScanResult{
			Success:            true,
			FaceMatchLevel:     matchLevel,
			DocumentData:       documentData,
			MRZVerified:        mrzStatus == 2,
			ChipFaceMatchLevel: chipFaceMatchLevel,
			NFCVerified:        nfcAuthStatus == 4,
			NFCStatus:          nfcStatus,
			BarcodeVerified:    barcodeStatus == 3,
			ChipAuthStatus:     nfcAuthStatus,
			ChipRaw:            extractNFCRawData(results["documentData"]),
			ChipPortrait:       chipPortrait,
		},
	}, true, nil
}

// LivenessProven reads FaceTec Server's liveness verdict, result.livenessProven,
// from a process-request response. ok is false when the response carries no
// verdict, which is the case for every step except the liveness step. A
// verdict that is present but not a boolean reads as not proven (fail closed).
func LivenessProven(payload map[string]any) (proven, ok bool) {
	result, isMap := payload["result"].(map[string]any)
	if !isMap {
		return false, false
	}
	value, present := result["livenessProven"]
	if !present {
		return false, false
	}
	b, isBool := value.(bool)
	return isBool && b, true
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

// extractNFCRawData returns documentData.nfcValues.rawData as a string map
// (base64 values), or nil when absent. Non-string or empty values are kept as
// empty strings, which can only make verification fail, never pass, while
// still counting as chip evidence.
func extractNFCRawData(value any) map[string]string {
	dd := documentDataMap(value)
	nfcRaw, present := dd["nfcValues"]
	if !present {
		return nil
	}
	nfcValues, ok := nfcRaw.(map[string]any)
	if !ok {
		return malformedRawData
	}
	rawAny, present := nfcValues["rawData"]
	if !present {
		return nil
	}
	rawData, ok := rawAny.(map[string]any)
	if !ok {
		return malformedRawData
	}
	if len(rawData) == 0 {
		return nil
	}
	out := make(map[string]string, len(rawData))
	for k, v := range rawData {
		// Keep the key even when the value is unusable: its presence is
		// evidence that a chip was read, and verification then fails closed.
		s, _ := v.(string)
		out[k] = s
	}
	return out
}

// malformedRawData stands in for chip data whose container has the wrong
// JSON type: non-empty, so it counts as chip evidence, but without a SOD, so
// it can never verify.
var malformedRawData = map[string]string{"rawData": ""}

// documentDataMap returns documentData as a map from either its object or
// JSON-string form, or nil.
func documentDataMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case string:
		var dd map[string]any
		if err := json.Unmarshal([]byte(typed), &dd); err != nil {
			return nil
		}
		return dd
	default:
		return nil
	}
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

	for _, candidate := range faceTecDateCandidates(s) {
		for _, layout := range dateLayouts {
			if t, err := time.Parse(layout, candidate); err == nil {
				return t.Format("2006-01-02")
			}
		}
	}

	// Return as-is if we can't parse it; downstream will see the raw value.
	// MapPhotoIDClaims then leaves the claim out entirely, so the caller logs
	// a warning naming the field — see apiv1.logUnparseableDates.
	return s
}

// dateLayouts are the shapes FaceTec's OCR has been seen to report a date in,
// beyond plain YYYY-MM-DD. "02/01/2006" (DD/MM) is tried before "01/02/2006"
// (MM/DD) because the documents this service reads are overwhelmingly European;
// a date that fits both is read as DD/MM.
var dateLayouts = []string{
	"02 Jan 2006",
	"02 January 2006",
	"2 Jan 2006",
	"2 January 2006",
	"Jan 02, 2006",
	"January 02, 2006",
	"Jan 2, 2006",
	"02.01.2006",
	"2.1.2006",
	"2006/01/02",
	"02/01/2006",
	"01/02/2006",
}

// faceTecDateCandidates expands a raw FaceTec date into the strings worth
// trying to parse, most likely first.
//
// Passports print the month in the issuing state's language and in English,
// and FaceTec reports the pair as it is printed: "10 MRT/MAR 1965" on a Dutch
// passport, "15 JAN/JAN 1990" on an English-language one (field type
// "dd MMM/MMM yyyy"). Only the English half is parseable by time.Parse, and on
// an English-language document the two halves are identical — which is why
// keeping the *first* half (as this function's predecessor did) looked correct
// for years and silently dropped birth_date for every document in another
// language.
//
// The English half is taken first and the local-language half second, so a
// document that prints them the other way round still parses.
func faceTecDateCandidates(s string) []string {
	idx := strings.Index(s, "/")
	if idx <= 0 {
		return []string{s}
	}

	// Pattern: "DD MON1/MON2 YYYY" — a slash inside one space-separated field.
	// A slash-separated date ("02/01/2006") has no such field and is left alone.
	fields := strings.Fields(s)
	for i, f := range fields {
		slash := strings.Index(f, "/")
		if slash <= 0 || slash == len(f)-1 {
			continue
		}

		second := append(append([]string{}, fields...), nil...)
		second[i] = f[slash+1:]

		first := append(append([]string{}, fields...), nil...)
		first[i] = f[:slash]

		return []string{strings.Join(second, " "), strings.Join(first, " "), s}
	}

	return []string{s}
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

// lookupEnumInt is lookupInt for enum status fields, which FaceTec sends as
// JSON numbers: a string (even a numeric one) is a wrong type and fails closed.
func lookupEnumInt(value any) (int, bool, error) {
	if _, isString := value.(string); isString {
		return 0, false, fmt.Errorf("unsupported type %T", value)
	}
	return lookupInt(value)
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

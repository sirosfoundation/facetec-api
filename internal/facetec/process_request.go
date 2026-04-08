package facetec

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
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

	// documentData lives at the top level.
	documentData, ok, err := extractDocumentData(payload["documentData"])
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
		var docData DocumentData
		if err := remarshalInto(typed, &docData); err != nil {
			return DocumentData{}, false, err
		}
		return docData, true, nil
	case string:
		if typed == "" {
			return DocumentData{}, false, nil
		}
		var docData DocumentData
		if err := json.Unmarshal([]byte(typed), &docData); err != nil {
			return DocumentData{}, false, err
		}
		return docData, true, nil
	default:
		return DocumentData{}, false, fmt.Errorf("unsupported type %T", value)
	}
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

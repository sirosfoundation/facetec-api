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

// ExtractScanResult translates a successful FaceTec process-request response
// into the internal ScanResult shape used by policy evaluation and issuance.
// It returns ok=false when the payload is not a successful photo-ID match.
func ExtractScanResult(payload map[string]any) (*ScanResult, bool, error) {
	resultValue, ok := payload["result"]
	if !ok || resultValue == nil {
		return nil, false, nil
	}

	resultMap, ok := resultValue.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("facetec: process-request result is %T, want object", resultValue)
	}

	success, ok, err := lookupBool(resultMap["success"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: process-request success: %w", err)
	}
	if !ok || !success {
		return nil, false, nil
	}

	faceMatchLevel, ok, err := lookupInt(resultMap["faceMatchLevel"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: process-request faceMatchLevel: %w", err)
	}
	if !ok {
		return nil, false, nil
	}

	documentData, ok, err := extractDocumentData(resultMap["documentData"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: process-request documentData: %w", err)
	}
	if !ok {
		return nil, false, nil
	}

	livenessScore, ok, err := extractLivenessScore(resultMap)
	if err != nil {
		return nil, false, fmt.Errorf("facetec: process-request liveness: %w", err)
	}
	if !ok {
		return nil, false, nil
	}

	nfcVerified, _, err := lookupBool(resultMap["nfcVerified"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: process-request nfcVerified: %w", err)
	}
	barcodeVerified, _, err := lookupBool(resultMap["barcodeVerified"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: process-request barcodeVerified: %w", err)
	}
	mrzVerified, _, err := lookupBool(resultMap["mrzVerified"])
	if err != nil {
		return nil, false, fmt.Errorf("facetec: process-request mrzVerified: %w", err)
	}

	return &ScanResult{
		Liveness: LivenessCheckResult{
			Success:       true,
			LivenessScore: livenessScore,
		},
		IDScan: IDScanResult{
			Success:         true,
			FaceMatchLevel:  faceMatchLevel,
			DocumentData:    documentData,
			NFCVerified:     nfcVerified,
			BarcodeVerified: barcodeVerified,
			MRZVerified:     mrzVerified,
		},
	}, true, nil
}

func extractLivenessScore(resultMap map[string]any) (float64, bool, error) {
	if score, ok, err := lookupFloat(resultMap["livenessScore"]); err != nil || ok {
		return score, ok, err
	}

	proven, ok, err := lookupBool(resultMap["livenessProven"])
	if err != nil {
		return 0, false, err
	}
	if !ok || !proven {
		return 0, false, nil
	}
	return 1.0, true, nil
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

func lookupFloat(value any) (float64, bool, error) {
	switch typed := value.(type) {
	case nil:
		return 0, false, nil
	case float64:
		return typed, true, nil
	case float32:
		return float64(typed), true, nil
	case int:
		return float64(typed), true, nil
	case int64:
		return float64(typed), true, nil
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false, fmt.Errorf("parse float %q: %w", typed.String(), err)
		}
		return parsed, true, nil
	case string:
		parsed, err := strconv.ParseFloat(typed, 64)
		if err != nil {
			return 0, false, fmt.Errorf("parse float %q: %w", typed, err)
		}
		return parsed, true, nil
	default:
		return 0, false, fmt.Errorf("unsupported type %T", value)
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

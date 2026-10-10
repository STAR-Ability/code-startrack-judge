package imports

import "github.com/STAR-Ability/code-startrack-judge/internal/contract"

var publicMessages = map[string]string{
	"PACKAGE_INVALID":           "Package structure is invalid",
	"PACKAGE_UNSUPPORTED":       "Package format is unsupported",
	"PACKAGE_LICENSE_MISSING":   "Package rights require ADMIN review",
	"PACKAGE_VALIDATION_FAILED": "Package technical validation failed",
	"IMPORT_SOURCE_UNAVAILABLE": "Pinned package source is unavailable",
	"IMPORT_INTERRUPTED":        "Import recovery reservations were exhausted",
}

// PublicDiagnostic never forwards source-controlled diagnostic strings. More
// detailed tool evidence belongs in private retained logs and provenance.
func PublicDiagnostic(code string) (contract.TaskError, bool) {
	message, ok := publicMessages[code]
	return contract.TaskError{Code: code, Message: message, Retryable: false}, ok
}

func NormalizeDiagnostics(items contract.Array[contract.TaskError]) (contract.Array[contract.TaskError], error) {
	if len(items) > 16 {
		return nil, ErrUnavailable
	}
	result := make(contract.Array[contract.TaskError], 0, len(items))
	for _, item := range items {
		safe, ok := PublicDiagnostic(item.Code)
		if !ok {
			return nil, ErrUnavailable
		}
		result = append(result, safe)
	}
	return result, nil
}

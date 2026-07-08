package validator

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	schemas "github.com/sufield/stave/internal/contracts/schema"
	"github.com/sufield/stave/internal/core/kernel"
)

// DefaultMaxValidationErrors is the conservative default for how many schema
// validation errors are shown before truncating.
const DefaultMaxValidationErrors = 3

// maxReportErrors controls how many errors are shown before truncating.
var maxReportErrors = DefaultMaxValidationErrors

// SetMaxValidationErrors overrides the validation error display cap.
// Must be called during process initialization (e.g., bootstrap), not
// concurrently with validation calls.
func SetMaxValidationErrors(n int) {
	if n > 0 {
		maxReportErrors = n
	}
}

// ValidateAssessment marshals the payload and checks it against the output schema.
func ValidateAssessment(payload any) error {
	return validatePayload(string(schemas.KindOutput), kernel.RegistryLayoutStandard, payload)
}

// ValidateAttestation marshals the payload and checks it against the output schema.
func ValidateAttestation(payload any) error {
	return validatePayload(string(schemas.KindOutput), kernel.RegistryLayoutStandard, payload)
}

// ValidateReadiness marshals the payload and checks it against the diagnose schema.
func ValidateReadiness(payload any) error {
	return validatePayload(string(schemas.KindDiagnose), kernel.RegistryLayoutStandard, payload)
}

func validatePayload(kind, version string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal for schema validation: %w", err)
	}
	v := New()
	diags, err := v.Validate(Request{
		Kind:          schemas.Kind(kind),
		ActualVersion: version,
		Data:          raw,
	})
	if err != nil {
		return fmt.Errorf("schema validation: %w", err)
	}
	if len(diags) > 0 {
		return formatReportDiagnostics(diags)
	}
	return nil
}

func formatReportDiagnostics(diags []Diagnostic) error {
	limit := maxReportErrors
	var sb strings.Builder
	sb.Grow(256)

	for i, d := range diags {
		if i >= limit {
			sb.WriteString("; and ")
			sb.WriteString(strconv.Itoa(len(diags) - limit))
			sb.WriteString(" more...")
			break
		}
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString("[")
		sb.WriteString(d.Path)
		sb.WriteString("] ")
		sb.WriteString(d.Message)
	}

	return fmt.Errorf("%w: %s (%d issues)", ErrSchemaValidationFailed, sb.String(), len(diags))
}

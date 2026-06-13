package report

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/kernel"
)

// ValidateAssessment checks an assessment against the output schema.
func ValidateAssessment(payload *Assessment) error {
	return validate(string(schemas.KindOutput), kernel.RegistryLayoutStandard, payload)
}

// ValidateAttestation checks an attestation against the output schema.
func ValidateAttestation(payload *Attestation) error {
	return validate(string(schemas.KindOutput), kernel.RegistryLayoutStandard, payload)
}

// ValidateReadiness checks a readiness report against the diagnose schema.
func ValidateReadiness(payload *Readiness) error {
	return validate(string(schemas.KindDiagnose), kernel.RegistryLayoutStandard, payload)
}

// validate marshals the payload and runs schema validation.
func validate(kind, version string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal for schema validation: %w", err)
	}
	return validateRaw(kind, version, raw)
}

// validateRaw validates pre-serialized JSON bytes against a schema.
func validateRaw(kind, version string, data []byte) error {
	validator := contractvalidator.New()
	diags, err := validator.Validate(contractvalidator.Request{
		Kind:          schemas.Kind(kind),
		ActualVersion: version,
		Data:          data,
	})
	if err != nil {
		return fmt.Errorf("schema validation: %w", err)
	}
	if len(diags) > 0 {
		return formatDiagnostics(diags)
	}
	return nil
}

// DefaultMaxValidationErrors is the conservative default for how many schema
// validation errors are shown before truncating.
const DefaultMaxValidationErrors = 3

// maxValidationErrors controls how many errors are shown before truncating.
// Set via SetMaxValidationErrors at startup. This is a process-level display
// preference, not domain state — acceptable as a package variable since it's
// set once during bootstrap and read during validation.
var maxValidationErrors = DefaultMaxValidationErrors

// SetMaxValidationErrors overrides the validation error display cap.
// Must be called during process initialization (e.g., bootstrap), not
// concurrently with validation calls.
func SetMaxValidationErrors(n int) {
	if n > 0 {
		maxValidationErrors = n
	}
}

func formatDiagnostics(diags []contractvalidator.Diagnostic) error {
	maxReported := maxValidationErrors
	var sb strings.Builder
	sb.Grow(256)

	for i, d := range diags {
		if i >= maxReported {
			sb.WriteString("; and ")
			sb.WriteString(strconv.Itoa(len(diags) - maxReported))
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

	return fmt.Errorf("%w: %s (%d issues)", contractvalidator.ErrSchemaValidationFailed, sb.String(), len(diags))
}

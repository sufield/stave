package safetyenvelope

import (
	"encoding/json"
	"fmt"
	"strings"

	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/kernel"
)

// ValidateEvaluation checks an evaluation envelope against the output schema.
func ValidateEvaluation(payload *Evaluation) error {
	return validate(string(schemas.KindOutput), kernel.RegistryLayoutStandard, payload)
}

// ValidateVerification checks a verification envelope against the output schema.
func ValidateVerification(payload *Verification) error {
	return validate(string(schemas.KindOutput), kernel.RegistryLayoutStandard, payload)
}

// ValidateDiagnose checks a diagnose envelope against the diagnose schema.
func ValidateDiagnose(payload *Diagnose) error {
	return validate(string(schemas.KindDiagnose), kernel.RegistryLayoutStandard, payload)
}

// validate marshals the payload and runs schema validation. Callers wrap
// the returned error with their own context if needed.
func validate(kind, version string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal for schema validation: %w", err)
	}
	return validateRaw(kind, version, raw)
}

// validateRaw validates pre-serialized JSON bytes against a schema.
// Use this when the caller already has the JSON representation.
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

// formatDiagnostics builds a single error from schema validation diagnostics.
// DefaultMaxValidationErrors is the conservative default for how many schema
// validation errors are shown before truncating. Override via SetMaxValidationErrors.
const DefaultMaxValidationErrors = 3

var maxValidationErrors = DefaultMaxValidationErrors

// SetMaxValidationErrors overrides the validation error display cap.
// Values <= 0 are ignored.
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
			fmt.Fprintf(&sb, "; and %d more...", len(diags)-maxReported)
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

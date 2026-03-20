package safetyenvelope

import (
	"encoding/json"
	"fmt"
	"strings"

	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func ValidateEvaluation(payload Evaluation) error {
	return validate(string(schemas.KindOutput), kernel.RegistryLayoutLegacyOutput, payload, "evaluation output")
}

func ValidateVerification(payload Verification) error {
	return validate(string(schemas.KindOutput), kernel.RegistryLayoutLegacyOutput, payload, "verification output")
}

func ValidateDiagnose(payload Diagnose) error {
	return validate(string(schemas.KindDiagnose), kernel.RegistryLayoutStandard, payload, "diagnose output")
}

func validate(kind string, version string, payload any, label string) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", label, err)
	}
	validator := contractvalidator.New()
	diags, err := validator.Validate(contractvalidator.Request{
		Kind:          schemas.Kind(kind),
		ActualVersion: version,
		Data:          raw,
	})
	if err != nil {
		return fmt.Errorf("validate %s schema: %w", label, err)
	}
	if len(diags) > 0 {
		const maxReported = 3
		var msg strings.Builder
		for i, d := range diags {
			if i >= maxReported {
				fmt.Fprintf(&msg, "; and %d more...", len(diags)-maxReported)
				break
			}
			if i > 0 {
				msg.WriteString("; ")
			}
			fmt.Fprintf(&msg, "[%s] %s", d.Path, d.Message)
		}
		return fmt.Errorf("%w: %s (%d issues): %s", contractvalidator.ErrSchemaValidationFailed, label, len(diags), msg.String())
	}
	return nil
}

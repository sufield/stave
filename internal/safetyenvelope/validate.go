package safetyenvelope

import (
	"encoding/json"
	"fmt"

	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/domain/kernel"
)

func ValidateEvaluation(payload Evaluation) error {
	return validate(schemas.KindOutput, kernel.OutputContractSchemaVersion, payload, "evaluation output")
}

func ValidateVerification(payload Verification) error {
	return validate(schemas.KindOutput, kernel.OutputContractSchemaVersion, payload, "verification output")
}

func ValidateDiagnose(payload Diagnose) error {
	return validate(schemas.KindDiagnose, kernel.EmbeddedContractSchemaVersion, payload, "diagnose output")
}

func validate(kind string, version string, payload any, label string) error {
	const payloadIsYAML = false

	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", label, err)
	}
	validator := contractvalidator.New()
	diags, err := validator.Validate(kind, version, raw, payloadIsYAML)
	if err != nil {
		return fmt.Errorf("validate %s schema: %w", label, err)
	}
	if len(diags) > 0 {
		return fmt.Errorf("%s schema validation failed (%d issues): %s: %s", label, len(diags), diags[0].Path, diags[0].Message)
	}
	return nil
}

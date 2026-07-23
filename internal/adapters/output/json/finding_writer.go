// Package json provides JSON-based output functionality for evaluation results.
// It handles formatting and writing of findings and evaluation results as JSON,
// with support for indented output for readability.
package json

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/adapters/output/dto"
	"github.com/sufield/stave/internal/env"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// FindingWriter marshals findings as JSON.
type FindingWriter struct {
	Indent           bool
	ValidateContract bool // When true, validate findings against the contract schema
}

var _ appcontracts.FindingMarshaler = (*FindingWriter)(nil)

// NewFindingWriter creates a new JSON finding marshaler.
// ValidateContract defaults to true so every emitted finding is
// checked against schemas/finding/v1/finding.schema.json before
// the writer returns its bytes. STAVE_DEV_VALIDATE_FINDINGS /
// STAVE_DEBUG remain as historical opt-in toggles but are no
// longer required for validation; callers that need to skip
// validation should construct a FindingWriter literal directly
// with ValidateContract: false.
func NewFindingWriter(indent bool) *FindingWriter {
	return &FindingWriter{
		Indent:           indent,
		ValidateContract: true,
	}
}

// MarshalFindings transforms enriched findings into JSON bytes without performing I/O.
func (w *FindingWriter) MarshalFindings(enriched *appcontracts.EnrichedResult) ([]byte, error) {
	envelope := output.BuildAssessmentFromEnriched(enriched)
	if err := validateEvaluationEnvelope(envelope, w.ValidateContract); err != nil {
		return nil, err
	}
	resultDTO, dtoErr := dto.FromEvaluation(envelope)
	if dtoErr != nil {
		return nil, fmt.Errorf("project assessment: %w", dtoErr)
	}

	var buf bytes.Buffer
	if err := encodeJSON(&buf, w.Indent, resultDTO); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// validateEvaluationEnvelope performs schema and optional contract validation.
// The validateContract flag is captured at construction time (from env vars)
// so this function remains pure.
//
// A nil output is rejected immediately rather than passed into
// ValidateAssessment which would dereference it. The earlier shape
// would have produced a confusing schema-failure error chain instead
// of the clear "nil envelope" diagnosis.
func validateEvaluationEnvelope(output *report.Assessment, validateContract bool) error {
	if output == nil {
		return errors.New("json: nil evaluation envelope")
	}
	if err := contractvalidator.ValidateAssessment(output); err != nil {
		return fmt.Errorf("failed to validate output schema: %w", err)
	}
	if validateContract {
		if err := validateFindings(contractvalidator.New(), output.Findings); err != nil {
			return fmt.Errorf("failed to validate finding contract: %w", err)
		}
	}
	return nil
}

// encodeJSON marshals the result DTO to JSON.
func encodeJSON(out io.Writer, indent bool, result dto.ResultDTO) error {
	encoder := json.NewEncoder(out)
	if indent {
		encoder.SetIndent("", "  ")
	}

	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to encode findings: %w", err)
	}
	return nil
}

func shouldValidateFindingContract() bool {
	return env.DevValidateFindings.IsTrue() || env.Debug.IsTrue()
}

func validateFindings(v *contractvalidator.Validator, findings []remediation.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	var allErrors error
	for i := range findings {
		f := &findings[i]
		// Validate the wire-format shape (FindingDTO), not the raw
		// internal struct. The DTO converter applies the snake_case
		// JSON tags and field projections that downstream consumers
		// actually see; validating the raw type produces phantom
		// schema diffs (e.g. CamelCase delta entries from
		// policy.DeltaPath which carries no json tags).
		dto := dto.FromFinding(f)
		raw, err := json.Marshal(dto)
		if err != nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("finding[%d]: marshal failed: %w", i, err))
			continue
		}

		diags, err := v.Validate(contractvalidator.Request{
			Kind:          schemas.KindFinding,
			ActualVersion: kernel.RegistryLayoutStandard,
			Data:          raw,
		})
		if err != nil {
			return fmt.Errorf("schema error: %w", err)
		}

		for _, d := range diags {
			allErrors = errors.Join(allErrors, fmt.Errorf("finding[%d] at %s: %s", i, d.Path, d.Message))
		}
	}
	return allErrors
}

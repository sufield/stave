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
	"github.com/sufield/stave/internal/envvar"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// FindingWriter marshals findings as JSON.
type FindingWriter struct {
	Indent           bool
	UseEnvelope      bool // When true, wrap output in {"ok": true, "data": ...}
	ValidateContract bool // When true, validate findings against the contract schema
}

var _ appcontracts.FindingMarshaler = (*FindingWriter)(nil)

// NewFindingWriter creates a new JSON finding marshaler.
// The validation decision (STAVE_DEV_VALIDATE_FINDINGS / STAVE_DEBUG) is
// captured at construction time so MarshalFindings remains pure.
func NewFindingWriter(indent bool) *FindingWriter {
	return &FindingWriter{
		Indent:           indent,
		UseEnvelope:      false,
		ValidateContract: shouldValidateFindingContract(),
	}
}

// NewFindingWriterWithEnvelope creates a marshaler that wraps output in ok/data envelope.
func NewFindingWriterWithEnvelope(indent bool) *FindingWriter {
	return &FindingWriter{
		Indent:           indent,
		UseEnvelope:      true,
		ValidateContract: shouldValidateFindingContract(),
	}
}

// MarshalFindings transforms enriched findings into JSON bytes without performing I/O.
func (w *FindingWriter) MarshalFindings(enriched appcontracts.EnrichedResult) ([]byte, error) {
	envelope := output.BuildSafetyEnvelopeFromEnriched(enriched)
	if err := validateEvaluationEnvelope(envelope, w.ValidateContract); err != nil {
		return nil, err
	}
	resultDTO := dto.FromEvaluation(envelope)

	var buf bytes.Buffer
	if err := encodeJSON(&buf, w.Indent, w.UseEnvelope, resultDTO); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// validateEvaluationEnvelope performs schema and optional contract validation.
// The validateContract flag is captured at construction time (from env vars)
// so this function remains pure.
func validateEvaluationEnvelope(output safetyenvelope.Evaluation, validateContract bool) error {
	if err := safetyenvelope.ValidateEvaluation(output); err != nil {
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
func encodeJSON(out io.Writer, indent bool, useEnvelope bool, result dto.ResultDTO) error {
	encoder := json.NewEncoder(out)
	if indent {
		encoder.SetIndent("", "  ")
	}

	var toEncode any = result
	if useEnvelope {
		toEncode = safetyenvelope.JSONEnvelope[dto.ResultDTO]{OK: true, Data: result}
	}

	if err := encoder.Encode(toEncode); err != nil {
		return fmt.Errorf("failed to encode findings: %w", err)
	}
	return nil
}

func shouldValidateFindingContract() bool {
	return envvar.DevValidateFindings.IsTrue() || envvar.Debug.IsTrue()
}

func validateFindings(v *contractvalidator.Validator, findings []remediation.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	var allErrors error
	for i, f := range findings {
		raw, err := json.Marshal(f)
		if err != nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("finding[%d]: marshal failed: %w", i, err))
			continue
		}

		diags, err := v.Validate(schemas.KindFinding, kernel.EmbeddedContractSchemaVersion, raw, false)
		if err != nil {
			return fmt.Errorf("schema error: %w", err)
		}

		for _, d := range diags {
			allErrors = errors.Join(allErrors, fmt.Errorf("finding[%d] at %s: %s", i, d.Path, d.Message))
		}
	}
	return allErrors
}

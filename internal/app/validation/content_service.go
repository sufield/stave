package validation

import (
	"bytes"

	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/diag"
)

// ContentValidator defines the behavior of a validatable piece of content.
// Each concrete type encapsulates its own validation strategy.
type ContentValidator interface {
	Validate(v *contractvalidator.Validator) (*Report, error)
}

// ExplicitRequest validates content against a named schema kind.
type ExplicitRequest struct {
	Data          []byte
	Kind          schemas.Kind
	SchemaVersion string
	Strict        bool
}

// Validate resolves the schema for the given kind and validates the data against it.
func (r ExplicitRequest) Validate(v *contractvalidator.Validator) (*Report, error) {
	version, err := schemas.ResolveVersion(r.Kind, r.SchemaVersion)
	if err != nil {
		return nil, err
	}
	diags, err := v.Validate(contractvalidator.Request{
		Kind:          r.Kind,
		ActualVersion: version,
		Data:          r.Data,
		IsYAML:        contractvalidator.IsLikelyYAML(r.Data),
	})
	if err != nil {
		return nil, err
	}
	return &Report{
		Diagnostics: contractvalidator.DiagnosticsResult(diags, "Fix input to match selected contract schema", r.Strict),
	}, nil
}

// AutoRequest validates content by auto-detecting its format.
type AutoRequest struct {
	Data []byte
}

// Validate detects the content format and validates accordingly.
func (r AutoRequest) Validate(v *contractvalidator.Validator) (*Report, error) {
	if isLikelyJSONContent(r.Data) {
		return validateObservationContent(v, r.Data)
	}
	return validateControlContent(v, r.Data)
}

// ContentService validates one content payload using a ContentValidator strategy.
type ContentService struct {
	newValidator func() *contractvalidator.Validator
}

// NewContentService constructs a content validation service with an
// injectable validator factory. Callers provide the concrete constructor.
func NewContentService(factory func() *contractvalidator.Validator) *ContentService {
	return &ContentService{
		newValidator: factory,
	}
}

// Validate creates a validator and delegates to the request's validation strategy.
func (s *ContentService) Validate(req ContentValidator) (*Report, error) {
	return req.Validate(s.newValidator())
}

func isLikelyJSONContent(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func validateObservationContent(v *contractvalidator.Validator, data []byte) (*Report, error) {
	issues, err := v.ValidateObservationJSON(data)
	if err != nil {
		return nil, err
	}
	result := &Report{Diagnostics: issues}
	if !issues.HasErrors() && !issues.HasWarnings() {
		result.Summary.SnapshotsLoaded = 1
	}
	return result, nil
}

func validateControlContent(v *contractvalidator.Validator, data []byte) (*Report, error) {
	issues, err := v.ValidateControlYAML(data)
	if err != nil {
		return nil, err
	}
	if issues == nil {
		issues = diag.NewResult()
	}
	result := &Report{Diagnostics: issues}
	if !issues.HasErrors() && !issues.HasWarnings() {
		result.Summary.ControlsLoaded = 1
	}
	return result, nil
}

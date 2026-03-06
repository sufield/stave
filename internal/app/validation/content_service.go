package validation

import (
	"bytes"

	service "github.com/sufield/stave/internal/app/service"
	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/domain/diag"
)

// SchemaValidator defines the schema validation operations needed by content validators.
type SchemaValidator interface {
	Validate(kind, version string, raw []byte, isYAML bool) ([]contractvalidator.Diagnostic, error)
	ValidateObservationJSON(raw []byte, opts ...contractvalidator.Option) (*diag.Result, error)
	ValidateControlYAML(raw []byte, opts ...contractvalidator.Option) (*diag.Result, error)
}

// ContentValidator defines the behavior of a validatable piece of content.
// Each concrete type encapsulates its own validation strategy.
type ContentValidator interface {
	Validate(v SchemaValidator) (*service.ValidationResult, error)
}

// ExplicitRequest validates content against a named schema kind.
type ExplicitRequest struct {
	Data          []byte
	Kind          string
	SchemaVersion string
	Strict        bool
}

// Validate resolves the schema for the given kind and validates the data against it.
func (r ExplicitRequest) Validate(v SchemaValidator) (*service.ValidationResult, error) {
	version, err := schemas.ResolveVersion(r.Kind, r.SchemaVersion)
	if err != nil {
		return nil, err
	}
	diags, err := v.Validate(r.Kind, version, r.Data, contractvalidator.IsLikelyYAML(r.Data))
	if err != nil {
		return nil, err
	}
	return &service.ValidationResult{
		Diagnostics: contractvalidator.DiagnosticsResult(diags, "Fix input to match selected contract schema", r.Strict),
	}, nil
}

// AutoRequest validates content by auto-detecting its format.
type AutoRequest struct {
	Data []byte
}

// Validate detects the content format and validates accordingly.
func (r AutoRequest) Validate(v SchemaValidator) (*service.ValidationResult, error) {
	if isLikelyJSONContent(r.Data) {
		return validateObservationContent(v, r.Data)
	}
	return validateControlContent(v, r.Data)
}

// ContentService validates one content payload using a ContentValidator strategy.
type ContentService struct {
	newValidator func() SchemaValidator
}

// NewContentService constructs a content validation service.
func NewContentService() *ContentService {
	return &ContentService{
		newValidator: func() SchemaValidator { return contractvalidator.New() },
	}
}

// Validate creates a validator and delegates to the request's validation strategy.
func (s *ContentService) Validate(req ContentValidator) (*service.ValidationResult, error) {
	return req.Validate(s.newValidator())
}

func isLikelyJSONContent(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func validateObservationContent(v SchemaValidator, data []byte) (*service.ValidationResult, error) {
	issues, err := v.ValidateObservationJSON(data)
	if err != nil {
		return nil, err
	}
	result := &service.ValidationResult{Diagnostics: issues}
	if !issues.HasErrors() && !issues.HasWarnings() {
		result.Summary.SnapshotsLoaded = 1
	}
	return result, nil
}

func validateControlContent(v SchemaValidator, data []byte) (*service.ValidationResult, error) {
	issues, err := v.ValidateControlYAML(data)
	if err != nil {
		return nil, err
	}
	if issues == nil {
		issues = diag.NewResult()
	}
	result := &service.ValidationResult{Diagnostics: issues}
	if !issues.HasErrors() && !issues.HasWarnings() {
		result.Summary.ControlsLoaded = 1
	}
	return result, nil
}

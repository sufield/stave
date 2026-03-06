package validator

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	schemas "github.com/sufield/stave/internal/contracts/schema"
	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"
	"gopkg.in/yaml.v3"
)

type diagnosticExternalError struct {
	path        string
	description string
	code        string
}

func (e diagnosticExternalError) Field() string       { return e.path }
func (e diagnosticExternalError) Description() string { return e.description }
func (e diagnosticExternalError) Code() string        { return e.code }

type options struct {
	pathPrefix string
}

// Option configures optional behavior for validation and diagnostics.
type Option func(*options)

// WithPrefix sets a path prefix for diagnostic messages.
func WithPrefix(prefix string) Option {
	return func(o *options) { o.pathPrefix = prefix }
}

func resolveOptions(opts []Option) options {
	var o options
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// IsUnknownFieldDiagnostic checks if a diagnostic refers to additional/unknown fields.
func IsUnknownFieldDiagnostic(d Diagnostic) bool {
	return classifyDiagnosticCode(d) == "additional_properties"
}

func classifyDiagnosticCode(d Diagnostic) string {
	if d.Kind != nil {
		switch d.Kind.(type) {
		case *kind.AdditionalProperties:
			return "additional_properties"
		case *kind.Required, *kind.Dependency, *kind.DependentRequired:
			return "required"
		case *kind.Enum, *kind.Const:
			return "enum"
		case *kind.Type:
			return "type"
		}
	}
	return "schema_violation"
}

// DiagnosticsResult converts generic schema diagnostics into canonical diag results.
func DiagnosticsResult(diags []Diagnostic, action string, strict bool, opts ...Option) *diag.Result {
	o := resolveOptions(opts)
	externalErrors := make([]diag.ExternalError, 0, len(diags))
	for _, d := range diags {
		code := classifyDiagnosticCode(d)
		if !strict && code == "additional_properties" {
			continue
		}
		externalErrors = append(externalErrors, diagnosticExternalError{
			path:        d.Path,
			description: d.Message,
			code:        code,
		})
	}

	return diag.NewTranslator(diag.CodeSchemaViolation).
		WithDefaultAction(action).
		WithPathPrefix(o.pathPrefix).
		Translate(externalErrors)
}

func syntaxResult(prefix, action string, err error) *diag.Result {
	result := diag.NewResult()
	if err == nil {
		return result
	}
	result.Add(
		diag.New(diag.CodeSchemaViolation).
			Error().
			Action(action).
			WithSensitive("error", prefix+err.Error()).
			Build(),
	)
	return result
}

func missingRequiredFieldResult(field, action string) *diag.Result {
	result := diag.NewResult()
	result.Add(
		diag.New(diag.CodeSchemaViolation).
			Error().
			Action(action).
			With("path", field).
			With("message", "missing required field").
			Build(),
	)
	return result
}

func unsupportedVersionResult(version string, supported []string, action string) *diag.Result {
	result := diag.NewResult()
	result.Add(
		diag.New(diag.CodeUnsupportedSchemaVersion).
			Error().
			Action(action).
			With("version", version).
			With("supported", strings.Join(supported, ", ")).
			Build(),
	)
	return result
}

func (v *Validator) validateKnownSchemaVersion(
	req SchemaValidationRequest,
) (*diag.Result, error) {
	const strictDiagnostics = true

	actual := strings.TrimSpace(req.ActualVersion)
	accepted := slices.Contains(req.AcceptedVersions, actual)
	if !accepted {
		action := strings.TrimSpace(req.Action)
		if action == "" {
			action = "Use a supported schema version"
		}
		return unsupportedVersionResult(req.ActualVersion, req.AcceptedVersions, action), nil
	}

	diags, err := v.Validate(req.Kind, kernel.EmbeddedContractSchemaVersion, req.Raw, req.IsYAML)
	if err != nil {
		return nil, err
	}
	action := strings.TrimSpace(req.Action)
	if action == "" {
		action = "Fix input to match schema"
	}
	return DiagnosticsResult(diags, action, strictDiagnostics, WithPrefix(req.PathPrefix)), nil
}

// ValidateControlYAML validates control YAML against contract schema.
func (v *Validator) ValidateControlYAML(raw []byte, opts ...Option) (*diag.Result, error) {
	o := resolveOptions(opts)
	var partial struct {
		DSLVersion string `yaml:"dsl_version"`
	}
	if err := yaml.Unmarshal(raw, &partial); err != nil {
		return syntaxResult("invalid YAML: ", "Fix YAML syntax errors", err), nil
	}
	if strings.TrimSpace(partial.DSLVersion) == "" {
		return missingRequiredFieldResult("dsl_version", "Add 'dsl_version' field to control YAML"), nil
	}

	return v.validateKnownSchemaVersion(SchemaValidationRequest{
		Raw:              raw,
		ActualVersion:    partial.DSLVersion,
		AcceptedVersions: []string{string(kernel.SchemaControl)},
		Kind:             schemas.KindControl,
		IsYAML:           true,
		PathPrefix:       o.pathPrefix,
		Action:           "Fix control to match DSL schema",
	})
}

// ValidateObservationJSON validates observation JSON against contract schema.
func (v *Validator) ValidateObservationJSON(raw []byte, opts ...Option) (*diag.Result, error) {
	o := resolveOptions(opts)
	var partial struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &partial); err != nil {
		return syntaxResult("invalid JSON: ", "Fix JSON syntax errors", err), nil
	}
	if strings.TrimSpace(partial.SchemaVersion) == "" {
		return missingRequiredFieldResult("schema_version", "Add 'schema_version' field to observation JSON"), nil
	}

	return v.validateKnownSchemaVersion(SchemaValidationRequest{
		Raw:              raw,
		ActualVersion:    partial.SchemaVersion,
		AcceptedVersions: []string{string(kernel.SchemaObservation)},
		Kind:             schemas.KindObservation,
		IsYAML:           false,
		PathPrefix:       o.pathPrefix,
		Action:           "Fix observation to match schema",
	})
}

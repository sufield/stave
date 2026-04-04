package validator

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	schemas "github.com/sufield/stave/internal/contracts/schema"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
	"gopkg.in/yaml.v3"
)

// DiagnosticCategory identifies specific classes of schema failures.
type DiagnosticCategory string

const (
	CatAdditionalProperties DiagnosticCategory = "additional_properties"
	CatRequired             DiagnosticCategory = "required"
	CatEnum                 DiagnosticCategory = "enum"
	CatType                 DiagnosticCategory = "type"
	CatViolation            DiagnosticCategory = "schema_violation"
)

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

// DiagnosticsResult converts engine-level diagnostics into a domain diag.Result.
func DiagnosticsResult(diags []Diagnostic, action string, strict bool, opts ...Option) *diag.Result {
	o := resolveOptions(opts)

	externalErrors := make([]diag.ExternalError, 0, len(diags))
	for _, d := range diags {
		cat := classify(d)
		if !strict && cat == CatAdditionalProperties {
			continue
		}
		externalErrors = append(externalErrors, schemaError{
			path: d.Path,
			desc: d.Message,
			code: string(cat),
		})
	}

	return diag.NewTranslator(diag.CodeSchemaViolation,
		diag.WithDefaultAction(action),
		diag.WithPathPrefix(o.pathPrefix),
	).Translate(externalErrors)
}

// ValidateControlYAML validates a control document against its contract schema.
func (v *Validator) ValidateControlYAML(raw []byte, opts ...Option) (*diag.Result, error) {
	return v.validateDocument(raw, docConfig{
		Unmarshal:     yaml.Unmarshal,
		FormatName:    "YAML",
		VersionField:  "dsl_version",
		Accepted:      []string{string(kernel.SchemaControl)},
		Kind:          string(schemas.KindControl),
		IsYAML:        true,
		DefaultAction: "Fix control to match DSL schema",
	}, opts...)
}

// ValidateObservationJSON validates an observation against its contract schema.
func (v *Validator) ValidateObservationJSON(raw []byte, opts ...Option) (*diag.Result, error) {
	return v.validateDocument(raw, docConfig{
		Unmarshal:     json.Unmarshal,
		FormatName:    "JSON",
		VersionField:  "schema_version",
		Accepted:      []string{string(kernel.SchemaObservation)},
		Kind:          string(schemas.KindObservation),
		IsYAML:        false,
		DefaultAction: "Fix observation to match schema",
	}, opts...)
}

// --- Internal helpers ---

// docConfig groups the parameters for validateDocument to prevent
// positional mix-ups between the multiple string fields.
type docConfig struct {
	Unmarshal     func([]byte, any) error
	FormatName    string
	VersionField  string
	Accepted      []string
	Kind          string
	IsYAML        bool
	DefaultAction string
}

func (v *Validator) validateDocument(raw []byte, cfg docConfig, opts ...Option) (*diag.Result, error) {
	o := resolveOptions(opts)

	var partial struct {
		Version string `json:"schema_version" yaml:"schema_version"`
		DSL     string `json:"dsl_version" yaml:"dsl_version"`
	}
	if err := cfg.Unmarshal(raw, &partial); err != nil {
		return syntaxErrorResult(cfg.FormatName, err), nil
	}

	actual := partial.Version
	if actual == "" {
		actual = partial.DSL
	}

	if strings.TrimSpace(actual) == "" {
		return missingFieldResult(cfg.VersionField, fmt.Sprintf("Add %q field to %s", cfg.VersionField, cfg.FormatName)), nil
	}

	if !slices.Contains(cfg.Accepted, actual) {
		return unsupportedVersionResult(actual, cfg.Accepted, "Use a supported schema version"), nil
	}

	diags, err := v.Validate(Request{
		Kind:          schemas.Kind(cfg.Kind),
		ActualVersion: kernel.RegistryLayoutStandard,
		Data:          raw,
		IsYAML:        cfg.IsYAML,
	})
	if err != nil {
		return nil, err
	}

	return DiagnosticsResult(diags, cfg.DefaultAction, true, WithPrefix(o.pathPrefix)), nil
}

func classify(d Diagnostic) DiagnosticCategory {
	if d.Kind == nil {
		return CatViolation
	}
	switch d.Kind.(type) {
	case *kind.AdditionalProperties:
		return CatAdditionalProperties
	case *kind.Required, *kind.Dependency, *kind.DependentRequired:
		return CatRequired
	case *kind.Enum, *kind.Const:
		return CatEnum
	case *kind.Type:
		return CatType
	default:
		return CatViolation
	}
}

type schemaError struct {
	path string
	desc string
	code string
}

func (e schemaError) Field() string       { return e.path }
func (e schemaError) Description() string { return e.desc }
func (e schemaError) Code() string        { return e.code }

func syntaxErrorResult(fmtName string, err error) *diag.Result {
	result := diag.NewResult()
	result.Add(
		diag.New(diag.CodeSchemaViolation).
			Error().
			Action(fmt.Sprintf("Fix %s syntax errors", fmtName)).
			WithSensitive("error", fmt.Sprintf("invalid %s: %v", fmtName, err)).
			Build(),
	)
	return result
}

func missingFieldResult(field, action string) *diag.Result {
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

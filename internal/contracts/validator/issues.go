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

// Schema diagnostic category constants.
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

// DiagnosticsResult converts engine-level diagnostics into a domain diag.Assessment.
func DiagnosticsResult(diags []Diagnostic, action string, strict bool, opts ...Option) *diag.Assessment {
	o := resolveOptions(opts)

	externalErrors := make([]diag.RawIssue, 0, len(diags))
	for _, d := range diags {
		if !d.IncludeInResults(strict) {
			continue
		}
		externalErrors = append(externalErrors, schemaError{
			path: d.Path,
			desc: d.Message,
			code: string(d.Category()),
		})
	}

	return diag.NewMapper(diag.RuleSchemaViolation,
		diag.WithDefaultRemediation(action),
		diag.WithPathPrefix(o.pathPrefix),
	).Map(externalErrors)
}

// ValidateControlYAML validates a control document against its contract schema.
func (v *Validator) ValidateControlYAML(raw []byte, opts ...Option) (*diag.Assessment, error) {
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
func (v *Validator) ValidateObservationJSON(raw []byte, opts ...Option) (*diag.Assessment, error) {
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

func (v *Validator) validateDocument(raw []byte, cfg docConfig, opts ...Option) (*diag.Assessment, error) {
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

	// kernel.RegistryLayoutStandard ("v1") names the schema-registry
	// layout version, NOT the document's content version. The two
	// are distinct: the registry currently ships exactly one layout,
	// while documents carry their own dsl_version / schema_version
	// (already validated against cfg.Accepted above). Passing the
	// document's version here would dispatch into a non-existent
	// registry slot ("ctrl.v1" → "no such schema").
	//
	// Earlier audit suggested this was a bug; verified by running
	// the parallel-CEL test suite — substituting `actual` produced
	// "unsupported version 'ctrl.v1' for kind 'control'" failures
	// across every fixture.
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

// Category returns the high-level schema-failure class for this
// diagnostic, derived from the structured jsonschema Kind. Replaces
// the package-level classify free function so callers can ask the
// diagnostic about itself instead of routing through a helper.
func (d Diagnostic) Category() DiagnosticCategory {
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

// IncludeInResults reports whether this diagnostic should fold into
// the converted diag.Assessment given the strict-mode flag. The
// AdditionalProperties category is filtered out of non-strict
// results — operators expect schema validation to ignore "extra
// fields" by default and only flag them when --strict is on.
// Centralises the gate on the diagnostic itself so DiagnosticsResult
// stops branching on (cat == CatAdditionalProperties) at the call
// site.
func (d Diagnostic) IncludeInResults(strict bool) bool {
	if !strict && d.Category() == CatAdditionalProperties {
		return false
	}
	return true
}

// IsUnknownField reports whether the diagnostic represents an
// "unknown / extra field" failure from JSON-Schema validation.
//
// Two cases qualify, and both must be covered:
//
//   - The structured Kind is *kind.AdditionalProperties (preferred,
//     when the validator preserved the typed kind).
//   - The text message contains "additionalProperties" (fallback,
//     when the validator only carried the human-readable
//     description).
//
// Callers — primarily the --allow-unknown-input filter and lint
// strict-mode toggles — branch on this to decide whether an extra
// field is allowed to slip through or must fail the validation.
func (d Diagnostic) IsUnknownField() bool {
	if d.Category() == CatAdditionalProperties {
		return true
	}
	return strings.Contains(d.Message, "additionalProperties")
}

type schemaError struct {
	path string
	desc string
	code string
}

func (e schemaError) Field() string       { return e.path }
func (e schemaError) Description() string { return e.desc }
func (e schemaError) Code() string        { return e.code }

func syntaxErrorResult(fmtName string, err error) *diag.Assessment {
	result := diag.NewAssessment()
	result.Record(
		diag.NewFinding(diag.RuleSchemaViolation).
			Error().
			Remediation(fmt.Sprintf("Fix %s syntax errors", fmtName)).
			SensitiveAttribute("error", fmt.Sprintf("invalid %s: %v", fmtName, err)).
			Build(),
	)
	return result
}

func missingFieldResult(field, action string) *diag.Assessment {
	result := diag.NewAssessment()
	result.Record(
		diag.NewFinding(diag.RuleSchemaViolation).
			Error().
			Remediation(action).
			Attribute("path", field).
			Attribute("message", "missing required field").
			Build(),
	)
	return result
}

func unsupportedVersionResult(version string, supported []string, action string) *diag.Assessment {
	result := diag.NewAssessment()
	result.Record(
		diag.NewFinding(diag.RuleUnsupportedSchemaVersion).
			Error().
			Remediation(action).
			Attribute("version", version).
			Attribute("supported", strings.Join(supported, ", ")).
			Build(),
	)
	return result
}

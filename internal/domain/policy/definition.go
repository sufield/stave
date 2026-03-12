package policy

import (
	"fmt"
	"slices"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// ControlDefinitions is a collection of control rules.
type ControlDefinitions []ControlDefinition

// FindByID retrieves a definition by its unique kernel ID. Returns nil if not found.
func (defs ControlDefinitions) FindByID(id kernel.ControlID) *ControlDefinition {
	for i := range defs {
		if defs[i].ID == id {
			return &defs[i]
		}
	}
	return nil
}

// ControlDefinition represents a security rule loaded from external configuration.
type ControlDefinition struct {
	DSLVersion           string            `yaml:"dsl_version"`
	ID                   kernel.ControlID  `yaml:"id"`
	Name                 string            `yaml:"name"`
	Description          string            `yaml:"description"`
	Severity             Severity          `yaml:"severity,omitempty"`
	Domain               string            `yaml:"domain,omitempty"`
	ScopeTags            []string          `yaml:"scope_tags,omitempty"`
	Compliance           ComplianceMapping `yaml:"compliance,omitempty"`
	Type                 ControlType       `yaml:"type"`
	Params               ControlParams     `yaml:"params"`
	UnsafePredicate      UnsafePredicate   `yaml:"unsafe_predicate"`
	UnsafePredicateAlias string            `yaml:"unsafe_predicate_alias,omitempty"`
	Remediation          *RemediationSpec  `yaml:"remediation,omitempty"`
	Exposure             *Exposure         `yaml:"exposure,omitempty"`

	// Prepared holds pre-calculated values to optimize the evaluation hot path.
	Prepared PreparedParams `yaml:"-" json:"-"`
}

// HasCompliance reports whether the control has a non-empty mapping for the given framework key.
func (ctl *ControlDefinition) HasCompliance(key string) bool {
	return ctl.Compliance.HasFramework(key)
}

// Prepare extracts and validates typed parameters from the raw Params map.
// This must be called exactly once after the control is loaded.
func (ctl *ControlDefinition) Prepare() error {
	// 1. Duration Handling
	if raw := ctl.Params.String("max_unsafe_duration"); raw != "" {
		d, err := kernel.ParseDuration(raw)
		if err != nil {
			// Initialize other params so accessors don't panic, but bubble the error
			ctl.initializePreparedParams()
			ctl.Prepared.Ready = true
			return fmt.Errorf("invalid max_unsafe_duration %q: %w", raw, err)
		}
		ctl.Prepared.MaxUnsafeDuration = d
		ctl.Prepared.HasMaxUnsafeDuration = true
	}

	// 2. Specialized Policy Parsing
	ctl.initializePreparedParams()
	ctl.Prepared.Ready = true
	return nil
}

// initializePreparedParams populates sub-policies from the Params map.
func (ctl *ControlDefinition) initializePreparedParams() {
	ctl.Prepared.Recurrence = ParseRecurrencePolicy(ctl.Params)
	ctl.Prepared.PrefixExposure = PrefixExposureParams{
		AllowedPublicPrefixes: ctl.Params.StringSlice("allowed_public_prefixes"),
		ProtectedPrefixes:     ctl.Params.StringSlice("protected_prefixes"),
	}
}

// --- Accessors (Require Prepare) ---

// RecurrencePolicy returns the parsed recurrence parameters.
func (ctl *ControlDefinition) RecurrencePolicy() RecurrencePolicy {
	ctl.mustBePrepared()
	return ctl.Prepared.Recurrence
}

// MaxUnsafeDuration returns the per-control max_unsafe_duration param.
// Returns 0 if not set (caller should apply CLI default fallback).
func (ctl *ControlDefinition) MaxUnsafeDuration() time.Duration {
	ctl.mustBePrepared()
	return ctl.Prepared.MaxUnsafeDuration
}

// EffectiveMaxUnsafe returns the per-control max_unsafe_duration if explicitly set,
// otherwise returns the provided fallback (typically the CLI --max-unsafe value).
func (ctl *ControlDefinition) EffectiveMaxUnsafe(fallback time.Duration) time.Duration {
	ctl.mustBePrepared()
	if ctl.Prepared.HasMaxUnsafeDuration {
		return ctl.Prepared.MaxUnsafeDuration
	}
	return fallback
}

// ExposurePrefixes returns the typed prefix lists for prefix_exposure controls.
func (ctl *ControlDefinition) ExposurePrefixes() PrefixExposureParams {
	ctl.mustBePrepared()
	return ctl.Prepared.PrefixExposure
}

func (ctl *ControlDefinition) mustBePrepared() {
	if !ctl.Prepared.Ready {
		panic(fmt.Sprintf("logic error: Control %s accessed before calling Prepare()", ctl.ID))
	}
}

// --- Parameter Handling ---

// ControlParams is a property bag for control-specific configuration.
type ControlParams map[string]any

// HasKey returns true if the parameter key exists.
func (p ControlParams) HasKey(key string) bool {
	_, ok := p[key]
	return ok
}

// String returns a string parameter or empty string if not found.
func (p ControlParams) String(key string) string {
	if v, ok := p[key].(string); ok {
		return v
	}
	return ""
}

// Int returns an int parameter or 0 if not found.
func (p ControlParams) Int(key string) int {
	switch v := p[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

// Bool returns a bool parameter or false if not found.
func (p ControlParams) Bool(key string) bool {
	if v, ok := p[key].(bool); ok {
		return v
	}
	return false
}

// StringSlice handles the common case where YAML unmarshals a list into []any.
func (p ControlParams) StringSlice(key string) []string {
	v, ok := p[key]
	if !ok {
		return nil
	}

	switch s := v.(type) {
	case []string:
		return s
	case []any:
		res := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				res = append(res, str)
			}
		}
		return res
	default:
		return nil
	}
}

// --- Domain Models ---

// PreparedParams holds validated, typed parameters extracted once at load time
// from the raw ControlParams map.
type PreparedParams struct {
	Ready                bool
	MaxUnsafeDuration    time.Duration
	HasMaxUnsafeDuration bool
	Recurrence           RecurrencePolicy
	PrefixExposure       PrefixExposureParams
}

// PrefixExposureParams holds the typed prefix lists for prefix_exposure controls.
type PrefixExposureParams struct {
	AllowedPublicPrefixes []string
	ProtectedPrefixes     []string
}

// EvaluatableTypes defines which control types the engine currently supports.
var EvaluatableTypes = []ControlType{
	TypeUnsafeState,
	TypeUnsafeDuration,
	TypeUnsafeRecurrence,
	TypePrefixExposure,
}

// IsEvaluatable reports whether the evaluator can process this control type.
func (ctl *ControlDefinition) IsEvaluatable() bool {
	return slices.Contains(EvaluatableTypes, ctl.Type)
}

// ControlMetadata provides a read-only snapshot of core identity and classification.
type ControlMetadata struct {
	ID          kernel.ControlID
	Name        string
	Description string
	Severity    Severity
	Compliance  ComplianceMapping
	Remediation *RemediationSpec
	Exposure    *Exposure
}

// Metadata returns the control's identity and classification fields
// packaged for Finding construction.
func (ctl *ControlDefinition) Metadata() ControlMetadata {
	return ControlMetadata{
		ID:          ctl.ID,
		Name:        ctl.Name,
		Description: ctl.Description,
		Severity:    ctl.Severity,
		Compliance:  ctl.Compliance,
		Remediation: ctl.Remediation,
		Exposure:    ctl.Exposure,
	}
}

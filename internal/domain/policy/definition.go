package policy

import (
	"fmt"
	"slices"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// ControlDefinitions is a collection of control definitions with query methods.
type ControlDefinitions []ControlDefinition

// FindByID returns the definition matching the given ID, or nil.
func (defs ControlDefinitions) FindByID(id kernel.ControlID) *ControlDefinition {
	for i := range defs {
		if defs[i].ID == id {
			return &defs[i]
		}
	}
	return nil
}

// ControlDefinition represents a control rule loaded from YAML.
type ControlDefinition struct {
	DSLVersion      string            `yaml:"dsl_version"`
	ID              kernel.ControlID  `yaml:"id"`
	Name            string            `yaml:"name"`
	Description     string            `yaml:"description"`
	Severity        Severity          `yaml:"severity,omitempty"`
	Domain          string            `yaml:"domain,omitempty"`
	ScopeTags       []string          `yaml:"scope_tags,omitempty"`
	Compliance      ComplianceMapping `yaml:"compliance,omitempty"`
	Type            ControlType       `yaml:"type"`
	Params          ControlParams     `yaml:"params"`
	UnsafePredicate UnsafePredicate   `yaml:"unsafe_predicate"`
	// UnsafePredicateAlias expands to a built-in semantic predicate during load.
	UnsafePredicateAlias string           `yaml:"unsafe_predicate_alias,omitempty"`
	Remediation          *RemediationSpec `yaml:"remediation,omitempty"`
	Exposure             *Exposure        `yaml:"exposure,omitempty"`
	Prepared             PreparedParams   `yaml:"-" json:"-"`
}

// HasCompliance reports whether the control has a non-empty mapping for the given framework key.
func (ctl *ControlDefinition) HasCompliance(key string) bool {
	return ctl.Compliance != nil && ctl.Compliance[key] != ""
}

// Prepare extracts and validates all typed parameters from the raw Params map.
// It must be called once at load time (by loaders). After Prepare, callers
// can access prepared fields via the accessor methods. Calling accessors
// without Prepare panics.
func (ctl *ControlDefinition) Prepare() error {
	if ctl.Params.HasKey("max_unsafe_duration") {
		raw := ctl.Params.String("max_unsafe_duration")
		if raw != "" {
			d, err := kernel.ParseDuration(raw)
			if err != nil {
				// Mark ready so accessors don't panic, but leave
				// HasMaxUnsafeDuration false — callers fall back to
				// the global threshold. The YAML loader validates
				// durations separately and reports user-facing errors.
				ctl.Prepared.Recurrence = ParseRecurrencePolicy(ctl.Params)
				ctl.Prepared.PrefixExposure = PrefixExposureParams{
					AllowedPublicPrefixes: ctl.Params.StringSlice("allowed_public_prefixes"),
					ProtectedPrefixes:     ctl.Params.StringSlice("protected_prefixes"),
				}
				ctl.Prepared.Ready = true
				return fmt.Errorf("invalid max_unsafe_duration %q: %w", raw, err)
			}
			ctl.Prepared.MaxUnsafeDuration = d
			ctl.Prepared.HasMaxUnsafeDuration = true
		}
	}

	ctl.Prepared.Recurrence = ParseRecurrencePolicy(ctl.Params)

	ctl.Prepared.PrefixExposure = PrefixExposureParams{
		AllowedPublicPrefixes: ctl.Params.StringSlice("allowed_public_prefixes"),
		ProtectedPrefixes:     ctl.Params.StringSlice("protected_prefixes"),
	}

	ctl.Prepared.Ready = true
	return nil
}

// RecurrencePolicy returns the parsed recurrence parameters.
// Prepare() must be called before this method.
func (ctl *ControlDefinition) RecurrencePolicy() RecurrencePolicy {
	ctl.mustBePrepared()
	return ctl.Prepared.Recurrence
}

// MaxUnsafeDuration returns the per-control max_unsafe_duration param.
// Returns 0 if not set (caller should apply CLI default fallback).
// Prepare() must be called before this method.
func (ctl *ControlDefinition) MaxUnsafeDuration() time.Duration {
	ctl.mustBePrepared()
	return ctl.Prepared.MaxUnsafeDuration
}

// EffectiveMaxUnsafe returns the per-control max_unsafe_duration if explicitly set,
// otherwise returns the provided fallback (typically the CLI --max-unsafe value).
// Prepare() must be called before this method.
func (ctl *ControlDefinition) EffectiveMaxUnsafe(fallback time.Duration) time.Duration {
	ctl.mustBePrepared()
	if ctl.Prepared.HasMaxUnsafeDuration {
		return ctl.Prepared.MaxUnsafeDuration
	}
	return fallback
}

// ExposurePrefixes returns the typed prefix lists for prefix_exposure controls.
// Prepare() must be called before this method.
func (ctl *ControlDefinition) ExposurePrefixes() PrefixExposureParams {
	ctl.mustBePrepared()
	return ctl.Prepared.PrefixExposure
}

func (ctl *ControlDefinition) mustBePrepared() {
	if !ctl.Prepared.Ready {
		panic("precondition failed: ControlDefinition.Prepare() must be called before accessing prepared fields")
	}
}

// ControlParams holds configurable parameters for a control definition.
// Uses map for flexibility across different control types.
type ControlParams map[string]any

// String returns a string parameter or empty string if not found.
func (p ControlParams) String(key string) string {
	if v, ok := p[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Int returns an int parameter or 0 if not found.
func (p ControlParams) Int(key string) int {
	if v, ok := p[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return 0
}

// Bool returns a bool parameter or false if not found.
func (p ControlParams) Bool(key string) bool {
	if v, ok := p[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// Duration returns a duration parameter or 0 if not found/invalid.
// Supports formats like "168h", "7d", "24h30m".
func (p ControlParams) Duration(key string) time.Duration {
	if v, ok := p[key]; ok {
		if s, ok := v.(string); ok {
			d, err := kernel.ParseDuration(s)
			if err == nil {
				return d
			}
		}
	}
	return 0
}

// StringSlice returns a string slice parameter or nil if not found.
// Handles both []any (from YAML unmarshalling) and []string.
func (p ControlParams) StringSlice(key string) []string {
	v, ok := p[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return s
	}
	return nil
}

// HasKey returns true if the parameter key exists.
func (p ControlParams) HasKey(key string) bool {
	_, ok := p[key]
	return ok
}

// PreparedParams holds validated, typed parameters extracted once at load time
// from the raw ControlParams map. This avoids repeated type-casting and
// parsing on every evaluation call.
type PreparedParams struct {
	Ready                bool // true after Prepare() completes successfully
	MaxUnsafeDuration    time.Duration
	HasMaxUnsafeDuration bool // distinguishes "not set" from "set to 0h"
	Recurrence           RecurrencePolicy
	PrefixExposure       PrefixExposureParams
}

// PrefixExposureParams holds the typed prefix lists for prefix_exposure controls.
type PrefixExposureParams struct {
	AllowedPublicPrefixes []string
	ProtectedPrefixes     []string
}

// EvaluatableTypes contains control types the evaluator can process.
// Other types are valid but will be skipped during evaluation.
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

// ControlMetadata holds the subset of ControlDefinition fields that are
// transcribed verbatim into a Finding. Extracting them into a value type
// lets the domain own the mapping and keeps the engine from reaching into
// individual fields.
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

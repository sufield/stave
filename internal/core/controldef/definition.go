package controldef

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// AliasResolver resolves a predicate alias name to its expanded UnsafePredicate.
// Returning false means the alias is unknown.
type AliasResolver func(alias string) (UnsafePredicate, bool)

// ControlDefinitions is a collection of control rules.
type ControlDefinitions []ControlDefinition

// FindByID retrieves a definition by its unique kernel ID. Returns nil if not found.
func (d ControlDefinitions) FindByID(id kernel.ControlID) *ControlDefinition {
	for i := range d {
		if d[i].ID == id {
			return &d[i]
		}
	}
	return nil
}

// ControlDefinition represents a security rule loaded from external configuration.
type ControlDefinition struct {
	DSLVersion           string
	ID                   kernel.ControlID
	Name                 string
	Description          string
	Severity             Severity
	Domain               string
	ScopeTags            []string
	Compliance           ComplianceMapping
	Type                 ControlType
	Params               ControlParams
	UnsafePredicate      UnsafePredicate
	UnsafePredicateAlias string
	Remediation          *RemediationSpec
	Exposure             *Exposure

	// Prepared holds pre-calculated values to optimize the evaluation hot path.
	Prepared PreparedParams `json:"-"`
}

// HasCompliance reports whether the control has a non-empty mapping for the given framework key.
func (ctl *ControlDefinition) HasCompliance(key string) bool {
	return ctl.Compliance.Has(key)
}

// Prepare extracts and validates typed parameters from the raw Params map.
// Idempotent — safe to call multiple times.
func (ctl *ControlDefinition) Prepare() error {
	if ctl.Prepared.Ready {
		return nil
	}
	if raw := ctl.Params.paramString("max_unsafe_duration"); raw != "" {
		d, err := kernel.ParseDuration(raw)
		if err != nil {
			ctl.Prepared.Recurrence = ParseRecurrencePolicy(ctl.Params)
			ctl.Prepared.PrefixExposure = preparePrefixExposure(ctl.Params)
			ctl.Prepared.Ready = true
			return fmt.Errorf("invalid max_unsafe_duration %q: %w", raw, err)
		}
		ctl.Prepared.MaxUnsafeDuration = d
		ctl.Prepared.HasMaxUnsafeDuration = true
	}
	ctl.Prepared.Recurrence = ParseRecurrencePolicy(ctl.Params)
	ctl.Prepared.PrefixExposure = preparePrefixExposure(ctl.Params)
	ctl.Prepared.Ready = true
	return nil
}

func preparePrefixExposure(params ControlParams) PrefixExposureParams {
	return PrefixExposureParams{
		AllowedPublicPrefixes: NewPrefixSet(params.paramStringSlice("allowed_public_prefixes")...),
		ProtectedPrefixes:     NewPrefixSet(params.paramStringSlice("protected_prefixes")...),
	}
}

// --- Accessors (Require Prepare) ---

// RecurrencePolicy returns the parsed recurrence parameters.
func (ctl *ControlDefinition) RecurrencePolicy() RecurrencePolicy {
	ctl.ensurePrepared()
	return ctl.Prepared.Recurrence
}

// MaxUnsafeDuration returns the per-control max_unsafe_duration param.
// Returns 0 if not set (caller should apply CLI default fallback).
func (ctl *ControlDefinition) MaxUnsafeDuration() time.Duration {
	ctl.ensurePrepared()
	return ctl.Prepared.MaxUnsafeDuration
}

// EffectiveMaxUnsafeDuration returns the per-control max_unsafe_duration if explicitly set,
// otherwise returns the provided fallback (typically the CLI --max-unsafe value).
func (ctl *ControlDefinition) EffectiveMaxUnsafeDuration(fallback time.Duration) time.Duration {
	ctl.ensurePrepared()
	if ctl.Prepared.HasMaxUnsafeDuration {
		return ctl.Prepared.MaxUnsafeDuration
	}
	return fallback
}

// ExposurePrefixes returns the typed prefix lists for prefix_exposure controls.
func (ctl *ControlDefinition) ExposurePrefixes() PrefixExposureParams {
	ctl.ensurePrepared()
	return ctl.Prepared.PrefixExposure
}

// ensurePrepared lazily calls Prepare() on first access.
// Follows the same pattern as ExceptionConfig.ShouldExcept (exception.go:104-106).
func (ctl *ControlDefinition) ensurePrepared() {
	if ctl.Prepared.Ready {
		return
	}
	_ = ctl.Prepare()
}

// --- Parameter Handling ---

// ControlParams is a property bag for control-specific configuration.
type ControlParams struct{ m map[string]any }

// NewParams wraps a raw map in a ControlParams struct.
func NewParams(m map[string]any) ControlParams { return ControlParams{m: m} }

// Raw returns the underlying map. Returns nil for zero-value ControlParams.
func (p ControlParams) Raw() map[string]any {
	if p.m == nil {
		return nil
	}
	return maps.Clone(p.m)
}

// Get retrieves a value by key. Safe to call on a zero-value ControlParams.
func (p ControlParams) Get(key string) (any, bool) {
	if p.m == nil {
		return nil, false
	}
	v, ok := p.m[key]
	return v, ok
}

// Set stores a value. Must be called on a non-zero ControlParams.
func (p *ControlParams) Set(key string, value any) {
	if p.m == nil {
		p.m = make(map[string]any)
	}
	p.m[key] = value
}

// Len returns the number of parameters.
func (p ControlParams) Len() int { return len(p.m) }

// IsZero reports whether the inner map is nil.
func (p ControlParams) IsZero() bool { return p.m == nil }

// HasKey returns true if the parameter key exists.
func (p ControlParams) HasKey(key string) bool {
	if p.m == nil {
		return false
	}
	_, ok := p.m[key]
	return ok
}

// getParam performs a type assertion on a parameter value.
// Returns the zero value of T if the key is missing or the type does not match.
func getParam[T any](m map[string]any, key string) T {
	var zero T
	if m == nil {
		return zero
	}
	v, ok := m[key].(T)
	if !ok {
		return zero
	}
	return v
}

// paramString returns a string parameter or empty string if not found.
func (p ControlParams) paramString(key string) string {
	return getParam[string](p.m, key)
}

// paramInt returns an int parameter or 0 if not found.
func (p ControlParams) paramInt(key string) int {
	if p.m == nil {
		return 0
	}
	switch v := p.m[key].(type) {
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

// paramStringSlice handles the common case where YAML unmarshals a list into []any.
func (p ControlParams) paramStringSlice(key string) []string {
	if p.m == nil {
		return nil
	}
	v, ok := p.m[key]
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
	AllowedPublicPrefixes PrefixSet
	ProtectedPrefixes     PrefixSet
}

// EvaluatableTypes returns the control types the engine currently supports.
func EvaluatableTypes() []ControlType {
	return []ControlType{
		TypeUnsafeState,
		TypeUnsafeDuration,
		TypeUnsafeRecurrence,
		TypePrefixExposure,
	}
}

// IsEvaluatable reports whether the evaluator can process this control type.
func (ctl *ControlDefinition) IsEvaluatable() bool {
	return slices.Contains(EvaluatableTypes(), ctl.Type)
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

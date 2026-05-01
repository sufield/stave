package controldef

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
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
	Domain               kernel.AssetDomain
	ScopeTags            []kernel.ScopeTag
	ApplicableAssetTypes []kernel.AssetType
	Compliance           ComplianceMapping
	CCMV4                []string
	Type                 ControlType
	Classification       Classification
	Params               ControlParams
	UnsafePredicate      UnsafePredicate
	UnsafePredicateAlias string
	Remediation          *RemediationSpec
	Exposure             *Exposure
	ObservationFields    []string      // property paths for compliance evidence extraction
	Alternatives         []Alternative // mappings to alternative detection tools' checks
	Tests                []ControlTest `yaml:"tests,omitempty" json:"-"`

	// Defect / Infection / Failure carry authored triage prose
	// following Andreas Zeller's Why Programs Fail failure-theory
	// chain. Optional; empty strings render as skipped sections.
	Defect    string
	Infection string
	Failure   string

	// Archetype is the structural defect classification (e.g.
	// "ghost-reference"). Optional; controls without an archetype are
	// excluded from `stave expand` results. See internal/archetype.
	Archetype string

	// Prepared holds pre-calculated values to optimize the evaluation hot path.
	Prepared PreparedParams `json:"-"`
}

// HasCompliance reports whether the control has a non-empty mapping for the given framework key.
func (ctl *ControlDefinition) HasCompliance(key ComplianceFramework) bool {
	return ctl.Compliance.Has(key)
}

// AppliesToAssetType reports whether this control should evaluate against
// the given asset type. Returns true when the control declares no
// applicable types (legacy default — fire on all) or when the asset type
// is in the declared list. Comparison is by exact string equality on the
// underlying type identifier.
func (ctl *ControlDefinition) AppliesToAssetType(assetType kernel.AssetType) bool {
	if len(ctl.ApplicableAssetTypes) == 0 {
		return true
	}
	return slices.Contains(ctl.ApplicableAssetTypes, assetType)
}

// Prepare extracts and validates typed parameters from the raw Params map.
// Idempotent — safe to call multiple times but not concurrently.
// See PreparedParams for concurrency notes.
func (ctl *ControlDefinition) Prepare() error {
	if ctl.Prepared.Ready {
		return nil
	}

	// Non-failable params — always parse.
	ctl.Prepared.Recurrence = ParseRecurrencePolicy(ctl.Params)
	ctl.Prepared.PrefixExposure = preparePrefixExposure(ctl.Params)

	// Failable param — duration parsing.
	if raw := ctl.Params.paramString("max_unsafe_duration"); raw != "" {
		d, err := kernel.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("invalid max_unsafe_duration %q: %w", raw, err)
		}
		ctl.Prepared.MaxUnsafeDuration = d
		ctl.Prepared.HasMaxUnsafeDuration = true
	}

	if raw := ctl.Params.paramString("sla_deadline"); raw != "" {
		d, err := kernel.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("invalid sla_deadline %q: %w", raw, err)
		}
		ctl.Prepared.SLADeadline = d
		ctl.Prepared.HasSLADeadline = true
	}

	// Mark Ready only after all parsing succeeds.
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
	_ = ctl.ensurePrepared() // load-time Prepare() validates; lazy fallback logs.
	return ctl.Prepared.Recurrence
}

// MaxUnsafeDuration returns the per-control max_unsafe_duration param.
// Returns 0 if not set (caller should apply CLI default fallback).
func (ctl *ControlDefinition) MaxUnsafeDuration() time.Duration {
	_ = ctl.ensurePrepared()
	return ctl.Prepared.MaxUnsafeDuration
}

// SLADeadline returns the per-control sla_deadline if set, otherwise 0.
func (ctl *ControlDefinition) SLADeadline() time.Duration {
	_ = ctl.ensurePrepared()
	return ctl.Prepared.SLADeadline
}

// HasSLADeadline reports whether this control has an explicit sla_deadline param.
func (ctl *ControlDefinition) HasSLADeadline() bool {
	_ = ctl.ensurePrepared()
	return ctl.Prepared.HasSLADeadline
}

// EffectiveMaxUnsafeDuration returns the per-control max_unsafe_duration if explicitly set,
// otherwise returns the provided fallback (typically the CLI --max-unsafe value).
func (ctl *ControlDefinition) EffectiveMaxUnsafeDuration(fallback time.Duration) time.Duration {
	_ = ctl.ensurePrepared()
	if ctl.Prepared.HasMaxUnsafeDuration {
		return ctl.Prepared.MaxUnsafeDuration
	}
	return fallback
}

// ExposurePrefixes returns the typed prefix lists for prefix_exposure controls.
func (ctl *ControlDefinition) ExposurePrefixes() PrefixExposureParams {
	_ = ctl.ensurePrepared()
	return ctl.Prepared.PrefixExposure
}

// ensurePrepared lazily calls Prepare() on first access. Returns the
// underlying Prepare error so callers can distinguish "ready" from
// "ready-but-bad-params" — the loader path
// (adapters/controls/{builtin,yaml}/loader.go) calls Prepare() eagerly
// and surfaces parse errors at that time. The accessors above
// intentionally discard the error: by the time they run, Prepare has
// already been validated, and a recurrence of the failure here
// indicates a programming error in the loader. The slog.Warn keeps the
// diagnostic visible without forcing every accessor to return a tuple.
func (ctl *ControlDefinition) ensurePrepared() error {
	if err := ctl.Prepare(); err != nil {
		slog.Warn("control prepare failed", "control", ctl.ID, "error", err)
		return err
	}
	return nil
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

// --- Risk Metadata Accessors ---
// These read from the Params bag, so existing controls without risk metadata
// return safe defaults (0, "", nil, 1.0). New controls opt in by adding params.

// BaseImpact returns the numeric base impact score (0-100).
// Read from params.base_impact. Defaults to 0.
func (d *ControlDefinition) BaseImpact() int {
	v := getParam[float64](d.Params.m, "base_impact")
	return int(v)
}

// AttackStage returns the MITRE ATT&CK-aligned attack stage.
// Read from params.attack_stage. Defaults to "".
// Values: initial_access, credential_access, persistence, exfiltration,
// detection_evasion, resilience.
func (d *ControlDefinition) AttackStage() kernel.AttackStage {
	return kernel.AttackStage(getParam[string](d.Params.m, "attack_stage"))
}

// ChainIDs returns the chain definition IDs this control participates in.
// Read from params.chain_ids. Defaults to nil.
func (d *ControlDefinition) ChainIDs() []kernel.ChainID {
	raw, ok := d.Params.Get("chain_ids")
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		ids := make([]kernel.ChainID, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				ids = append(ids, kernel.ChainID(s))
			}
		}
		return ids
	case []string:
		ids := make([]kernel.ChainID, len(v))
		for i, s := range v {
			ids[i] = kernel.ChainID(s)
		}
		return ids
	default:
		return nil
	}
}

// BlastRadiusType returns the blast radius category (detection, prevention, recovery).
// Read from params.blast_radius.type. Defaults to "".
func (d *ControlDefinition) BlastRadiusType() kernel.BlastRadiusType {
	raw, ok := d.Params.Get("blast_radius")
	if !ok {
		return ""
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	return kernel.BlastRadiusType(getParam[string](m, "type"))
}

// BlastMultiplier returns the blast radius multiplier.
// Read from params.blast_radius.multiplier. Defaults to 1.0.
// Detection controls (e.g., CloudTrail) may have 2.5+ because disabling
// them makes all other violations invisible.
func (d *ControlDefinition) BlastMultiplier() float64 {
	raw, ok := d.Params.Get("blast_radius")
	if !ok {
		return 1.0
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return 1.0
	}
	v := getParam[float64](m, "multiplier")
	if v == 0 {
		return 1.0
	}
	return v
}

// BlastScope returns the scope of the blast radius (account, network, resource).
// Read from params.blast_radius.scope. Defaults to "resource".
// Account scope means disabling this control blinds the entire account.
// Network scope means it affects resources in the same VPC.
// Resource scope means it only affects this specific resource.
func (d *ControlDefinition) BlastScope() kernel.BlastScope {
	raw, ok := d.Params.Get("blast_radius")
	if !ok {
		return kernel.BlastScopeResource
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return kernel.BlastScopeResource
	}
	s := kernel.BlastScope(getParam[string](m, "scope"))
	if s == "" {
		return kernel.BlastScopeResource
	}
	return s
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
		values := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				values = append(values, str)
			}
		}
		return values
	default:
		return nil
	}
}

// --- Domain Models ---

// PreparedParams holds validated, typed parameters extracted once at load time
// from the raw ControlParams map.
//
// Not thread-safe: ControlDefinition is a value type used by-value in
// PredicateEval, slice iteration, and many callers. Embedding sync.Once
// would trigger copylocks across the codebase. Callers must ensure
// Prepare() completes during single-threaded control loading before
// evaluation begins.
type PreparedParams struct {
	Ready                bool
	MaxUnsafeDuration    time.Duration
	HasMaxUnsafeDuration bool
	SLADeadline          time.Duration
	HasSLADeadline       bool
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
	ID             kernel.ControlID
	Name           string
	Description    string
	Severity       Severity
	Compliance     ComplianceMapping
	CCMV4          []string
	Remediation    *RemediationSpec
	Exposure       *Exposure
	Alternatives   []Alternative
	Classification Classification
	ScopeTags      []kernel.ScopeTag
	Defect         string
	Infection      string
	Failure        string
	Archetype      string
}

// Fingerprint computes a stable hash of the control's identity and logic
// fields. Changes when ID, Severity, Type, or UnsafePredicate changes.
// Display-only fields (Name, Description, Remediation) are excluded.
func (ctl *ControlDefinition) Fingerprint(h ports.Digester) kernel.Digest {
	if h == nil {
		return ""
	}
	components := []string{
		string(ctl.ID),
		ctl.Severity.String(),
		ctl.Type.String(),
		fmt.Sprintf("%v", ctl.UnsafePredicate),
	}
	return h.Digest(components, '\n')
}

// Metadata returns the control's identity and classification fields
// packaged for Finding construction.
func (ctl *ControlDefinition) Metadata() ControlMetadata {
	return ControlMetadata{
		ID:             ctl.ID,
		Name:           ctl.Name,
		Description:    ctl.Description,
		Severity:       ctl.Severity,
		Compliance:     ctl.Compliance,
		CCMV4:          ctl.CCMV4,
		Remediation:    ctl.Remediation,
		Exposure:       ctl.Exposure,
		Alternatives:   ctl.Alternatives,
		Classification: ctl.Classification,
		ScopeTags:      ctl.ScopeTags,
		Defect:         ctl.Defect,
		Infection:      ctl.Infection,
		Failure:        ctl.Failure,
		Archetype:      ctl.Archetype,
	}
}

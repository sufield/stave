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
	ObservationFields    []string         // property paths for compliance evidence extraction
	Alternatives         []Alternative    // mappings to alternative detection tools' checks
	MitreAttack          []MitreAttackRef // structured MITRE ATT&CK technique mappings
	ValidatedAgainst     []LabValidation  // vendor lab verification records
	Tests                []ControlTest    `yaml:"tests,omitempty" json:"-"`

	Taxonomy []string

	// Defect / Infection / Failure carry authored triage prose
	// following Andreas Zeller's Why Programs Fail failure-theory
	// chain. Optional; empty strings render as skipped sections.
	Defect    string
	Infection string
	Failure   string

	// Archetype is the structural defect classification (e.g.
	// "ghost-reference"). Optional; controls without an archetype are
	// excluded from `stave expand` results. See internal/archetype.
	Archetype kernel.ArchetypeID

	// Scope names the cardinality of the predicate's reasoning:
	// "atomic" when the predicate evaluates a single asset's
	// properties, "compound" when it reasons across multiple related
	// assets. Orthogonal to [Classification] (which names predicate
	// shape). Compound is Stave-distinctive territory — per-resource
	// framework scanners miss these by construction. Populated by the
	// build-time scope classifier (internal/tools/scope-classifier)
	// when authors don't set it explicitly; explicit value wins. Empty
	// string means "unclassified" for legacy / in-flight controls.
	Scope string

	// CorpusReference cites the real-world attack pattern this
	// control detects. The build-time validator requires it when
	// Scope=="compound". Prefix-schema recommended for grep-ability:
	//   MITRE:T1078.004
	//   incident:capital-one-2019
	//   stratus:aws.persistence.iam-create-admin-user
	//   hackerone:1234567
	//   csa:top-threats-2024:t1
	//   rhino:iam-passrole-to-ec2
	//   triz:<contradiction-id>
	// Optional for atomic controls (typically framework-cited via
	// [Compliance] already).
	CorpusReference string

	// IntentRationale states WHY the control exists — the security
	// invariant it preserves. Distinct from Description (what the
	// control checks). Surfaces verbatim into SIR.ControlFact so an
	// external solver / AI agent has the human-authored context for
	// whether a triggered finding actually matters. Optional; empty
	// rationale renders as the absent JSON field in SIR exports.
	IntentRationale string

	// ForbiddenState is a high-level invariant the control declares
	// the system must never satisfy (e.g. principal=="*" AND
	// network=="public"). Distinct from UnsafePredicate (which
	// triggers a finding on match): ForbiddenState carries the
	// authored invariant verbatim into SIR.ControlFact.ForbiddenState
	// for solver-side invariant checking. Reuses the existing
	// UnsafePredicate shape so authors can express forbidden states
	// with the predicate vocabulary they already know.
	ForbiddenState UnsafePredicate

	// prepared holds pre-calculated values to optimize the evaluation
	// hot path. Only Prepare() (in this package) writes to it; the
	// per-attribute accessors below are the read surface for
	// external callers (HasSLADeadline, MaxUnsafeDuration,
	// HasMaxUnsafeDuration, PrefixExposureParams,
	// EffectiveMaxUnsafeDuration, ExposurePrefixes).
	prepared PreparedParams `json:"-"`
}

// HasCompliance reports whether the control has a non-empty mapping for the given framework key.
func (ctl *ControlDefinition) HasCompliance(key ComplianceFramework) bool {
	return ctl.Compliance.Has(key)
}

// HasComplianceCitations reports whether the catalog has wired any
// framework citation onto the control. Distinct from HasCompliance,
// which checks a specific framework — this asks the broader
// "is this control mapped at all?" question the metadata-quality
// review uses.
func (ctl *ControlDefinition) HasComplianceCitations() bool {
	return ctl != nil && len(ctl.Compliance) > 0
}

// IsActionable reports whether the control's remediation block
// carries a concrete fix action. The metadata-quality check uses
// this to flag controls operators can detect but not act on.
func (ctl *ControlDefinition) IsActionable() bool {
	return ctl != nil && ctl.Remediation != nil && ctl.Remediation.Action != ""
}

// IsTaxonomyMapped reports whether the control declares an
// attack-stage mapping (the kill-chain / MITRE ATT&CK label the
// catalog ships with). Used by the metadata-quality review to flag
// controls that are missing the taxonomy linkage downstream
// reporting depends on.
func (ctl *ControlDefinition) IsTaxonomyMapped() bool {
	return ctl != nil && ctl.AttackStage() != ""
}

// MetadataQuality is the structured outcome of a control-completeness
// review. It groups warnings the authoring guide treats as
// non-blocking but recommended.
type MetadataQuality struct {
	Warnings []string
}

// HasWarnings reports whether the review found any quality gaps.
func (q MetadataQuality) HasWarnings() bool {
	return len(q.Warnings) > 0
}

// CheckQuality reviews the control's metadata-completeness signals
// (compliance citations, remediation action, taxonomy mapping) and
// returns the issues an authoring tool should surface. Distinct
// from Validate (which checks structural correctness — predicate
// shape, parameter binding, severity validity) — CheckQuality
// answers "is this control well-annotated?" rather than "is this
// control structurally valid?". Forge runs both during lint.
func (ctl *ControlDefinition) CheckQuality() MetadataQuality {
	var q MetadataQuality
	if ctl == nil {
		return q
	}
	if !ctl.HasComplianceCitations() {
		q.Warnings = append(q.Warnings, "missing optional field: compliance (no framework citations)")
	}
	if !ctl.IsActionable() {
		q.Warnings = append(q.Warnings, "missing remediation.action")
	}
	if !ctl.IsTaxonomyMapped() {
		q.Warnings = append(q.Warnings, "missing params.attack_stage")
	}
	return q
}

// HasType reports whether the control declares a non-zero ControlType.
// Replaces (ctl.Type == 0) probes in lint and validation paths so a
// future zero-as-default change (e.g. switching to an enum that uses
// 0 for an explicit "unknown" tier) is one edit on the type.
func (ctl *ControlDefinition) HasType() bool {
	return ctl != nil && ctl.Type != TypeUnknown
}

// RequiresCELValidation reports whether the control is one of the
// types whose UnsafePredicate must compile under the CEL evaluator
// at lint time. TypeUnsafeState and TypeMarker both carry a
// CEL-evaluated predicate; types that lift their decision out of the
// predicate (Recurrence, PrefixExposure) skip the compile check.
func (ctl *ControlDefinition) RequiresCELValidation() bool {
	return ctl != nil && (ctl.Type == TypeUnsafeState || ctl.Type == TypeMarker)
}

// OneLineSummary returns the first human-readable label that callers
// should display for the control: the authored Defect prose when
// present (it carries the most diagnostic-friendly summary), falling
// back to Name when Defect is empty. Replaces the
// (Defect != "" ? Defect : Name) ternary at cmd/expand/cmd.go:354-355
// so a future addition of a Title or Headline field is one edit on
// the type instead of a scan across every renderer.
func (ctl *ControlDefinition) OneLineSummary() string {
	if ctl == nil {
		return ""
	}
	if ctl.HasDiagnosis() {
		return ctl.Defect
	}
	return ctl.Name
}

// HasDiagnosis reports whether the control carries any of the
// authored triage prose (Defect / Infection / Failure). Mirrors
// evaluation.Finding.HasDiagnosis so renderers consuming the
// catalog directly (cmd/expand) stop probing the Defect field
// individually.
func (ctl *ControlDefinition) HasDiagnosis() bool {
	return ctl != nil && (ctl.Defect != "" || ctl.Infection != "" || ctl.Failure != "")
}

// IsUnsafeState reports whether the control is the state-assertion
// shape (the predicate fires on a snapshot's instantaneous values).
func (ctl *ControlDefinition) IsUnsafeState() bool {
	return ctl != nil && ctl.Type == TypeUnsafeState
}

// IsUnsafeDuration reports whether the control is the duration-
// based shape (the predicate fires once dwell time exceeds a
// threshold).
func (ctl *ControlDefinition) IsUnsafeDuration() bool {
	return ctl != nil && ctl.Type == TypeUnsafeDuration
}

// IsTemporalControl reports whether the control's type is one of
// the temporal evaluation shapes the upcoming-risk engine
// considers (state-assertion or duration-based). Encapsulates
// the (TypeUnsafeState || TypeUnsafeDuration) compound check.
func (ctl *ControlDefinition) IsTemporalControl() bool {
	return ctl.IsUnsafeState() || ctl.IsUnsafeDuration()
}

// ExposureSummary returns the (type, principal-scope) pair the
// catalog's Exposure block exposes for renderers. ok = false
// when the control has no Exposure annotation, so callers can
// branch on a single boolean instead of nil-checking the pointer.
func (ctl *ControlDefinition) ExposureSummary() (exposureType, principalScope string, ok bool) {
	if ctl == nil || ctl.Exposure == nil {
		return "", "", false
	}
	return string(ctl.Exposure.Type), ctl.Exposure.PrincipalScope.String(), true
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

// HasMaxUnsafeDuration reports whether this control has an
// explicit max_unsafe_duration param. Sibling of HasSLADeadline.
// Replaces the (PreparedParams().HasMaxUnsafeDuration) probe at
// strategy.go so callers do not have to reach through the
// PreparedParams aggregate to ask one boolean.
func (ctl *ControlDefinition) HasMaxUnsafeDuration() bool {
	ctl.ensurePrepared()
	return ctl.prepared.HasMaxUnsafeDuration
}

// PrefixExposureParams returns the typed prefix-exposure params
// populated by Prepare. Mirrors the existing ExposurePrefixes
// accessor but returns the full struct so callers (the
// prefix-exposure assessor) get both AllowedPublicPrefixes and
// ProtectedPrefixes in one call.
func (ctl *ControlDefinition) PrefixExposureParams() PrefixExposureParams {
	ctl.ensurePrepared()
	return ctl.prepared.PrefixExposure
}

// Prepare extracts and validates typed parameters from the raw Params map.
// Idempotent — safe to call multiple times but not concurrently.
// External callers read prepare state through the per-attribute
// accessors (HasSLADeadline, MaxUnsafeDuration,
// HasMaxUnsafeDuration, PrefixExposureParams) — the full struct
// is not exposed.
func (ctl *ControlDefinition) Prepare() error {
	if ctl.prepared.Ready {
		return nil
	}

	// Non-failable params — always parse.
	ctl.prepared.Recurrence = ParseRecurrencePolicy(ctl.Params)
	ctl.prepared.PrefixExposure = preparePrefixExposure(ctl.Params)

	// Failable param — duration parsing.
	if raw := ctl.Params.paramString("max_unsafe_duration"); raw != "" {
		d, err := kernel.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("invalid max_unsafe_duration %q: %w", raw, err)
		}
		ctl.prepared.MaxUnsafeDuration = d
		ctl.prepared.HasMaxUnsafeDuration = true
	}

	if raw := ctl.Params.paramString("sla_deadline"); raw != "" {
		d, err := kernel.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("invalid sla_deadline %q: %w", raw, err)
		}
		ctl.prepared.SLADeadline = d
		ctl.prepared.HasSLADeadline = true
	}

	// Mark Ready only after all parsing succeeds.
	ctl.prepared.Ready = true
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
	ctl.ensurePrepared() // load-time Prepare() validates; lazy fallback logs.
	return ctl.prepared.Recurrence
}

// MaxUnsafeDuration returns the per-control max_unsafe_duration param.
// Returns 0 if not set (caller should apply CLI default fallback).
func (ctl *ControlDefinition) MaxUnsafeDuration() time.Duration {
	ctl.ensurePrepared()
	return ctl.prepared.MaxUnsafeDuration
}

// SLADeadline returns the per-control sla_deadline if set, otherwise 0.
func (ctl *ControlDefinition) SLADeadline() time.Duration {
	ctl.ensurePrepared()
	return ctl.prepared.SLADeadline
}

// HasSLADeadline reports whether this control has an explicit sla_deadline param.
func (ctl *ControlDefinition) HasSLADeadline() bool {
	ctl.ensurePrepared()
	return ctl.prepared.HasSLADeadline
}

// EffectiveMaxUnsafeDuration returns the per-control max_unsafe_duration if explicitly set,
// otherwise returns the provided fallback (typically the CLI --max-unsafe value).
func (ctl *ControlDefinition) EffectiveMaxUnsafeDuration(fallback time.Duration) time.Duration {
	ctl.ensurePrepared()
	if ctl.prepared.HasMaxUnsafeDuration {
		return ctl.prepared.MaxUnsafeDuration
	}
	return fallback
}

// ExposurePrefixes returns the typed prefix lists for prefix_exposure controls.
func (ctl *ControlDefinition) ExposurePrefixes() PrefixExposureParams {
	ctl.ensurePrepared()
	return ctl.prepared.PrefixExposure
}

// ensurePrepared lazily calls Prepare() on first access and logs at
// WARN if preparation fails. Side-effecting only — the void return
// signals to callers (the per-attribute accessors below) that error
// handling is centralised here, removing the `ctl.ensurePrepared()`
// blank-assignment pattern.
//
// The loader path (adapters/controls/{builtin,yaml}/loader.go) calls
// Prepare() eagerly and surfaces parse errors at that time; a
// recurrence of the failure during a lazy accessor call indicates a
// programming error in the loader. The slog.Warn keeps the
// diagnostic visible without forcing every accessor to return a
// tuple.
func (ctl *ControlDefinition) ensurePrepared() {
	if err := ctl.Prepare(); err != nil {
		slog.Warn("control prepare failed", "control", ctl.ID, "error", err)
	}
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

// IsZero reports whether the inner map is empty or nil.
func (p ControlParams) IsZero() bool { return len(p.m) == 0 }

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
// detection_evasion, resilience, etc. The vocabulary is open at the
// type level — see asCatalogAttackStage for the design rationale.
func (d *ControlDefinition) AttackStage() kernel.AttackStage {
	return asCatalogAttackStage(getParam[string](d.Params.m, "attack_stage"))
}

// asCatalogAttackStage casts a raw param string into kernel.AttackStage
// without runtime validation. The vocabulary is intentionally open
// at the type level: the catalog ships values beyond the named
// constants (collection, discovery, execution) and the closed-set
// enforcement lives in the catalog linter, not these accessors —
// see the kernel/attack_stage.go type doc. Naming the cast
// documents that design choice so a future maintainer doesn't try
// to "tighten" this accessor by validating against the named
// constants — which would silently drop stages the catalog ships.
func asCatalogAttackStage(raw string) kernel.AttackStage {
	return kernel.AttackStage(raw)
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
// Read from params.blast_radius.type. Defaults to "". The vocabulary
// is open at the type level — see asCatalogBlastRadiusType.
func (d *ControlDefinition) BlastRadiusType() kernel.BlastRadiusType {
	raw, ok := d.Params.Get("blast_radius")
	if !ok {
		return ""
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	return asCatalogBlastRadiusType(getParam[string](m, "type"))
}

// asCatalogBlastRadiusType casts a raw param string into
// kernel.BlastRadiusType without runtime validation. The catalog
// ships values beyond the named constants (availability, control,
// data_exposure, governance) and the closed-set enforcement lives
// in the catalog linter, not this accessor.
func asCatalogBlastRadiusType(raw string) kernel.BlastRadiusType {
	return kernel.BlastRadiusType(raw)
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
// The vocabulary is open at the type level — see asCatalogBlastScope.
func (d *ControlDefinition) BlastScope() kernel.BlastScope {
	raw, ok := d.Params.Get("blast_radius")
	if !ok {
		return kernel.BlastScopeResource
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return kernel.BlastScopeResource
	}
	s := asCatalogBlastScope(getParam[string](m, "scope"))
	if s == "" {
		return kernel.BlastScopeResource
	}
	return s
}

// asCatalogBlastScope casts a raw param string into kernel.BlastScope
// without runtime validation. The catalog ships values beyond the
// named constants (cross_account, organization, region) and the
// closed-set enforcement lives in the catalog linter, not this
// accessor.
func asCatalogBlastScope(raw string) kernel.BlastScope {
	return kernel.BlastScope(raw)
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

// IsDurationPrevalidated reports whether Prepare() has already parsed
// and verified max_unsafe_duration for this control. Validation sites
// can short-circuit a re-parse when this is true. Encapsulates the
// (Ready && HasMaxUnsafeDuration) probe so a future change to the
// prepared-state representation (status enum, additional flags) lands
// on the type rather than every call site.
func (p *PreparedParams) IsDurationPrevalidated() bool {
	return p.Ready && p.HasMaxUnsafeDuration
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
		TypeMarker,
	}
}

// IsMarker reports whether the control is a fact-recording marker.
// Marker findings do not count toward violations / SecurityState /
// exit codes; they exist so chains can compose facts that aren't
// individually unsafe (e.g. data-classification tags) with
// violation findings on related assets.
func (ctl *ControlDefinition) IsMarker() bool {
	return ctl != nil && ctl.Type == TypeMarker
}

// IsEvaluatable reports whether the evaluator can process this control type.
func (ctl *ControlDefinition) IsEvaluatable() bool {
	return slices.Contains(EvaluatableTypes(), ctl.Type)
}

// ControlMetadata provides a read-only snapshot of core identity and classification.
type ControlMetadata struct {
	ID              kernel.ControlID
	Name            string
	Description     string
	Severity        Severity
	Compliance      ComplianceMapping
	CCMV4           []string
	Remediation     *RemediationSpec
	Exposure        *Exposure
	Alternatives    []Alternative
	Classification  Classification
	ScopeTags       []kernel.ScopeTag
	Defect          string
	Infection       string
	Failure         string
	Archetype       kernel.ArchetypeID
	Scope           string
	CorpusReference string
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
		fmt.Sprintf("%v", ctl.ApplicableAssetTypes),
	}
	return h.Digest(components, '\n')
}

// Metadata returns the control's identity and classification fields
// packaged for Finding construction.
func (ctl *ControlDefinition) Metadata() ControlMetadata {
	return ControlMetadata{
		ID:              ctl.ID,
		Name:            ctl.Name,
		Description:     ctl.Description,
		Severity:        ctl.Severity,
		Compliance:      ctl.Compliance,
		CCMV4:           ctl.CCMV4,
		Remediation:     ctl.Remediation,
		Exposure:        ctl.Exposure,
		Alternatives:    ctl.Alternatives,
		Classification:  ctl.Classification,
		ScopeTags:       ctl.ScopeTags,
		Defect:          ctl.Defect,
		Infection:       ctl.Infection,
		Failure:         ctl.Failure,
		Archetype:       ctl.Archetype,
		Scope:           ctl.Scope,
		CorpusReference: ctl.CorpusReference,
	}
}

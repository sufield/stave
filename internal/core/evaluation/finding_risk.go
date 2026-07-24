package evaluation

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// Exploitability classifies a finding's position in the attack graph.
type Exploitability string

const (
	// ExploitabilityExploitable means this finding participates in a
	// compound chain where all preconditions are present.
	ExploitabilityExploitable Exploitability = "exploitable"

	// ExploitabilityOneAway means this finding participates in a chain
	// that would fire if one currently-absent precondition appeared.
	ExploitabilityOneAway Exploitability = "one_away"

	// ExploitabilityReachable means the finding is true but not
	// connected to a complete or near-complete attack path.
	ExploitabilityReachable Exploitability = "reachable"
)

// DecidingLayer identifies which policy layer is responsible for a
// finding — i.e. which layer the operator should change to remediate.
type DecidingLayer string

const (
	LayerIdentityPolicy       DecidingLayer = "identity_policy"
	LayerTrustPolicy          DecidingLayer = "trust_policy"
	LayerSCPCeiling           DecidingLayer = "scp_ceiling"
	LayerPermissionBoundary   DecidingLayer = "permission_boundary"
	LayerResourcePolicy       DecidingLayer = "resource_control_policy"
	LayerCredentialManagement DecidingLayer = "credential_management" //nolint:gosec // domain enum, not a credential
	LayerFederation           DecidingLayer = "federation"
)

// NearMissEntry records that a finding is one control away from
// completing a compound chain.
type NearMissEntry struct {
	ChainID         kernel.ChainID     `json:"chain_id"`
	ChainSeverity   policy.Severity    `json:"chain_severity"`
	MissingControl  kernel.ControlID   `json:"missing_control"`
	ControlsFailing []kernel.ControlID `json:"controls_failing,omitempty"`
	Description     string             `json:"description"`
}

// ChainMembershipEntry records that a finding contributed to a fired chain.
type ChainMembershipEntry struct {
	// ChainID is the chain definition ID (e.g. "data_exfiltration_path").
	ChainID kernel.ChainID `json:"chain_id"`

	// ChainSeverity is the compound severity of the chain.
	ChainSeverity policy.Severity `json:"chain_severity"`

	// StageSpan is the attack stage progression of the chain,
	// sorted by kill chain order.
	StageSpan []kernel.AttackStage `json:"stage_span"`

	// Narrative is the chain's human-readable description.
	Narrative string `json:"narrative"`
}

// IsChainMember reports whether the finding contributed to one or
// more fired chains. Sorting and rendering paths use this to push
// chain participants ahead of single-control violations.
//
// Nil-safe: required because HasEnrichedContext calls this on
// possibly-nil receivers (the other predicates folded into the
// disjunction already nil-guard themselves).
func (f *Finding) IsChainMember() bool {
	if f == nil {
		return false
	}
	return len(f.ChainMembership) > 0
}

// ChainMembershipCount returns the number of chains this finding
// participates in. Wraps the embedded slice length so callers
// (RankInput projection, chain-membership tests) stop reading
// `len(f.ChainMembership)` directly.
func (f *Finding) ChainMembershipCount() int {
	if f == nil {
		return 0
	}
	return len(f.ChainMembership)
}

// PrimaryChainSeverity returns the severity of the first chain this
// finding participates in, or "" if the finding is not a chain
// member. The "primary" chain is the first entry in ChainMembership;
// chain detection appends in deterministic order so this is stable
// across runs.
func (f *Finding) PrimaryChainSeverity() string {
	if f == nil || len(f.ChainMembership) == 0 {
		return ""
	}
	return f.ChainMembership[0].ChainSeverity.String()
}

// PrimaryChainID returns the ID of the first chain this finding
// participates in, or "" if the finding is not a chain member.
func (f *Finding) PrimaryChainID() string {
	if f == nil || len(f.ChainMembership) == 0 {
		return ""
	}
	return string(f.ChainMembership[0].ChainID)
}

// PrimaryChainNarrative returns the narrative attached to the
// first chain this finding participates in, or "" if the finding
// is not a chain member. Sibling of PrimaryChainID /
// PrimaryChainSeverity for the renderer that needs the prose
// alongside the IDs.
func (f *Finding) PrimaryChainNarrative() string {
	if f == nil || len(f.ChainMembership) == 0 {
		return ""
	}
	return f.ChainMembership[0].Narrative
}

// PrimaryChainStageSpan returns the StageSpan slice of the first
// chain this finding participates in, or nil when the finding is
// not a chain member. Used by the SARIF renderer's chain-context
// properties bag so the per-stage list lives on the type.
func (f *Finding) PrimaryChainStageSpan() []kernel.AttackStage {
	if f == nil || len(f.ChainMembership) == 0 {
		return nil
	}
	return f.ChainMembership[0].StageSpan
}

// ChainIDs returns every chain ID the finding contributes to, in
// catalogue order. Nil slice for non-chain findings so range loops
// behave the same as on an empty membership.
func (f *Finding) ChainIDs() []kernel.ChainID {
	if f == nil || len(f.ChainMembership) == 0 {
		return nil
	}
	out := make([]kernel.ChainID, len(f.ChainMembership))
	for i := range f.ChainMembership {
		out[i] = f.ChainMembership[i].ChainID
	}
	return out
}

// ChainMembershipProperties returns the per-chain property maps
// the graph builder embeds on a finding node's
// `x_stave_chain_membership` extension. Each entry carries
// chain_id, chain_severity, and narrative; stage_span is left for
// callers that need ATT&CK projections (the graph builder applies
// attack.TranslateStages on top of this slice's entries).
//
// Centralising the map shape here keeps the wire format stable
// across producers — any future addition lands in one place.
func (f *Finding) ChainMembershipProperties() []map[string]any {
	if f == nil || len(f.ChainMembership) == 0 {
		return nil
	}
	out := make([]map[string]any, len(f.ChainMembership))
	for i, cm := range f.ChainMembership {
		out[i] = map[string]any{
			"chain_id":       cm.ChainID,
			"chain_severity": cm.ChainSeverity,
			"stage_span":     cm.StageSpan,
			"narrative":      cm.Narrative,
		}
	}
	return out
}

// AddChainMembership appends a chain-membership entry to the
// finding. Centralised so the chain-attribution pass in
// app/eval/workflow stops mutating the slice directly — keeps the
// invariant ("entries are appended in chain-detection order, never
// reordered") on the type that owns the slice. A future change
// (deduplication, capacity reservation) lands one place.
func (f *Finding) AddChainMembership(entry ChainMembershipEntry) {
	if f == nil {
		return
	}
	f.ChainMembership = append(f.ChainMembership, entry)
}

// ChainMembershipEntries returns the chain-membership slice for
// adapter mapping. Returns nil when the finding does not
// participate in any chain so callers can branch on len(out) > 0
// without dereferencing a nil receiver.
func (f *Finding) ChainMembershipEntries() []ChainMembershipEntry {
	if f == nil {
		return nil
	}
	return f.ChainMembership
}

// ToFailingControl projects the finding to the (control, asset) pair
// the chain / attack-stage analysis consumes. Centralising the field
// extraction here means a future addition to FailingControl (e.g. a
// region or scope_tags hint) lands once on the producer side instead
// of being threaded through every enrichment caller.
func (f *Finding) ToFailingControl() risk.FailingControl {
	if f == nil {
		return risk.FailingControl{}
	}
	return risk.FailingControl{
		ControlID: f.ControlID,
		AssetID:   f.AssetID,
	}
}

// ToRankInput projects the finding to the input shape the exposure
// ranking consumes. The 6-field copy used to live inline in
// internal/app/eval/workflow.go; moving it here keeps the
// finding-to-rank-input contract on the type that owns the source
// fields so a future Evidence-field rename only edits one site.
func (f *Finding) ToRankInput() risk.RankInput {
	if f == nil {
		return risk.RankInput{}
	}
	return risk.RankInput{
		ControlID:            f.ControlID,
		AssetID:              f.AssetID,
		ControlSeverity:      f.ControlSeverity,
		Exposure:             f.Exposure,
		UnsafeDurationHours:  f.Evidence.UnsafeDurationHours,
		ChainMembershipCount: f.ChainMembershipCount(),
	}
}

// ComputeBaseScore returns the per-finding base exposure score the
// remediation roadmap uses when the chain-aware top-N ranker has not
// produced a precomputed score for this finding (e.g. assets that
// did not enter the top-N batch). The math mirrors the formula in
// risk.RankExposures: severity weight × duration factor × blind
// multiplier. Callers receive the score and the breakdown together
// so the roadmap entry can populate ScoreBreakdown without a second
// pass over the same fields.
func (f *Finding) ComputeBaseScore() (float64, findings.ScoreBreakdown) {
	if f == nil {
		return 0, findings.ScoreBreakdown{}
	}
	base := f.ControlSeverity.Weight()
	daysBlind := f.Evidence.UnsafeDurationHours / 24.0
	durFactor := risk.DurationFactor(f.Evidence.UnsafeDurationHours)
	blindMult := risk.BlindMultiplier(daysBlind)
	score := float64(base) * durFactor * blindMult
	return score, findings.ScoreBreakdown{
		BaseScore:          base,
		DurationFactor:     durFactor,
		BlastMultiplier:    1.0,
		ExposureMultiplier: 1.0,
		BlindMultiplier:    blindMult,
		DaysBlind:          daysBlind,
	}
}

// RiskContribution returns the per-finding contribution to an
// account-level risk score: severity weight × duration factor.
// Differs from ComputeBaseScore in that it omits the BlindMultiplier
// — consolidate's per-account roll-up uses the simpler formula so a
// long-blind finding doesn't dominate the account total. Centralised
// so consolidate's assessAccount loop stops re-deriving the (base ×
// dur) product inline.
func (f *Finding) RiskContribution() float64 {
	if f == nil {
		return 0
	}
	base := float64(f.ControlSeverity.Weight())
	dur := risk.DurationFactor(f.Evidence.UnsafeDurationHours)
	return base * dur
}

// PriorityAttributes packages the chain-membership + SLA-overdue
// state the rank renderer needs into a single struct so the priority
// entry construction site doesn't query four predicates and two
// accessors separately. Returned values mirror the originating
// Finding accessors:
//
//   - IsChainMember / ChainID / ChainSeverity come from
//     IsChainMember() and the PrimaryChain* accessors.
//   - SLABreached / OverdueHours come from IsOverdue() and
//     OverdueHours().
//
// Centralised here so a future enrichment field (e.g. chain
// confidence, SLA escalation severity) lands on the type, not at
// every priority-entry construction site.
type PriorityAttributes struct {
	IsChainMember bool
	ChainID       string
	ChainSeverity string
	SLABreached   bool
	OverdueHours  float64
	HasOverdue    bool
}

// PriorityAttributes returns the chain-membership and SLA overdue
// projections for use by the rank renderer. See PriorityAttributes
// for the contract.
func (f *Finding) PriorityAttributes() PriorityAttributes {
	if f == nil {
		return PriorityAttributes{}
	}
	out := PriorityAttributes{}
	if f.IsChainMember() {
		out.IsChainMember = true
		out.ChainID = f.PrimaryChainID()
		out.ChainSeverity = f.PrimaryChainSeverity()
	}
	if f.IsOverdue() {
		out.SLABreached = true
		if hours, ok := f.OverdueHours(); ok {
			out.OverdueHours = hours
			out.HasOverdue = true
		}
	}
	return out
}

// MaxSeverityWith returns the higher of this finding's ControlSeverity
// and other. Centralises the
// (if f.ControlSeverity > maxSev { maxSev = f.ControlSeverity })
// pattern that identity-rank's direct/transitive max-severity loops
// reproduce twice. nil receiver returns other.
func (f *Finding) MaxSeverityWith(other policy.Severity) policy.Severity {
	if f == nil {
		return other
	}
	if other > f.ControlSeverity {
		return other
	}
	return f.ControlSeverity
}

// MatchesSeverityFilter reports whether this finding's severity is
// in the allowed-set passed by a filter. The allowed map keys are
// the canonical lowercase severity labels (SeverityLabel form).
// Empty / nil allowed-map matches every finding so callers can pass
// a single filter shape regardless of whether a severity restriction
// is active. Replaces the
// (filter.Severities[f.ControlSeverity.String()]) probe in
// telemetry/mapper.go's matchesFilter.
func (f *Finding) MatchesSeverityFilter(allowed map[string]struct{}) bool {
	if len(allowed) == 0 {
		return true
	}
	if f == nil {
		return false
	}
	_, ok := allowed[f.SeverityLabel()]
	return ok
}

// SeveritySortRank returns the sort key the JSON report renderer
// uses to order findings by descending severity. Critical → 0,
// High → 1, Medium → 2, Low → 3, Info → 4. Encapsulates the
// (SeverityCritical - ControlSeverity) arithmetic on the iota
// ordering so renderers stop reaching for the constant directly.
//
// A nil receiver returns 0 — the highest-priority bucket — so a
// degenerate / placeholder Finding sorts to the front rather than
// being buried under real Critical findings (the previous behaviour
// returned int(SeverityCritical) which is 5, sorting nil findings
// last).
func (f *Finding) SeveritySortRank() int {
	if f == nil {
		return 0
	}
	return int(policy.SeverityCritical - f.ControlSeverity)
}

// IsCritical reports whether this finding's control severity is
// Critical. Replaces the
// strings.EqualFold(f.ControlSeverity.String(), "critical") pattern
// at cmd/trend/team_trend.go:113 with a typed comparison that does
// not depend on string-rendering of the severity enum.
func (f *Finding) IsCritical() bool {
	return f != nil && f.ControlSeverity == policy.SeverityCritical
}

// IsHighOrAbove reports whether this finding's control severity is
// High or Critical. Used by ranking / prioritisation code that
// needs the "important enough to surface" threshold.
func (f *Finding) IsHighOrAbove() bool {
	return f != nil && f.ControlSeverity >= policy.SeverityHigh
}

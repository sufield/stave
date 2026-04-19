package evaluation

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// Finding represents a detected control violation.
// A Finding is purely factual: evidence + classification, no advice.
type Finding struct {
	FindingID          string                   `json:"finding_id"`
	ControlID          kernel.ControlID         `json:"control_id"`
	ControlName        string                   `json:"control_name"`
	ControlDescription string                   `json:"control_description"`
	AssetID            asset.ID                 `json:"asset_id"`
	AssetType          kernel.AssetType         `json:"asset_type"`
	AssetVendor        kernel.Vendor            `json:"asset_vendor"`
	Source             *asset.SourceRef         `json:"source,omitempty"`
	Evidence           Evidence                 `json:"evidence"`
	ControlSeverity    policy.Severity          `json:"control_severity,omitempty"`
	ControlCompliance  policy.ComplianceMapping `json:"control_compliance,omitempty"`
	ControlCCMV4       []string                 `json:"control_compliance_ccm_v4,omitempty"`
	Exposure           *policy.Exposure         `json:"exposure,omitempty"`
	PostureDrift       *PostureDrift            `json:"posture_drift,omitempty"`
	ControlRemediation *policy.RemediationSpec  `json:"-"`

	// ChainMembership is non-empty when this finding is a member
	// of one or more chains that are currently firing.
	ChainMembership []ChainMembershipEntry `json:"chain_membership,omitempty"`

	// SLA fields — populated when an SLA deadline applies to this finding.
	SLADeadlineHours     *float64 `json:"sla_deadline_hours,omitempty"`
	SLABreached          bool     `json:"sla_breached,omitempty"`
	SLAOverdueHours      *float64 `json:"sla_overdue_hours,omitempty"`
	SLAEscalatedSeverity string   `json:"sla_escalated_severity,omitempty"`
	SLAPolicySource      string   `json:"sla_policy_source,omitempty"`

	// Owner routing — populated when a team manifest is loaded.
	OwnerTeamID     string `json:"owner_team_id,omitempty"`
	OwnerTeamName   string `json:"owner_team_name,omitempty"`
	OwnerContact    string `json:"owner_contact,omitempty"`
	OwnerResolution string `json:"owner_resolution_path,omitempty"`

	// Reachability — populated when IAM data is in the snapshot.
	Reachability *ReachabilityContext `json:"reachability,omitempty"`

	// ExposureScore is the priority score used to order findings. Populated
	// by the enrichment pass (internal/app/eval/workflow.go) after chain
	// membership is annotated. 0 on findings that have not been scored yet
	// (e.g., during assessor.compileReport before enrichment runs).
	ExposureScore float64 `json:"exposure_score,omitempty"`

	// ScoreBreakdown decomposes ExposureScore into the factors that produced
	// it. Populated alongside ExposureScore. Nil on unscored findings.
	ScoreBreakdown *risk.ScoreBreakdown `json:"score_breakdown,omitempty"`

	// ReasoningTrace lists the predicate leaf clauses that the engine
	// evaluated to produce this finding, each paired with the observed
	// value from the snapshot. For predicates rooted in `all:` (the
	// dominant shape in the catalog), every entry is a matched clause.
	// For predicates rooted in `any:`, entries are the full set of
	// evaluated clauses — the reader compares ObservedValue to
	// ExpectedValue to infer which satisfied the operator. Nil on
	// findings produced without a backing predicate (rare: compound
	// chain findings in report.ChainFindings).
	ReasoningTrace []MatchedClause `json:"reasoning_trace,omitempty"`
}

// ReasoningTraceFromMisconfigurations converts a predicate-extracted
// misconfiguration list into the reasoning-trace shape surfaced on a
// finding. The two carry the same triggering state from slightly
// different angles: Misconfiguration is the failed-logic-gate framing
// (used by Evidence), MatchedClause is the predicate-match-record
// framing (used by ReasoningTrace).
//
// See docs/product/metrics.md § Metric 3 for the inline-trace
// specification and the "shared predicate-consumed observation
// fields" framing that Metric 2 (Deduplication) will consume.
func ReasoningTraceFromMisconfigurations(ms []policy.Misconfiguration) []MatchedClause {
	if len(ms) == 0 {
		return nil
	}
	out := make([]MatchedClause, len(ms))
	for i, mc := range ms {
		key := mc.DisplayProperty()
		expected := mc.UnsafeValue
		operator := string(mc.Operator)
		out[i] = MatchedClause{
			PredicateExpr:  formatClauseExpr(key, operator, expected),
			ObservationKey: key,
			Operator:       operator,
			ExpectedValue:  expected,
			ObservedValue:  mc.ActualValue,
		}
	}
	return out
}

// formatClauseExpr renders the clause in the authored form for display.
func formatClauseExpr(key, op string, expected any) string {
	switch expected.(type) {
	case nil:
		return key + " " + op
	default:
		return key + " " + op + " " + stringifyExpected(expected)
	}
}

// stringifyExpected returns a compact display form of the expected value.
// Strings are quoted; other scalars use default Go formatting.
func stringifyExpected(v any) string {
	switch t := v.(type) {
	case string:
		return "\"" + t + "\""
	default:
		return fmt.Sprint(t)
	}
}

// MatchedClause records one predicate leaf clause and the observed
// value that triggered (or was considered in) the fire. See
// docs/product/metrics.md § Metric 3 for semantics.
type MatchedClause struct {
	// PredicateExpr is the authored form of the clause, e.g.
	// "storage.access.public_read eq true" — convenient for display.
	PredicateExpr string `json:"predicate_expr"`
	// ObservationKey is the field path the clause consumed, with the
	// "properties." prefix stripped for readability.
	ObservationKey string `json:"observation_key"`
	// Operator is the clause's op, e.g. "eq", "any_in_field".
	Operator string `json:"operator"`
	// ExpectedValue is the value the clause expected (or the param
	// reference when the value was `params.<name>`).
	ExpectedValue any `json:"expected_value,omitempty"`
	// ObservedValue is the value resolved from the snapshot at
	// ObservationKey. Nil when the field is absent from the
	// observation.
	ObservedValue any `json:"observed_value,omitempty"`
}

// ReachabilityContext carries IAM reachability data for a finding.
type ReachabilityContext struct {
	TotalReachablePrincipals   int     `json:"total_reachable_principals"`
	PrivilegedPrincipalCount   int     `json:"privileged_principal_count"`
	HighestPrivilegePrincipal  string  `json:"highest_privilege_principal,omitempty"`
	ExternalPrincipalReachable bool    `json:"external_principal_reachable,omitempty"`
	BlastRadiusScore           float64 `json:"blast_radius_score"`
}

// ChainMembershipEntry records that a finding contributed to a fired chain.
type ChainMembershipEntry struct {
	// ChainID is the chain definition ID (e.g. "data_exfiltration_path").
	ChainID string `json:"chain_id"`

	// ChainSeverity is the compound severity of the chain.
	ChainSeverity string `json:"chain_severity"`

	// StageSpan is the attack stage progression of the chain,
	// sorted by kill chain order.
	StageSpan []string `json:"stage_span"`

	// Narrative is the chain's human-readable description.
	Narrative string `json:"narrative"`
}

// SortFindings sorts findings by actionable priority:
// ExposureScore descending (highest-score findings first), with
// alphabetical tiebreaker on ControlID + AssetID (and further
// fallbacks) so the order stays deterministic when scores collide
// or when the sort is called before scoring runs.
//
// Unscored findings (ExposureScore == 0, e.g. during
// assessor.compileReport before the enrichment pass populates
// scores) fall through to the alphabetical tiebreaker, matching the
// previous sort semantics in that window.
func SortFindings(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		return cmp.Or(
			// Primary: ExposureScore descending.
			cmp.Compare(b.ExposureScore, a.ExposureScore),
			// Tiebreaker: deterministic alphabetical ordering.
			cmp.Compare(a.ControlID, b.ControlID),
			cmp.Compare(a.AssetID, b.AssetID),
			cmp.Compare(a.Evidence.TemporalRisk, b.Evidence.TemporalRisk),
			cmp.Compare(a.ControlName, b.ControlName),
			cmp.Compare(a.AssetType, b.AssetType),
		)
	})
}

// StableFindingID computes a deterministic fingerprint for a (control, asset) pair.
// Same inputs always produce the same ID, enabling cross-run finding correlation.
func StableFindingID(ctlID kernel.ControlID, astID asset.ID) string {
	h := sha256.New()
	h.Write([]byte("finding:"))
	h.Write([]byte(ctlID))
	h.Write([]byte(":"))
	h.Write([]byte(astID))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}

// NewFindingFromMetadata creates a Finding pre-populated with control metadata.
func NewFindingFromMetadata(m policy.ControlMetadata) Finding {
	return Finding{
		ControlID:          m.ID,
		ControlName:        m.Name,
		ControlDescription: m.Description,
		ControlSeverity:    m.Severity,
		ControlCompliance:  m.Compliance,
		ControlCCMV4:       m.CCMV4,
		ControlRemediation: m.Remediation,
		Exposure:           m.Exposure,
	}
}

// ExceptedFinding records a finding that was excepted, with audit trail.
type ExceptedFinding struct {
	ControlID kernel.ControlID  `json:"control_id"`
	AssetID   asset.ID          `json:"asset_id"`
	Reason    string            `json:"reason"`
	Expires   policy.ExpiryDate `json:"expires"`
}

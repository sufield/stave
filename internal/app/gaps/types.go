// Package gaps produces a field-level observation-gap report:
// for each (asset_type, property_path) the catalog declares, how
// many observed assets are missing that property and how many
// controls + chains the absence blocks.
//
// Phase 1 scope: tag gaps + collector gaps surfaced; per-asset-ID
// lists deferred behind a future --verbose flag; intent-property
// taxonomy hardcoded to a canonical 4-path set (data_classification,
// role-type, environment for storage and compute) until
// internal/controldata/taxonomy/ grows an intent_properties.yaml.
package gaps

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Report is the analyzer's output: the prioritized gap list plus
// a summary that aggregates counts for the operator's "what
// fraction of the catalog is this unlocking?" question.
type Report struct {
	Gaps    []FieldGap `json:"gaps"`
	Summary Summary    `json:"summary"`
}

// FieldGap is one (asset_type, property_path) pair where at least
// one observed asset of the type doesn't carry the property. Each
// gap carries the controls / chains it would unlock if fixed,
// plus a remediation hint.
type FieldGap struct {
	Priority             int                `json:"priority"`
	PropertyPath         string             `json:"property_path"`
	AssetType            kernel.AssetType   `json:"asset_type"`
	MissingCount         int                `json:"missing_count"`
	TotalCount           int                `json:"total_count"`
	ControlsBlocked      []kernel.ControlID `json:"controls_blocked"`
	ControlsBlockedCount int                `json:"controls_blocked_count"`
	ChainsBlocked        []kernel.ChainID   `json:"chains_blocked,omitempty"`
	ChainsBlockedCount   int                `json:"chains_blocked_count"`
	MaxSeverity          policy.Severity    `json:"max_severity"`
	IsIntentProperty     bool               `json:"is_intent_property"`
	Remediation          Remediation        `json:"remediation"`
}

// Remediation describes how the operator closes the gap and the
// effort it takes. Four classes today, partitioned along "can an
// agent loop fix this on the next iteration without escalating to
// a human?":
//
//	tag        — operator (or agent) adds a tag in the cloud
//	             provider's tag-resource API. Seconds per asset.
//	             FixableByAgent: true.
//	derived    — the property is a transform-time computation over
//	             values the source data already carries. An agent
//	             authoring a Steampipe → Stave mapping can add the
//	             field. FixableByAgent: true.
//	api        — the property requires a secondary cloud API call
//	             (Access Advisor, CloudTrail data events, etc.)
//	             outside the standard observation surface. The
//	             agent cannot conjure data it doesn't have.
//	             FixableByAgent: false.
//	collector  — the property requires a cross-inventory check or
//	             a collector code change (ghost references, intent
//	             matching, delegation analysis). The data source
//	             itself must grow to cover it. FixableByAgent: false.
//
// Agents read FixableByAgent to decide whether to retry (true) or
// escalate to the human operator (false). The Type field stays the
// authoritative classification — FixableByAgent is its derived
// boolean projection.
// RemediationType classifies the remediation action category.
type RemediationType string

const (
	RemediationTag       RemediationType = "tag"
	RemediationAPI       RemediationType = "api"
	RemediationDerived   RemediationType = "derived"
	RemediationCollector RemediationType = "collector"
)

type Remediation struct {
	Type           RemediationType `json:"type"`
	FixableByAgent bool            `json:"fixable_by_agent"`
	Guidance       string          `json:"guidance,omitempty"`
	Command        string          `json:"command,omitempty"`
	Effort         string          `json:"effort"`
}

// Summary aggregates counts and a "quick wins" estimate so the
// operator gets a single-line answer to "how much catalog
// coverage am I leaving on the table?"
//
// Per-type counts partition the gap set exactly: TagGaps +
// ApiGaps + DerivedGaps + CollectorGaps equals TotalGaps, and
// FixableByAgentGaps + NotFixableByAgentGaps equals TotalGaps.
// Agents read FixableByAgentGaps to decide whether to keep
// iterating; operators read the per-type split to budget effort
// (tag work is seconds, derived work is mapping edits, api and
// collector are escalations).
type Summary struct {
	TotalGaps               int    `json:"total_gaps"`
	TagGaps                 int    `json:"tag_gaps"`
	ApiGaps                 int    `json:"api_gaps"`
	DerivedGaps             int    `json:"derived_gaps"`
	CollectorGaps           int    `json:"collector_gaps"`
	FixableByAgentGaps      int    `json:"fixable_by_agent_gaps"`
	NotFixableByAgentGaps   int    `json:"not_fixable_by_agent_gaps"`
	ChainsBlockedTotal      int    `json:"chains_blocked_total"`
	ChainsUnblockedByTopN   int    `json:"chains_unblocked_by_top_n,omitempty"`
	TopN                    int    `json:"top_n,omitempty"`
	QuickWinTimeEstimate    string `json:"quick_win_time_estimate,omitempty"`
	IndeterminateControls   int    `json:"indeterminate_controls"`
	IndeterminateDisclaimer string `json:"indeterminate_disclaimer,omitempty"`
}

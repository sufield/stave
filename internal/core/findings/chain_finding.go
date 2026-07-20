// Package findings defines the data shapes the chain engine + risk
// engine produce and consumers (report.Assessment fields, DTOs,
// renderers) consume. Originally these types lived in
// internal/core/evaluation/risk; they were relocated here during
// the chain-engine untangle (may8.md sequence) so that:
//   - report/ stops importing risk/ (the original entanglement)
//   - the risk → report → evaluation → risk cycle is structurally
//     impossible (this package is a leaf — kernel/asset/controldef only)
//   - risk/ retains source-level compat through transitional aliases
//     while consumers migrate one at a time to the findings/ name
//
// The aliases in risk/ are scaffolding for the rolling migration;
// they will be deleted after every consumer rewrites risk.X → findings.X.
package findings

import (
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// CompoundFinding represents a chain-detected compound risk — multiple
// co-failing controls that together create a risk greater than their sum.
//
// AssetID is one representative contributing asset (deterministic — the
// lowest asset.ID under string sort among the assets that fed the
// chain). When the chain uses ScopeField, multiple distinct assets may
// have contributed; ScopeID carries the shared scope value, ScopeField
// records which property path produced it, and ContributingAssets lists
// every asset.ID that fed the chain. When ScopeField is empty (default),
// ScopeID is empty and ContributingAssets contains the single asset
// whose failures triggered the chain — preserving the legacy shape.
//
// Moved from internal/core/evaluation/risk/chain_engine.go during the
// chain-engine untangle (may8.md sequence) so report/ stops importing
// risk/. risk.CompoundFinding remains as a brief local alias for
// producer-side code in risk/ (DetectChains and sortFunc callbacks);
// external consumers reach for findings.CompoundFinding directly.
type CompoundFinding struct {
	ChainID               kernel.ChainID       `json:"chain"`
	AssetID               asset.ID             `json:"asset_id,omitempty"`
	ScopeID               string               `json:"scope_id,omitempty"`
	ScopeField            string               `json:"scope_field,omitempty"`
	ContributingAssets    []asset.ID           `json:"contributing_assets,omitempty"`
	Description           string               `json:"description,omitempty"`
	ControlsFailing       []kernel.ControlID   `json:"controls_failing"`
	MissingSafeguards     []kernel.ControlID   `json:"missing_safeguards,omitempty"`
	CompoundScore         float64              `json:"compound_score"`
	Severity              policy.Severity      `json:"severity"`
	Narrative             string               `json:"narrative"`
	AttackStages          []kernel.AttackStage `json:"attack_stages,omitempty"`
	Confidence            string               `json:"confidence,omitempty"`
	CompensatingNote      string               `json:"compensating_note,omitempty"`
	FreshnessReason       string               `json:"freshness_reason,omitempty"`
	DependencyDiagnostics []string             `json:"dependency_diagnostics,omitempty"`

	// DegradedEdge marks graph-sourced findings that reference expired
	// or dormant assets — the underlying trust relationship may not
	// be exploitable.
	DegradedEdge       bool   `json:"degraded_edge,omitempty"`
	DegradedEdgeReason string `json:"degraded_edge_reason,omitempty"`
}

// SeverityLabel returns the canonical lowercase severity string
// for the chain finding (e.g. "critical"). Mirrors the shape on
// Finding so renderers can ask either type for its label without
// knowing which variant is in hand.
func (c *CompoundFinding) SeverityLabel() string {
	if c == nil {
		return ""
	}
	return c.Severity.String()
}

// ChainSuggestion is a candidate chain definition inferred from
// unchained high-severity controls that co-fail on the same asset(s).
type ChainSuggestion struct {
	ControlIDs []kernel.ControlID `json:"control_ids"`
	AssetIDs   []asset.ID         `json:"asset_ids"`
	Reason     string             `json:"reason"`
	MaxSev     policy.Severity    `json:"max_severity"`
}

// NearMissChain represents a chain that is exactly one control short
// of firing. The controls that ARE failing are tracked alongside the
// single missing control that would complete the chain.
type NearMissChain struct {
	ChainID         kernel.ChainID     `json:"chain"`
	Description     string             `json:"description,omitempty"`
	ControlsFailing []kernel.ControlID `json:"controls_failing"`
	MissingControl  kernel.ControlID   `json:"missing_control"`
	Severity        policy.Severity    `json:"severity"`
	ScopeID         string             `json:"scope_id,omitempty"`
}

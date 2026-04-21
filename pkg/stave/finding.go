package stave

import (
	"github.com/sufield/stave/internal/core/evaluation"
)

// Finding is a per-(control, asset) violation record.
//
// This is a trimmed view of the engine's internal finding shape.
// Fields that are CLI-adapter-specific (owner routing, SLA overlay
// fields, chain membership annotations, reachability context) or
// not yet earned through consumer evidence are omitted. Add them
// here when a consumer demonstrates a concrete need.
type Finding struct {
	// FindingID is a stable fingerprint over (control, asset).
	FindingID FindingID

	// ControlID identifies the fired control.
	ControlID ControlID

	// ControlName is the control's human-readable name.
	ControlName string

	// AssetID identifies the failing asset.
	AssetID AssetID

	// AssetType categorizes the failing asset.
	AssetType AssetType

	// Severity is the control's declared severity.
	Severity Severity

	// Classification marks the control's semantic role. Consumers
	// filtering "is this asset actually in the unsafe state?"
	// select [StateAssertion]; absence and parameterized checks
	// answer different questions and belong in separate buckets.
	Classification Classification

	// ScopeTags carries the control's scope_tags field. In
	// practice tags like "aws" or "s3" — the catalog is growing
	// more discriminating tags (e.g. "public-access") over time.
	ScopeTags []ScopeTag

	// ControlCompliance maps framework identifiers (e.g. "hipaa",
	// "soc2", "pci") to the specific citation the control
	// satisfies. Empty when the control declares no framework
	// mappings.
	ControlCompliance map[string]string

	// Remediation is the guidance the catalog authored for this
	// control. Zero value means the control declared no custom
	// remediation; the engine falls back to class-based defaults.
	Remediation Remediation

	// ReasoningTrace lists the predicate clauses the engine
	// evaluated to produce this finding, paired with the observed
	// values from the snapshot. Useful for explaining why a
	// finding fired. Also the backing data for the OBSERVED
	// section when adopters render the full triage chain.
	ReasoningTrace []MatchedClause

	// Defect / Infection / Failure carry the authored triage
	// chain from Andreas Zeller's Why Programs Fail, applied to
	// cloud misconfigurations. Copied from the control's YAML
	// metadata at evaluation time. Empty when the control hasn't
	// been authored for the failure-theory chain yet; consumer
	// rendering should skip empty sections rather than emit
	// placeholders.
	Defect    string
	Infection string
	Failure   string

	// Delta is the mechanically-derived set of fix paths. Each
	// DeltaPath is an independent change that eliminates this
	// finding. For AND predicates, any single path suffices. Nil
	// when derivation is not possible.
	Delta []DeltaPath

	// ChainMembership lists the compound-risk chains this finding
	// participates in. Empty when no chain's escalation threshold
	// was met OR when the library was run without chain definitions
	// loaded. See Assessment.ChainFindings for the top-level chain
	// entries referenced by ChainID.
	ChainMembership []ChainMembershipEntry

	// ChainBonus is the ExposureScore multiplier applied to this
	// finding by virtue of its chain membership: 1.0× for findings
	// on 0 chains, 1.5× for 1 chain, 2.0× for 2+ chains. Populated
	// by the engine's ranking pass. Useful when rendering scores
	// with provenance (e.g. "ExposureScore: 7.6 (2.0× chain
	// bonus)"). Defaults to 1.0 for findings not enrolled in any
	// chain.
	ChainBonus float64

	// ExposureScore is the priority score the engine assigned
	// after risk enrichment. Higher scores are more urgent.
	// Incorporates ChainBonus; sort findings by ExposureScore
	// descending to surface chain-member findings first.
	ExposureScore float64
}

// MatchedClause is one predicate leaf clause evaluated against a
// snapshot. Aliased from the internal evaluation package.
type MatchedClause = evaluation.MatchedClause

// DeltaPath represents one independent fix that eliminates a finding.
type DeltaPath struct {
	PropertyLabel string // human-readable property name
	PropertyPath  string // raw observation path
	CurrentValue  string // observed value from snapshot
	FixAction     string // change needed to eliminate finding
}

// Remediation is the catalog-authored remediation guidance for a
// control. The fields are copied from the control's RemediationSpec
// in the YAML.
type Remediation struct {
	// Description is a brief human-readable summary.
	Description string

	// Action is the remediation text itself — either a
	// parameterized CLI command (e.g., "aws s3api put-bucket-acl ...")
	// when the catalog authored an executable fix, or prose when
	// the fix is advisory. Consumers detecting "do we have an
	// actionable command?" check whether this starts with a
	// known tool prefix.
	Action string

	// Example shows a concrete usage, when the catalog declared
	// one.
	Example string
}

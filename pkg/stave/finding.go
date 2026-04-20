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
	// finding fired.
	ReasoningTrace []MatchedClause

	// ExposureScore is the priority score the engine assigned
	// after risk enrichment. Higher scores are more urgent.
	ExposureScore float64
}

// MatchedClause is one predicate leaf clause evaluated against a
// snapshot. Aliased from the internal evaluation package.
type MatchedClause = evaluation.MatchedClause

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

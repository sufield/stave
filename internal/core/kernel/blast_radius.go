package kernel

// BlastRadiusType describes how a control attenuates risk: by
// detecting events after they occur, preventing them up front, or
// recovering from them after the fact. Read from
// params.blast_radius.type in a control definition.
type BlastRadiusType string

const (
	BlastRadiusDetection  BlastRadiusType = "detection"
	BlastRadiusPrevention BlastRadiusType = "prevention"
	BlastRadiusRecovery   BlastRadiusType = "recovery"
)

// String returns the raw value.
func (b BlastRadiusType) String() string { return string(b) }

// BlastScope describes the reach of a control's failure: account-wide
// (e.g., disabling CloudTrail blinds the whole account), network-wide
// (one VPC), or limited to the specific resource. Read from
// params.blast_radius.scope; defaults to "resource".
type BlastScope string

const (
	BlastScopeAccount  BlastScope = "account"
	BlastScopeNetwork  BlastScope = "network"
	BlastScopeResource BlastScope = "resource"
)

// String returns the raw value.
func (b BlastScope) String() string { return string(b) }

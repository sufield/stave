package diff

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// RiskDelta captures compound-level risk movement caused by configuration
// changes between two snapshots. Populated by running evaluation on both
// snapshots and comparing the results.
type RiskDelta struct {
	ChainsActivated  []ChainActivation `json:"chains_activated,omitempty"`
	ChainsResolved   []ChainResolution `json:"chains_resolved,omitempty"`
	DistanceChanges  []DistanceChange  `json:"distance_changes,omitempty"`
	NewFindings      int               `json:"new_findings"`
	ResolvedFindings int               `json:"resolved_findings"`
}

// ChainActivation records a compound chain that became active due to changes.
type ChainActivation struct {
	ChainID  kernel.ChainID  `json:"chain_id"`
	Severity policy.Severity `json:"severity"`
	Cause    []string        `json:"cause,omitempty"` // field changes that activated it
}

// ChainResolution records a compound chain that was resolved by changes.
type ChainResolution struct {
	ChainID kernel.ChainID `json:"chain_id"`
	Cause   []string       `json:"cause,omitempty"` // field changes that resolved it
}

// DistanceChange records a chain whose distance (remaining gates) changed.
type DistanceChange struct {
	ChainID     kernel.ChainID     `json:"chain_id"`
	WasDistance int                `json:"was_distance"`
	NowDistance int                `json:"now_distance"`
	GatesFell   []kernel.ControlID `json:"gates_fell,omitempty"` // controls that went pass→fail
	GatesHeld   []kernel.ControlID `json:"gates_held,omitempty"` // controls still holding
}

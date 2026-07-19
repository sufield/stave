package diff

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

// NetDirection returns the overall risk direction of the delta.
func (d *RiskDelta) NetDirection() RiskDirection {
	if len(d.ChainsActivated) > len(d.ChainsResolved) {
		return RiskIncreasing
	}
	if len(d.ChainsResolved) > len(d.ChainsActivated) {
		return RiskDecreasing
	}
	if d.NewFindings > d.ResolvedFindings {
		return RiskIncreasing
	}
	if d.ResolvedFindings > d.NewFindings {
		return RiskDecreasing
	}
	return RiskNeutral
}

// ChainActivation records a compound chain that became active due to changes.
type ChainActivation struct {
	ChainID  string   `json:"chain_id"`
	Severity string   `json:"severity"`
	Cause    []string `json:"cause,omitempty"` // field changes that activated it
}

// ChainResolution records a compound chain that was resolved by changes.
type ChainResolution struct {
	ChainID string   `json:"chain_id"`
	Cause   []string `json:"cause,omitempty"` // field changes that resolved it
}

// DistanceChange records a chain whose distance (remaining gates) changed.
type DistanceChange struct {
	ChainID     string   `json:"chain_id"`
	WasDistance int      `json:"was_distance"`
	NowDistance int      `json:"now_distance"`
	GatesFell   []string `json:"gates_fell,omitempty"` // controls that went pass→fail
	GatesHeld   []string `json:"gates_held,omitempty"` // controls still holding
}

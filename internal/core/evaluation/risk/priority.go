package risk

import (
	"cmp"
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// PriorityInput carries the data needed to compute a priority score
// for one compound finding.
type PriorityInput struct {
	Severity             policy.Severity
	Complexity           policy.ChainComplexity
	EnvironmentTier      EnvironmentTier
	SharedChainCount     int
	HasIncidentPrecedent bool
}

// PriorityScore computes a numeric priority from multiple dimensions.
// Higher = more urgent. Bonuses are multiplicative so LOW-severity
// can never outrank CRITICAL at the same complexity/environment tier.
func PriorityScore(in PriorityInput) float64 {
	base := float64(in.Severity.Weight())
	pre := base * complexityMultiplier(in.Complexity) * EnvironmentMultiplier(in.EnvironmentTier)
	chokeMult := 1.0 + float64(in.SharedChainCount)*0.05
	if chokeMult > 1.5 {
		chokeMult = 1.5
	}
	precedentMult := 1.0
	if in.HasIncidentPrecedent {
		precedentMult = 1.25
	}
	return pre * chokeMult * precedentMult
}

func complexityMultiplier(c policy.ChainComplexity) float64 {
	switch c {
	case policy.ComplexityAutomated:
		return 2.0
	case policy.ComplexityManual:
		return 1.0
	case policy.ComplexityDependent:
		return 0.7
	default:
		return 1.0
	}
}

// PrioritizedFinding pairs a compound finding with its computed score.
type PrioritizedFinding struct {
	Finding  findings.CompoundFinding
	Priority float64
}

// PrioritizeFindings scores and sorts compound findings by priority descending.
// chainLookup provides complexity and shared-chain-count from chain definitions.
func PrioritizeFindings(
	cfs []findings.CompoundFinding,
	chainLookup map[kernel.ChainID]*policy.ChainDefinition,
	envTier EnvironmentTier,
) []PrioritizedFinding {
	if len(cfs) == 0 {
		return nil
	}

	membershipCounts := buildMembershipCounts(cfs, chainLookup)

	out := make([]PrioritizedFinding, len(cfs))
	for i := range cfs {
		cf := &cfs[i]
		complexity := policy.ChainComplexity("")
		hasIncident := false
		if def, ok := chainLookup[cf.ChainID]; ok {
			complexity = def.Complexity
			hasIncident = chainHasIncidentRef(def)
		}
		out[i] = PrioritizedFinding{
			Finding: *cf,
			Priority: PriorityScore(PriorityInput{
				Severity:             cf.Severity,
				Complexity:           complexity,
				EnvironmentTier:      envTier,
				SharedChainCount:     membershipCounts[cf.ChainID],
				HasIncidentPrecedent: hasIncident,
			}),
		}
	}

	slices.SortFunc(out, func(a, b PrioritizedFinding) int {
		if c := cmp.Compare(b.Priority, a.Priority); c != 0 {
			return c
		}
		return cmp.Compare(a.Finding.ChainID, b.Finding.ChainID)
	})
	return out
}

// buildMembershipCounts counts how many OTHER chains share at least one
// control with each chain (the "choke point" heuristic).
func buildMembershipCounts(
	cfs []findings.CompoundFinding,
	chainLookup map[kernel.ChainID]*policy.ChainDefinition,
) map[kernel.ChainID]int {
	controlToChains := make(map[kernel.ControlID]map[kernel.ChainID]struct{})
	for i := range cfs {
		for _, cid := range cfs[i].ControlsFailing {
			if controlToChains[cid] == nil {
				controlToChains[cid] = make(map[kernel.ChainID]struct{})
			}
			controlToChains[cid][cfs[i].ChainID] = struct{}{}
		}
	}

	counts := make(map[kernel.ChainID]int, len(cfs))
	for i := range cfs {
		shared := make(map[kernel.ChainID]struct{})
		for _, cid := range cfs[i].ControlsFailing {
			for chainID := range controlToChains[cid] {
				if chainID != cfs[i].ChainID {
					shared[chainID] = struct{}{}
				}
			}
		}
		counts[cfs[i].ChainID] = len(shared)
	}
	_ = chainLookup
	return counts
}

func chainHasIncidentRef(def *policy.ChainDefinition) bool {
	return def != nil && def.IncidentPrecedent != nil
}

package risk

import (
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// LintUnchainedHighSeverity returns control IDs of critical/high atomic
// findings that do not appear in any compound chain's ControlsFailing.
// These are blind spots in compound-only mode.
func LintUnchainedHighSeverity(
	atomicControlIDs []kernel.ControlID,
	atomicSeverities map[kernel.ControlID]policy.Severity,
	chainFindings []findings.CompoundFinding,
) []string {
	chained := make(map[kernel.ControlID]struct{})
	for i := range chainFindings {
		for _, cid := range chainFindings[i].ControlsFailing {
			chained[cid] = struct{}{}
		}
	}

	var unchained []string
	for _, cid := range atomicControlIDs {
		sev := atomicSeverities[cid]
		if sev != policy.SeverityCritical && sev != policy.SeverityHigh {
			continue
		}
		if _, ok := chained[cid]; !ok {
			unchained = append(unchained, string(cid))
		}
	}
	slices.Sort(unchained)
	return slices.Compact(unchained)
}

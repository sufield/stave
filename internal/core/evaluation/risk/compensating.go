package risk

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	findingsdata "github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// ApplyCompensatingControls checks whether any of the chain's
// declared compensating controls are passing. If so, downgrades
// the finding's exploitability accordingly.
//
// The finding still fires — compensating controls improve the
// classification, they don't suppress the finding. If the
// compensating control is later removed, exploitability reverts.
func ApplyCompensatingControls(
	finding *findingsdata.CompoundFinding,
	chain policy.ChainDefinition,
	passingControls map[kernel.ControlID]bool,
) {
	for _, cc := range chain.CompensatingControls {
		cid := kernel.ControlID(cc.ControlID)
		if !passingControls[cid] {
			continue
		}
		switch cc.Effect {
		case policy.EffectBlocks:
			finding.CompensatingNote = cc.Rationale
			finding.Confidence = "reduced"
			return
		case policy.EffectDowngrade:
			finding.CompensatingNote = cc.Rationale
			finding.Confidence = "reduced"
		}
	}
}

package engine

import (
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

// FindingContext groups the situational details for a specific violation.
type FindingContext struct {
	Reason     string
	Misconfigs []policy.Misconfiguration
}

// NewFinding creates a finding by combining control metadata, asset identity,
// and the specific situational evidence (FindingContext).
func NewFinding(
	ctl *policy.ControlDefinition,
	t *asset.Timeline,
	ctx FindingContext,
) *evaluation.Finding {
	f := newBaseFinding(ctl, t)
	f.Evidence = evaluation.Evidence{
		Misconfigurations: ctx.Misconfigs,
		WhyNow:            ctx.Reason,
	}
	return f
}

// newBaseFinding returns a Finding pre-populated with control and asset metadata.
func newBaseFinding(ctl *policy.ControlDefinition, t *asset.Timeline) *evaluation.Finding {
	a := t.Asset()
	f := evaluation.NewFindingFromMetadata(ctl.Metadata())
	f.AssetID = t.ID
	f.AssetType = a.Type
	f.AssetVendor = a.Vendor
	f.Source = a.Source
	f.PostureDrift = evaluation.ComputePostureDrift(t)
	return &f
}

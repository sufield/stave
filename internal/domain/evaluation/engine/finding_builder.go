package engine

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
)

// FindingContext groups the situational details for a specific violation.
type FindingContext struct {
	Why        string
	Misconfigs []policy.Misconfiguration
}

// baseFinding returns a Finding pre-populated with control metadata, asset
// identity, and posture drift. Callers set Evidence before returning.
func baseFinding(ctl *policy.ControlDefinition, timeline *asset.Timeline) evaluation.Finding {
	f := evaluation.NewFindingFromMetadata(ctl.Metadata())
	a := timeline.Asset()
	f.AssetID = timeline.ID
	f.AssetType = a.Type
	f.AssetVendor = a.Vendor
	f.Source = a.Source
	f.PostureDrift = evaluation.ComputePostureDrift(timeline)
	return f
}

// NewFinding creates a finding by combining control metadata and timeline state.
func NewFinding(
	ctl *policy.ControlDefinition,
	timeline *asset.Timeline,
	ctx FindingContext,
) evaluation.Finding {
	f := baseFinding(ctl, timeline)
	f.Evidence = evaluation.Evidence{
		Misconfigurations: ctx.Misconfigs,
		WhyNow:            ctx.Why,
	}
	return f
}

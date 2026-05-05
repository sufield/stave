package engine

import (
	"log/slog"

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
//
// Returns nil when the underlying newBaseFinding rejects the inputs
// (nil control or nil lifecycle). Callers must propagate the nil
// rather than dereferencing — see exposure.go for the slice-append
// pattern and the collector for the nil-tolerant RecordFindings
// path.
func NewFinding(
	ctl *policy.ControlDefinition,
	t *asset.ExposureLifecycle,
	ctx FindingContext,
) *evaluation.Finding {
	f := newBaseFinding(ctl, t)
	if f == nil {
		return nil
	}
	f.Evidence = evaluation.Evidence{
		Misconfigurations: ctx.Misconfigs,
		TemporalRisk:      ctx.Reason,
	}
	f.ReasoningTrace = evaluation.ReasoningTraceFromMisconfigurations(ctx.Misconfigs)
	f.Delta = policy.DeriveDeltas(ctx.Misconfigs)
	return f
}

// newBaseFinding returns a Finding pre-populated with control and asset metadata.
// Returns nil when either input is nil — a zero-value finding would otherwise
// flow into the collector with empty FindingID / AssetID, where it appeared in
// output as a phantom "0 violations" row that operators couldn't trace back to
// any control. The caller chain (NewFinding, CreateRecurrenceFinding,
// CreateDurationFinding) and the collector's RecordFindings tolerate the nil.
func newBaseFinding(ctl *policy.ControlDefinition, t *asset.ExposureLifecycle) *evaluation.Finding {
	if t == nil || ctl == nil {
		slog.Warn("newBaseFinding called with nil input; skipping finding",
			"nil_lifecycle", t == nil, "nil_control", ctl == nil)
		return nil
	}
	a := t.Asset()
	f := evaluation.NewFindingFromMetadata(ctl.Metadata())
	f.FindingID = evaluation.StableFindingID(ctl.ID, t.ID)
	f.AssetID = t.ID
	f.AssetType = a.Type
	f.AssetVendor = a.Vendor
	f.Source = a.Source
	f.PostureDrift = evaluation.ComputePostureDrift(t)
	return &f
}

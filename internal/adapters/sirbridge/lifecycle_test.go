package sirbridge

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/sir"
)

// stubPredicateEval marks every (control, asset) pair "exposed"
// when the asset's properties carry the marker key
// "is_exposed_for_test=true", and "secure" otherwise. Lets the
// bridge test exercise the engine pipeline without bringing in
// the real CEL evaluator.
func stubPredicateEval(_ controldef.ControlDefinition, a asset.Asset, _ []asset.CloudIdentity) (bool, error) {
	if v, ok := a.Properties["is_exposed_for_test"].(bool); ok && v {
		return true, nil
	}
	return false, nil
}

func TestEngineLifecycleSource_RoundTripThroughBuilder(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ctl := controldef.ControlDefinition{
		ID:                   kernel.ControlID("CTL.S3.PUBLIC.001"),
		Type:                 controldef.TypeUnsafeState,
		Severity:             controldef.SeverityHigh,
		ApplicableAssetTypes: []kernel.AssetType{kernel.AssetType("aws_s3_bucket")},
	}
	bucket := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::bucket-a"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"is_exposed_for_test": true,
		},
	}
	snap1 := asset.Snapshot{Source: asset.SourceDeployed, CapturedAt: now.Add(-3 * time.Hour), Assets: []asset.Asset{bucket}}
	snap2 := asset.Snapshot{Source: asset.SourceDeployed, CapturedAt: now.Add(-time.Hour), Assets: []asset.Asset{bucket}}

	src := NewEngineLifecycleSource(stubPredicateEval)
	b := sir.NewBuilder(sir.WithLifecycleSource(src))
	doc, err := b.Build([]controldef.ControlDefinition{ctl}, []asset.Snapshot{snap1, snap2}, now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(doc.Temporal.Windows) == 0 {
		t.Fatalf("expected at least one window, got 0")
	}
	w := doc.Temporal.Windows[0]
	if w.AssetID != "arn:aws:s3:::bucket-a" {
		t.Errorf("Window AssetID: got %q", w.AssetID)
	}
	if !w.UnsafePredicateMatched {
		t.Errorf("Window UnsafePredicateMatched: want true")
	}
	if !w.End.Equal(now) {
		// Active window should terminate at EvaluatedAt.
		t.Errorf("active window End: want %v, got %v", now, w.End)
	}
	if len(w.ContributingControls) != 1 || w.ContributingControls[0] != "CTL.S3.PUBLIC.001" {
		t.Errorf("ContributingControls: want [CTL.S3.PUBLIC.001], got %v", w.ContributingControls)
	}
}

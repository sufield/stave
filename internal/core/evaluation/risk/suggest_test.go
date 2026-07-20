package risk

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestSuggestChains_CoFailingOnSameAsset(t *testing.T) {
	failures := []FailingControl{
		{ControlID: "CTL.A", AssetID: "bucket-1"},
		{ControlID: "CTL.B", AssetID: "bucket-1"},
		{ControlID: "CTL.C", AssetID: "bucket-1"},
	}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.A": {ID: "CTL.A", Severity: policy.SeverityCritical},
		"CTL.B": {ID: "CTL.B", Severity: policy.SeverityHigh},
		"CTL.C": {ID: "CTL.C", Severity: policy.SeverityHigh},
	}

	suggestions := SuggestChains(failures, nil, lookup)

	if len(suggestions) != 1 {
		t.Fatalf("want 1 suggestion, got %d", len(suggestions))
	}
	s := suggestions[0]
	if len(s.ControlIDs) != 3 {
		t.Errorf("want 3 controls, got %d", len(s.ControlIDs))
	}
	if s.MaxSev != policy.SeverityCritical {
		t.Errorf("want critical, got %s", s.MaxSev)
	}
	if len(s.AssetIDs) != 1 || s.AssetIDs[0] != "bucket-1" {
		t.Errorf("want [bucket-1], got %v", s.AssetIDs)
	}
}

func TestSuggestChains_ExcludesChainedControls(t *testing.T) {
	failures := []FailingControl{
		{ControlID: "CTL.A", AssetID: "bucket-1"},
		{ControlID: "CTL.B", AssetID: "bucket-1"},
	}
	chainFindings := []findings.CompoundFinding{
		{ChainID: "existing", ControlsFailing: []kernel.ControlID{"CTL.A", "CTL.B"}},
	}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.A": {ID: "CTL.A", Severity: policy.SeverityCritical},
		"CTL.B": {ID: "CTL.B", Severity: policy.SeverityHigh},
	}

	suggestions := SuggestChains(failures, chainFindings, lookup)

	if len(suggestions) != 0 {
		t.Errorf("want 0 suggestions (all controls chained), got %d", len(suggestions))
	}
}

func TestSuggestChains_IgnoresLowSeverity(t *testing.T) {
	failures := []FailingControl{
		{ControlID: "CTL.A", AssetID: "bucket-1"},
		{ControlID: "CTL.B", AssetID: "bucket-1"},
	}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.A": {ID: "CTL.A", Severity: policy.SeverityMedium},
		"CTL.B": {ID: "CTL.B", Severity: policy.SeverityLow},
	}

	suggestions := SuggestChains(failures, nil, lookup)

	if len(suggestions) != 0 {
		t.Errorf("want 0 suggestions (low severity), got %d", len(suggestions))
	}
}

func TestSuggestChains_SingleControlNoSuggestion(t *testing.T) {
	failures := []FailingControl{
		{ControlID: "CTL.A", AssetID: "bucket-1"},
	}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.A": {ID: "CTL.A", Severity: policy.SeverityCritical},
	}

	suggestions := SuggestChains(failures, nil, lookup)

	if len(suggestions) != 0 {
		t.Errorf("want 0 suggestions (single control), got %d", len(suggestions))
	}
}

func TestSuggestChains_MergesAcrossAssets(t *testing.T) {
	failures := []FailingControl{
		{ControlID: "CTL.A", AssetID: "bucket-1"},
		{ControlID: "CTL.B", AssetID: "bucket-1"},
		{ControlID: "CTL.A", AssetID: "bucket-2"},
		{ControlID: "CTL.B", AssetID: "bucket-2"},
	}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.A": {ID: "CTL.A", Severity: policy.SeverityHigh},
		"CTL.B": {ID: "CTL.B", Severity: policy.SeverityHigh},
	}

	suggestions := SuggestChains(failures, nil, lookup)

	if len(suggestions) != 1 {
		t.Fatalf("want 1 merged suggestion, got %d", len(suggestions))
	}
	if len(suggestions[0].AssetIDs) != 2 {
		t.Errorf("want 2 assets, got %d", len(suggestions[0].AssetIDs))
	}
}

func TestSuggestChains_SortBySeverityThenSize(t *testing.T) {
	failures := []FailingControl{
		{ControlID: "CTL.A", AssetID: asset.ID("b1")},
		{ControlID: "CTL.B", AssetID: asset.ID("b1")},
		{ControlID: "CTL.X", AssetID: asset.ID("b2")},
		{ControlID: "CTL.Y", AssetID: asset.ID("b2")},
		{ControlID: "CTL.Z", AssetID: asset.ID("b2")},
	}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.A": {ID: "CTL.A", Severity: policy.SeverityHigh},
		"CTL.B": {ID: "CTL.B", Severity: policy.SeverityHigh},
		"CTL.X": {ID: "CTL.X", Severity: policy.SeverityCritical},
		"CTL.Y": {ID: "CTL.Y", Severity: policy.SeverityHigh},
		"CTL.Z": {ID: "CTL.Z", Severity: policy.SeverityHigh},
	}

	suggestions := SuggestChains(failures, nil, lookup)

	if len(suggestions) != 2 {
		t.Fatalf("want 2 suggestions, got %d", len(suggestions))
	}
	if suggestions[0].MaxSev != policy.SeverityCritical {
		t.Error("first suggestion should be critical")
	}
	if len(suggestions[0].ControlIDs) != 3 {
		t.Errorf("critical suggestion should have 3 controls, got %d", len(suggestions[0].ControlIDs))
	}
}

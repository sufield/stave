package gaps

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func ctl(id string, sev policy.Severity, types []kernel.AssetType, paths ...string) policy.ControlDefinition {
	rules := make([]policy.PredicateRule, 0, len(paths))
	for _, p := range paths {
		rules = append(rules, policy.PredicateRule{
			Field: predicate.NewFieldPath(p),
			Op:    "eq",
			Value: policy.Bool(true),
		})
	}
	return policy.ControlDefinition{
		ID:                   kernel.ControlID(id),
		Severity:             sev,
		ApplicableAssetTypes: types,
		UnsafePredicate:      policy.UnsafePredicate{All: rules},
	}
}

func chain(id string, members ...string) policy.ChainDefinition {
	mids := make([]kernel.ControlID, len(members))
	for i, m := range members {
		mids[i] = kernel.ControlID(m)
	}
	return policy.ChainDefinition{
		ID:         kernel.ChainID(id),
		ControlIDs: mids,
	}
}

func obs(id, t string, props map[string]any) asset.Asset {
	return asset.Asset{
		ID:         asset.ID(id),
		Type:       kernel.AssetType(t),
		Properties: props,
	}
}

func snap(captured time.Time, assets ...asset.Asset) asset.Snapshot {
	return asset.Snapshot{CapturedAt: captured, Assets: assets}
}

func TestAnalyze_EmptyInputs(t *testing.T) {
	r := Analyze(nil, nil, nil, 0)
	if r.Summary.TotalGaps != 0 {
		t.Errorf("empty input → 0 gaps, got %d", r.Summary.TotalGaps)
	}
}

func TestAnalyze_AssetMissingTaggedProperty(t *testing.T) {
	c := ctl("CTL.S3.001", policy.SeverityHigh,
		[]kernel.AssetType{"aws_s3_bucket"},
		"properties.storage.tags.data_classification",
	)
	a1 := obs("b1", "aws_s3_bucket", map[string]any{"storage": map[string]any{"tags": map[string]any{"data_classification": "phi"}}})
	a2 := obs("b2", "aws_s3_bucket", map[string]any{"storage": map[string]any{"tags": map[string]any{}}})
	a3 := obs("b3", "aws_s3_bucket", map[string]any{})
	r := Analyze([]policy.ControlDefinition{c}, nil, []asset.Snapshot{snap(time.Now(), a1, a2, a3)}, 0)
	if r.Summary.TotalGaps != 1 {
		t.Fatalf("expected 1 gap, got %d", r.Summary.TotalGaps)
	}
	g := r.Gaps[0]
	if g.MissingCount != 2 || g.TotalCount != 3 {
		t.Errorf("missing/total: want 2/3, got %d/%d", g.MissingCount, g.TotalCount)
	}
	if !g.IsIntentProperty {
		t.Error("data_classification path should be tagged intent")
	}
	if g.Remediation.Type != RemediationTag {
		t.Errorf("expected tag remediation, got %s", g.Remediation.Type)
	}
}

func TestAnalyze_NullValueCountsAsMissing(t *testing.T) {
	// Brief rule #6: absent != false. Null IS absent.
	c := ctl("CTL.X.001", policy.SeverityHigh,
		[]kernel.AssetType{"aws_s3_bucket"},
		"properties.storage.tags.environment",
	)
	a := obs("b1", "aws_s3_bucket", map[string]any{"storage": map[string]any{"tags": map[string]any{"environment": nil}}})
	r := Analyze([]policy.ControlDefinition{c}, nil, []asset.Snapshot{snap(time.Now(), a)}, 0)
	if r.Summary.TotalGaps != 1 || r.Gaps[0].MissingCount != 1 {
		t.Errorf("null value should count as missing; got %+v", r.Summary)
	}
}

func TestAnalyze_PrioritizesIntentTagsFirst(t *testing.T) {
	intent := ctl("CTL.I.001", policy.SeverityMedium,
		[]kernel.AssetType{"aws_s3_bucket"},
		"properties.storage.tags.data_classification",
	)
	collectorCritical := ctl("CTL.C.001", policy.SeverityCritical,
		[]kernel.AssetType{"aws_s3_bucket"},
		"properties.storage.encryption.algorithm",
	)
	a := obs("b1", "aws_s3_bucket", map[string]any{})
	r := Analyze([]policy.ControlDefinition{intent, collectorCritical}, nil, []asset.Snapshot{snap(time.Now(), a)}, 0)
	if len(r.Gaps) != 2 {
		t.Fatalf("expected 2 gaps, got %d", len(r.Gaps))
	}
	// Intent tag must beat a critical-severity collector gap.
	if !r.Gaps[0].IsIntentProperty {
		t.Errorf("intent property should sort first; top gap is %s", r.Gaps[0].PropertyPath)
	}
}

func TestAnalyze_ChainBlockedCountFromMembership(t *testing.T) {
	c1 := ctl("CTL.A.001", policy.SeverityHigh,
		[]kernel.AssetType{"aws_s3_bucket"},
		"properties.storage.access.public_read",
	)
	c2 := ctl("CTL.B.001", policy.SeverityHigh,
		[]kernel.AssetType{"aws_s3_bucket"},
		"properties.storage.access.public_read", // same path
	)
	ch := chain("CHAIN.PUBLIC", "CTL.A.001", "CTL.B.001")
	a := obs("b1", "aws_s3_bucket", map[string]any{})
	r := Analyze(
		[]policy.ControlDefinition{c1, c2},
		[]policy.ChainDefinition{ch},
		[]asset.Snapshot{snap(time.Now(), a)},
		0,
	)
	if len(r.Gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(r.Gaps))
	}
	// Brief rule #7: deduplicate chain counts — chain reads
	// path via 2 members but counts once.
	if r.Gaps[0].ChainsBlockedCount != 1 {
		t.Errorf("chains_blocked: want 1 (dedupe), got %d", r.Gaps[0].ChainsBlockedCount)
	}
}

func TestAnalyze_IndeterminateControlsSurfacedInSummary(t *testing.T) {
	withType := ctl("CTL.A.001", policy.SeverityHigh,
		[]kernel.AssetType{"aws_s3_bucket"},
		"properties.storage.tags.x",
	)
	noType := ctl("CTL.B.001", policy.SeverityHigh, nil, "properties.unknown.path")
	a := obs("b1", "aws_s3_bucket", map[string]any{})
	r := Analyze([]policy.ControlDefinition{withType, noType}, nil, []asset.Snapshot{snap(time.Now(), a)}, 0)
	if r.Summary.IndeterminateControls != 1 {
		t.Errorf("expected 1 indeterminate control, got %d", r.Summary.IndeterminateControls)
	}
	if r.Summary.IndeterminateDisclaimer == "" {
		t.Errorf("disclaimer should be populated when indeterminate controls exist")
	}
}

func TestAnalyze_AssetTypeWithoutDeclarationProducesNoGaps(t *testing.T) {
	// Controls without applicable_asset_types contribute paths
	// to the per-control index but not to any per-type set.
	// An asset whose type has no declared paths yields zero
	// gaps even when observed.
	c := ctl("CTL.X.001", policy.SeverityHigh, nil, "properties.storage.tags.something")
	a := obs("b1", "aws_s3_bucket", map[string]any{})
	r := Analyze([]policy.ControlDefinition{c}, nil, []asset.Snapshot{snap(time.Now(), a)}, 0)
	if r.Summary.TotalGaps != 0 {
		t.Errorf("undeclared control should not surface a gap; got %d", r.Summary.TotalGaps)
	}
}

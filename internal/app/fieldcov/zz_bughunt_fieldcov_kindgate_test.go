package fieldcov

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestKindGate_ServerlessMSK_NotApplicable(t *testing.T) {
	// Provisioned-only control gates on streaming.kind == msk_cluster
	ctl := policy.ControlDefinition{
		ID:                   "CTL.MSK.VERSION.001",
		Severity:             policy.SeverityMedium,
		ApplicableAssetTypes: []kernel.AssetType{"aws_msk_cluster"},
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.streaming.kind"), Op: predicate.OpEq, Value: policy.NewOperand("msk_cluster")},
				{Field: predicate.NewFieldPath("properties.streaming.config.version_current"), Op: predicate.OpEq, Value: policy.NewOperand(false)},
			},
		},
	}

	// Snapshot has a serverless MSK cluster — different kind value
	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{
					Type: "aws_msk_cluster",
					Properties: map[string]any{
						"streaming": map[string]any{
							"kind": "msk_serverless_cluster",
							"auth": map[string]any{"iam_enabled": true},
						},
					},
				},
			},
		},
	}

	report := Analyze(AnalyzeInput{
		Controls:  []policy.ControlDefinition{ctl},
		Snapshots: snapshots,
	})

	if report.Summary.NotApplicable != 1 {
		t.Errorf("expected NotApplicable = 1, got %d (SilentRisk = %d)",
			report.Summary.NotApplicable, report.Summary.SilentRisk)
	}
	if report.Summary.SilentRisk != 0 {
		t.Errorf("serverless observation must not produce silent risk, got %d", report.Summary.SilentRisk)
	}
}

func TestKindGate_MatchingKind_StillEvaluable(t *testing.T) {
	// Same control, but observation has matching kind — should classify normally
	ctl := policy.ControlDefinition{
		ID:                   "CTL.MSK.VERSION.001",
		Severity:             policy.SeverityMedium,
		ApplicableAssetTypes: []kernel.AssetType{"aws_msk_cluster"},
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.streaming.kind"), Op: predicate.OpEq, Value: policy.NewOperand("msk_cluster")},
				{Field: predicate.NewFieldPath("properties.streaming.config.version_current"), Op: predicate.OpEq, Value: policy.NewOperand(false)},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{
					Type: "aws_msk_cluster",
					Properties: map[string]any{
						"streaming": map[string]any{
							"kind":   "msk_cluster",
							"config": map[string]any{"version_current": true},
						},
					},
				},
			},
		},
	}

	report := Analyze(AnalyzeInput{
		Controls:  []policy.ControlDefinition{ctl},
		Snapshots: snapshots,
	})

	if report.Summary.Evaluable != 1 {
		t.Errorf("matching kind should be evaluable, got Evaluable=%d, NotApplicable=%d, SilentRisk=%d",
			report.Summary.Evaluable, report.Summary.NotApplicable, report.Summary.SilentRisk)
	}
}

func TestKindGate_DifferentDomain_NotApplicable(t *testing.T) {
	// Control gates on storage.kind == msk_cluster, but the observation
	// only has streaming domain — storage.kind absent entirely.
	ctl := policy.ControlDefinition{
		ID:                   "CTL.MSK.ENCRYPT.CMK.001",
		Severity:             policy.SeverityMedium,
		ApplicableAssetTypes: []kernel.AssetType{"aws_msk_cluster"},
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.NewOperand("msk_cluster")},
				{Field: predicate.NewFieldPath("properties.storage.encryption.kms_key_origin"), Op: predicate.OpEq, Value: policy.NewOperand("AWS_KMS")},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{
					Type: "aws_msk_cluster",
					Properties: map[string]any{
						"streaming": map[string]any{
							"kind": "msk_serverless_cluster",
						},
					},
				},
			},
		},
	}

	report := Analyze(AnalyzeInput{
		Controls:  []policy.ControlDefinition{ctl},
		Snapshots: snapshots,
	})

	if report.Summary.NotApplicable != 1 {
		t.Errorf("absent storage.kind should be NotApplicable, got NotApplicable=%d, SilentRisk=%d",
			report.Summary.NotApplicable, report.Summary.SilentRisk)
	}
}

func TestKindGate_MixedKinds_Evaluable(t *testing.T) {
	// Control gates on msk_cluster. Snapshot has BOTH kinds.
	// Provisioned fields are present (from the provisioned asset).
	// Should be Evaluable — the control applies to at least one asset.
	ctl := policy.ControlDefinition{
		ID:                   "CTL.MSK.VERSION.001",
		Severity:             policy.SeverityMedium,
		ApplicableAssetTypes: []kernel.AssetType{"aws_msk_cluster"},
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.streaming.kind"), Op: predicate.OpEq, Value: policy.NewOperand("msk_cluster")},
				{Field: predicate.NewFieldPath("properties.streaming.config.version_current"), Op: predicate.OpEq, Value: policy.NewOperand(false)},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{
					Type: "aws_msk_cluster",
					Properties: map[string]any{
						"streaming": map[string]any{
							"kind": "msk_serverless_cluster",
							"auth": map[string]any{"iam_enabled": true},
						},
					},
				},
				{
					Type: "aws_msk_cluster",
					Properties: map[string]any{
						"streaming": map[string]any{
							"kind":   "msk_cluster",
							"config": map[string]any{"version_current": false},
						},
					},
				},
			},
		},
	}

	report := Analyze(AnalyzeInput{
		Controls:  []policy.ControlDefinition{ctl},
		Snapshots: snapshots,
	})

	if report.Summary.Evaluable != 1 {
		t.Errorf("mixed-kind snapshot should be evaluable (provisioned asset provides fields), got Evaluable=%d",
			report.Summary.Evaluable)
	}
}

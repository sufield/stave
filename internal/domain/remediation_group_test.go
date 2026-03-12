package domain

import (
	"testing"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
)

func TestBuildRemediationGroups(t *testing.T) {
	makeActions := func(paths ...string) []evaluation.RemediationAction {
		actions := make([]evaluation.RemediationAction, len(paths))
		for i, p := range paths {
			actions[i] = evaluation.RemediationAction{ActionType: "set", Path: p, Value: true}
		}
		return actions
	}

	makeFinding := func(controlID, assetID string, actions []evaluation.RemediationAction) remediation.Finding {
		ctlID := kernel.ControlID(controlID)
		resID := asset.ID(assetID)
		f := remediation.Finding{
			Finding: evaluation.Finding{
				ControlID: ctlID,
				AssetID:   resID,
				AssetType: kernel.TypeStorageBucket,
			},
		}
		if actions != nil {
			f.RemediationPlan = &evaluation.RemediationPlan{
				ID:      remediation.StablePlanID(ctlID, resID),
				Target:  evaluation.RemediationTarget{AssetID: resID, AssetType: kernel.TypeStorageBucket},
				Actions: actions,
			}
		}
		return f
	}

	sharedActions := makeActions(
		"security_posture.block_identity_public_access",
		"security_posture.block_resource_metadata_access",
		"security_posture.ignore_resource_metadata_access",
		"security_posture.restrict_resource_public_access",
	)

	differentActions := makeActions(
		"security_posture.encryption.enabled",
	)

	tests := []struct {
		name              string
		findings          []remediation.Finding
		wantNil           bool
		wantGroupCount    int
		wantControlCounts []int
	}{
		{
			name:     "no findings",
			findings: []remediation.Finding{},
			wantNil:  true,
		},
		{
			name: "no fix plans",
			findings: []remediation.Finding{
				makeFinding("CTL.S3.CONTROLS.001", "bucket-a", nil),
			},
			wantNil: true,
		},
		{
			name: "single finding with fix plan",
			findings: []remediation.Finding{
				makeFinding("CTL.S3.PUBLIC.001", "bucket-a", sharedActions),
			},
			wantGroupCount:    1,
			wantControlCounts: []int{1},
		},
		{
			name: "two findings same resource same actions",
			findings: []remediation.Finding{
				makeFinding("CTL.S3.PUBLIC.001", "bucket-a", sharedActions),
				makeFinding("CTL.S3.PUBLIC.002", "bucket-a", sharedActions),
			},
			wantGroupCount:    1,
			wantControlCounts: []int{2},
		},
		{
			name: "two findings same resource different actions",
			findings: []remediation.Finding{
				makeFinding("CTL.S3.PUBLIC.001", "bucket-a", sharedActions),
				makeFinding("CTL.S3.ENCRYPT.001", "bucket-a", differentActions),
			},
			wantGroupCount:    2,
			wantControlCounts: []int{1, 1},
		},
		{
			name: "two findings different resources same actions",
			findings: []remediation.Finding{
				makeFinding("CTL.S3.PUBLIC.001", "bucket-a", sharedActions),
				makeFinding("CTL.S3.PUBLIC.001", "bucket-b", sharedActions),
			},
			wantGroupCount:    2,
			wantControlCounts: []int{1, 1},
		},
		{
			name: "deterministic ordering by asset_id",
			findings: []remediation.Finding{
				makeFinding("CTL.S3.PUBLIC.001", "bucket-z", sharedActions),
				makeFinding("CTL.S3.PUBLIC.001", "bucket-a", sharedActions),
			},
			wantGroupCount:    2,
			wantControlCounts: []int{1, 1},
		},
		{
			name: "contributing controls sorted lexicographically",
			findings: []remediation.Finding{
				makeFinding("CTL.S3.PUBLIC.002", "bucket-a", sharedActions),
				makeFinding("CTL.S3.PUBLIC.001", "bucket-a", sharedActions),
			},
			wantGroupCount:    1,
			wantControlCounts: []int{2},
		},
		{
			name: "mixed fix plan and no fix plan",
			findings: []remediation.Finding{
				makeFinding("CTL.S3.PUBLIC.001", "bucket-a", sharedActions),
				makeFinding("CTL.S3.CONTROLS.001", "bucket-a", nil),
				makeFinding("CTL.S3.PUBLIC.002", "bucket-a", sharedActions),
			},
			wantGroupCount:    1,
			wantControlCounts: []int{2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups := remediation.BuildGroups(tt.findings)

			if tt.wantNil {
				if groups != nil {
					t.Fatalf("expected nil, got %d groups", len(groups))
				}
				return
			}

			if len(groups) != tt.wantGroupCount {
				t.Fatalf("expected %d groups, got %d", tt.wantGroupCount, len(groups))
			}

			for i, wantCount := range tt.wantControlCounts {
				if len(groups[i].ContributingControls) != wantCount {
					t.Errorf("group[%d]: expected %d contributing controls, got %d",
						i, wantCount, len(groups[i].ContributingControls))
				}
			}
		})
	}
}

func TestBuildRemediationGroups_DeterministicOrdering(t *testing.T) {
	actions := []evaluation.RemediationAction{
		{ActionType: "set", Path: "security_posture.block_identity_public_access", Value: true},
	}
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.S3.PUBLIC.001",
				AssetID:   "bucket-z",
				AssetType: kernel.TypeStorageBucket,
			},
			RemediationPlan: &evaluation.RemediationPlan{ID: "fix-z", Target: evaluation.RemediationTarget{AssetID: asset.ID("bucket-z")}, Actions: actions},
		},
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.S3.PUBLIC.001",
				AssetID:   "bucket-a",
				AssetType: kernel.TypeStorageBucket,
			},
			RemediationPlan: &evaluation.RemediationPlan{ID: "fix-a", Target: evaluation.RemediationTarget{AssetID: asset.ID("bucket-a")}, Actions: actions},
		},
	}

	groups := remediation.BuildGroups(findings)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].AssetID != "bucket-a" {
		t.Errorf("expected first group asset_id = bucket-a, got %s", groups[0].AssetID)
	}
	if groups[1].AssetID != "bucket-z" {
		t.Errorf("expected second group asset_id = bucket-z, got %s", groups[1].AssetID)
	}
}

func TestBuildRemediationGroups_ContributingControlsSorted(t *testing.T) {
	actions := []evaluation.RemediationAction{
		{ActionType: "set", Path: "security_posture.block_identity_public_access", Value: true},
	}
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.S3.PUBLIC.003",
				AssetID:   "bucket-a",
				AssetType: kernel.TypeStorageBucket,
			},
			RemediationPlan: &evaluation.RemediationPlan{ID: "fix-1", Target: evaluation.RemediationTarget{AssetID: asset.ID("bucket-a")}, Actions: actions},
		},
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.S3.PUBLIC.001",
				AssetID:   "bucket-a",
				AssetType: kernel.TypeStorageBucket,
			},
			RemediationPlan: &evaluation.RemediationPlan{ID: "fix-2", Target: evaluation.RemediationTarget{AssetID: asset.ID("bucket-a")}, Actions: actions},
		},
	}

	groups := remediation.BuildGroups(findings)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	invs := groups[0].ContributingControls
	if len(invs) != 2 {
		t.Fatalf("expected 2 controls, got %d", len(invs))
	}
	if invs[0] != "CTL.S3.PUBLIC.001" {
		t.Errorf("expected first control = CTL.S3.PUBLIC.001, got %s", invs[0])
	}
	if invs[1] != "CTL.S3.PUBLIC.003" {
		t.Errorf("expected second control = CTL.S3.PUBLIC.003, got %s", invs[1])
	}
}

func TestBuildRemediationGroups_StableGroupID(t *testing.T) {
	actions := []evaluation.RemediationAction{
		{ActionType: "set", Path: "security_posture.block_identity_public_access", Value: true},
	}
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.S3.PUBLIC.001",
				AssetID:   "bucket-a",
				AssetType: kernel.TypeStorageBucket,
			},
			RemediationPlan: &evaluation.RemediationPlan{ID: "fix-original", Target: evaluation.RemediationTarget{AssetID: asset.ID("bucket-a")}, Actions: actions},
		},
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.S3.PUBLIC.002",
				AssetID:   "bucket-a",
				AssetType: kernel.TypeStorageBucket,
			},
			RemediationPlan: &evaluation.RemediationPlan{ID: "fix-other", Target: evaluation.RemediationTarget{AssetID: asset.ID("bucket-a")}, Actions: actions},
		},
	}

	groups := remediation.BuildGroups(findings)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}

	// The group's fix plan ID should be a stable hash, not the original finding's fix plan ID
	if groups[0].RemediationPlan.ID == "fix-original" || groups[0].RemediationPlan.ID == "fix-other" {
		t.Errorf("group fix plan ID should be a new stable hash, got %s", groups[0].RemediationPlan.ID)
	}

	// Running again should produce the same ID
	groups2 := remediation.BuildGroups(findings)
	if groups[0].RemediationPlan.ID != groups2[0].RemediationPlan.ID {
		t.Errorf("group fix plan ID not stable: %s vs %s", groups[0].RemediationPlan.ID, groups2[0].RemediationPlan.ID)
	}
}

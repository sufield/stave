package domain

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
)

func TestBuildRemediationPlan_S3Public(t *testing.T) {
	planner := remediation.NewPlanner()
	finding := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID: kernel.ControlID("CTL.S3.PUBLIC.001"),
			AssetID:   asset.ID("bucket-a"),
			AssetType: kernel.TypeStorageBucket,
		},
	}

	plan := planner.PlanFor(finding)
	if plan == nil {
		t.Fatal("PlanFor() = nil, want non-nil plan")
	}

	wantID := remediation.StablePlanID(finding.ControlID, finding.AssetID)
	if plan.ID != wantID {
		t.Fatalf("plan.ID = %q, want %q", plan.ID, wantID)
	}
	if plan.Target.AssetID != finding.AssetID {
		t.Fatalf("plan.Target.AssetID = %q, want %q", plan.Target.AssetID, finding.AssetID)
	}

	wantActionPaths := []string{
		"security_posture.block_identity_public_access",
		"security_posture.block_resource_metadata_access",
		"security_posture.ignore_resource_metadata_access",
		"security_posture.restrict_resource_public_access",
	}
	gotPaths := make([]string, len(plan.Actions))
	for i := range plan.Actions {
		gotPaths[i] = plan.Actions[i].Path
	}
	if !reflect.DeepEqual(gotPaths, wantActionPaths) {
		t.Fatalf("action paths = %v, want %v", gotPaths, wantActionPaths)
	}
}

func TestBuildRemediationPlan_UnknownClass(t *testing.T) {
	planner := remediation.NewPlanner()
	finding := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID: kernel.ControlID("CTL.CUSTOM.001"),
			AssetID:   asset.ID("res-1"),
			AssetType: kernel.TypeStorageBucket,
		},
	}

	plan := planner.PlanFor(finding)
	if plan != nil {
		t.Fatalf("PlanFor() = %+v, want nil for unknown control class", plan)
	}
}

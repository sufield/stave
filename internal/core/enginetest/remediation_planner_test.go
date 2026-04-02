package enginetest

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBuildRemediationPlan_S3Public(t *testing.T) {
	planner := remediation.NewPlanner(testIDGen())
	finding := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID: kernel.ControlID("CTL.S3.PUBLIC.001"),
			AssetID:   asset.ID("bucket-a"),
			AssetType: kernel.AssetType("storage_bucket"),
		},
	}

	plan := planner.PlanFor(finding)
	if plan == nil {
		t.Fatal("PlanFor() = nil, want non-nil plan")
	}

	wantID := remediation.StablePlanID(testIDGen(), finding.ControlID, finding.AssetID)
	if plan.ID != wantID {
		t.Fatalf("plan.ID = %q, want %q", plan.ID, wantID)
	}
	if plan.Target.AssetID != finding.AssetID {
		t.Fatalf("plan.Target.AssetID = %q, want %q", plan.Target.AssetID, finding.AssetID)
	}

	wantActionPaths := []string{
		"security_posture.block_identity_public_access",
		"security_posture.block_resource_metadata_access",
		"security_posture.block_resource_public_access",
		"security_posture.ignore_resource_metadata_access",
	}
	gotPaths := make([]string, len(plan.Actions))
	for i := range plan.Actions {
		gotPaths[i] = plan.Actions[i].Path.String()
	}
	if !reflect.DeepEqual(gotPaths, wantActionPaths) {
		t.Fatalf("action paths = %v, want %v", gotPaths, wantActionPaths)
	}
}

func TestBuildRemediationPlan_UnknownClass(t *testing.T) {
	planner := remediation.NewPlanner(testIDGen())
	finding := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID: kernel.ControlID("CTL.CUSTOM.001"),
			AssetID:   asset.ID("res-1"),
			AssetType: kernel.AssetType("storage_bucket"),
		},
	}

	plan := planner.PlanFor(finding)
	if plan != nil {
		t.Fatalf("PlanFor() = %+v, want nil for unknown control class", plan)
	}
}

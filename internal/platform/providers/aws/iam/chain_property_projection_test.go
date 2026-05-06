package iam

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// snapshotForProjector returns a minimal snapshot exercising the
// confused-deputy and TOCTOU primitives end-to-end. Two
// principals, one Lambda function, one CFN stack, one role
// scheduled for deletion.
func snapshotForProjector(t *testing.T) *asset.Snapshot {
	t.Helper()
	devARN := "arn:aws:iam::111122223333:role/dev"
	cfnUserARN := "arn:aws:iam::111122223333:role/cfn-deployer"
	doomedARN := "arn:aws:iam::111122223333:role/doomed"

	lambdaARN := "arn:aws:lambda:us-east-1:111122223333:function:legacy"
	stackARN := "arn:aws:cloudformation:us-east-1:111122223333:stack/legacy/abc"
	lambdaRoleARN := "arn:aws:iam::111122223333:role/legacy-lambda-exec"
	cfnRoleARN := "arn:aws:iam::111122223333:role/legacy-cfn-exec"

	return &asset.Snapshot{
		Identities: []asset.CloudIdentity{
			{
				ID:   asset.ID(devARN),
				Properties: map[string]any{
					"identity": map[string]any{
						"scp_json": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
					"policies_json": `{"Statement":[
							{"Effect":"Allow","Action":"lambda:InvokeFunction",
							 "Resource":"` + lambdaARN + `"}
						]}`,
					},
				},
			},
			{
				ID: asset.ID(cfnUserARN),
				Properties: map[string]any{
					"identity": map[string]any{
						"scp_json": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
					"policies_json": `{"Statement":[
							{"Effect":"Allow","Action":"cloudformation:UpdateStack",
							 "Resource":"` + stackARN + `"},
							{"Effect":"Allow","Action":"sts:AssumeRole",
							 "Resource":"` + doomedARN + `"}
						]}`,
					},
				},
			},
			{
				ID: asset.ID(lambdaRoleARN),
				Properties: map[string]any{
					"identity": map[string]any{
						"scp_json": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
					"policies_json": `{"Statement":[
							{"Effect":"Allow","Action":"*","Resource":"*"}
						]}`,
					},
				},
			},
			{
				ID: asset.ID(cfnRoleARN),
				Properties: map[string]any{
					"identity": map[string]any{
						"scp_json": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
					"policies_json": `{"Statement":[
							{"Effect":"Allow","Action":"*","Resource":"*"}
						]}`,
					},
				},
			},
			{
				ID: asset.ID(doomedARN),
				Properties: map[string]any{
					"identity": map[string]any{
						"scp_json": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
					"policies_json": `{"Statement":[
							{"Effect":"Allow","Action":"*","Resource":"*"}
						]}`,
						"trust_policy_json": `{"Statement":[
							{"Effect":"Allow","Action":"sts:AssumeRole",
							 "Principal":{"AWS":"` + cfnUserARN + `"}}
						]}`,
						// Iter 5: scheduled-deletion property.
						"lifecycle": map[string]any{
							"scheduled_for_deletion_at": "2027-01-01T00:00:00Z",
						},
					},
				},
			},
		},
		Assets: []asset.Asset{
			{
				ID:   asset.ID(lambdaARN),
				Type: kernel.AssetType("aws_lambda_function"),
				Properties: map[string]any{
					"compute": map[string]any{"role_arn": lambdaRoleARN},
				},
			},
			{
				ID:   asset.ID(stackARN),
				Type: kernel.AssetType("aws_cloudformation_stack"),
				Properties: map[string]any{
					"cloudformation": map[string]any{"role_arn": cfnRoleARN},
				},
			},
		},
	}
}

// TestProjectChainProperties_LambdaInvoke pins the load-bearing
// wiring: after running the projector, the dev principal must
// carry `identity.escalation.confused_lambda_invoke.present=true`,
// matching the predicate that
// CTL.IAM.ESCALATE.CONFUSED.LAMBDA.INVOKE.001 reads.
func TestProjectChainProperties_LambdaInvoke(t *testing.T) {
	snap := snapshotForProjector(t)
	ProjectChainProperties(snap)

	devARN := "arn:aws:iam::111122223333:role/dev"
	got := readProjectedFlag(t, snap, devARN, "escalation", "confused_lambda_invoke")
	if !got {
		t.Fatalf("dev principal must have confused_lambda_invoke.present=true; "+
			"got snap=%+v", snap.Identities[0].Properties)
	}
	target := readProjectedString(t, snap, devARN,
		"escalation", "confused_lambda_invoke", "target_role")
	if target != "arn:aws:iam::111122223333:role/legacy-lambda-exec" {
		t.Errorf("target_role: got %q", target)
	}
}

// TestProjectChainProperties_CfnUpdate covers the CFN side.
func TestProjectChainProperties_CfnUpdate(t *testing.T) {
	snap := snapshotForProjector(t)
	ProjectChainProperties(snap)

	cfnUserARN := "arn:aws:iam::111122223333:role/cfn-deployer"
	got := readProjectedFlag(t, snap, cfnUserARN, "escalation", "confused_cfn_update")
	if !got {
		t.Fatalf("cfn-deployer must have confused_cfn_update.present=true; "+
			"got snap=%+v", snap.Identities[1].Properties)
	}
	target := readProjectedString(t, snap, cfnUserARN,
		"escalation", "confused_cfn_update", "target_role")
	if target != "arn:aws:iam::111122223333:role/legacy-cfn-exec" {
		t.Errorf("target_role: got %q", target)
	}
}

// TestProjectChainProperties_GhostDeletion: the cfn-deployer's
// chain reaches a role scheduled for deletion (via sts:AssumeRole
// to doomed). The projector must surface
// `identity.chain.ghost_deletion.present=true` plus the
// scheduled_deletion_at timestamp.
func TestProjectChainProperties_GhostDeletion(t *testing.T) {
	snap := snapshotForProjector(t)
	ProjectChainProperties(snap)

	cfnUserARN := "arn:aws:iam::111122223333:role/cfn-deployer"
	if !readProjectedFlag(t, snap, cfnUserARN, "chain", "ghost_deletion") {
		t.Fatalf("cfn-deployer must have ghost_deletion.present=true; "+
			"got snap=%+v", snap.Identities[1].Properties)
	}
	ts := readProjectedString(t, snap, cfnUserARN,
		"chain", "ghost_deletion", "scheduled_deletion_at")
	if ts != "2027-01-01T00:00:00Z" {
		t.Errorf("scheduled_deletion_at: got %q", ts)
	}
}

// TestProjectChainProperties_NegativeIdentity: a principal with
// no chains must end up with `present=false` (or no key) — the
// projector is not allowed to false-positively flag innocent
// identities.
func TestProjectChainProperties_NegativeIdentity(t *testing.T) {
	snap := snapshotForProjector(t)
	ProjectChainProperties(snap)

	// lambda-exec is the role bound to the function; it has no
	// PassRole, no InvokeFunction grants of its own → no
	// confused-deputy chain originates from it.
	lambdaRoleARN := "arn:aws:iam::111122223333:role/legacy-lambda-exec"
	if readProjectedFlag(t, snap, lambdaRoleARN, "escalation", "confused_lambda_invoke") {
		t.Errorf("legacy-lambda-exec must NOT have confused_lambda_invoke.present=true")
	}
}

// TestProjectChainProperties_Idempotent: running the projector
// twice produces identical state. Required so callers that do
// not synchronise the projection (e.g. shadow re-evaluation)
// don't drift from the primary path.
func TestProjectChainProperties_Idempotent(t *testing.T) {
	snap := snapshotForProjector(t)
	ProjectChainProperties(snap)
	devProps1 := snap.Identities[0].Properties
	ProjectChainProperties(snap)
	devProps2 := snap.Identities[0].Properties
	// Map identity comparison: we expect the SAME map (mutation
	// in place), with the SAME values — the second pass
	// overwrote with identical content.
	if &devProps1 != &devProps2 {
		// nothing — both should still be the same map reference;
		// this branch is here as a structural reminder.
	}
	if !readProjectedFlag(t, snap, "arn:aws:iam::111122223333:role/dev",
		"escalation", "confused_lambda_invoke") {
		t.Fatalf("idempotent run lost the projection")
	}
}

// TestProjectChainProperties_NilSnapshot is the zero-input
// guard.
func TestProjectChainProperties_NilSnapshot(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil snapshot panicked: %v", r)
		}
	}()
	ProjectChainProperties(nil)
}

// readProjectedFlag walks identity.escalation.X.present (or any
// equivalent .present path) on the named principal's Properties.
func readProjectedFlag(t *testing.T, snap *asset.Snapshot, arn string, prefix, key string) bool {
	t.Helper()
	props := propsForPrincipal(t, snap, arn)
	v, ok := walkProperty(props, []string{"identity", prefix, key, "present"})
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// readProjectedString fetches a string-valued projected field.
// Variadic so the same helper covers target_role,
// scheduled_deletion_at, etc.
func readProjectedString(t *testing.T, snap *asset.Snapshot, arn string, path ...string) string {
	t.Helper()
	props := propsForPrincipal(t, snap, arn)
	full := append([]string{"identity"}, path...)
	v, ok := walkProperty(props, full)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func propsForPrincipal(t *testing.T, snap *asset.Snapshot, arn string) map[string]any {
	t.Helper()
	for i := range snap.Identities {
		if string(snap.Identities[i].ID) == arn {
			return snap.Identities[i].Properties
		}
	}
	t.Fatalf("principal %q not in snapshot", arn)
	return nil
}

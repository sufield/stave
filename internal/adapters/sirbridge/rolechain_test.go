package sirbridge

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/sir"
)

// crossAccountSnapshot is a minimal but realistic snapshot whose
// identity properties carry the JSON shape iam.BuildResolutionInput
// expects: identity.policies_json, identity.trust_policy_json,
// optionally identity.scp_json / identity.boundary_json.
//
// Topology: AppRole (account 111) is granted sts:AssumeRole on
// CrossAdmin (account 444). CrossAdmin's trust policy allows
// AppRole to assume it. Result: a 1-hop chain ending at the
// cross-account admin role.
func crossAccountSnapshot(ts time.Time) asset.Snapshot {
	appRolePolicies := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "sts:AssumeRole",
			"Resource": "arn:aws:iam::444455556666:role/CrossAdmin"
		}]
	}`

	crossAdminPolicies := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "*",
			"Resource": "*"
		}]
	}`

	crossAdminTrust := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "sts:AssumeRole",
			"Resource": "arn:aws:iam::111122223333:role/AppRole"
		}]
	}`

	// permissiveSCP marks resolution complete by satisfying the
	// SCPPresent invariant that iam.Resolve enforces. Production
	// snapshots from extractors always supply an SCP (even an
	// empty/permissive one) — the bridge inherits that contract.
	permissiveSCP := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "*",
			"Resource": "*"
		}]
	}`

	return asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: ts,
		Identities: []asset.CloudIdentity{
			{
				ID:     asset.ID("arn:aws:iam::111122223333:role/AppRole"),
				Type:   kernel.AssetType("aws_iam_role"),
				Vendor: kernel.Vendor("aws"),
				Properties: map[string]any{
					"identity": map[string]any{
						"policies_json": appRolePolicies,
						"scp_json":      permissiveSCP,
					},
				},
			},
			{
				ID:     asset.ID("arn:aws:iam::444455556666:role/CrossAdmin"),
				Type:   kernel.AssetType("aws_iam_role"),
				Vendor: kernel.Vendor("aws"),
				Properties: map[string]any{
					"identity": map[string]any{
						"policies_json":     crossAdminPolicies,
						"trust_policy_json": crossAdminTrust,
						"scp_json":          permissiveSCP,
					},
				},
			},
		},
	}
}

func TestAWSRoleChainSource_CrossAccountChainSurfaces(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	snap := crossAccountSnapshot(now.Add(-time.Hour))

	src := NewAWSRoleChainSource()
	chains, err := src.RoleChains([]asset.Snapshot{snap})
	if err != nil {
		t.Fatalf("RoleChains: %v", err)
	}

	appRoleChains := chains[asset.ID("arn:aws:iam::111122223333:role/AppRole")]
	if len(appRoleChains) == 0 {
		t.Fatalf("expected AppRole to have at least one chain; got 0")
	}

	// Find the chain that ends at the cross-account admin role.
	var found *sir.RoleChainFact
	for i := range appRoleChains {
		if appRoleChains[i].FinalRoleARN == "arn:aws:iam::444455556666:role/CrossAdmin" {
			found = &appRoleChains[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no chain reached CrossAdmin; got: %+v", appRoleChains)
	}
	if len(found.Hops) != 1 {
		t.Fatalf("expected 1 hop, got %d (%+v)", len(found.Hops), found.Hops)
	}
	if !found.Hops[0].CrossAccount {
		t.Errorf("hop must be flagged CrossAccount=true (account 111 → 444): %+v", found.Hops[0])
	}
	if found.TerminationReason != "normal" {
		t.Errorf("expected TerminationReason=normal, got %q", found.TerminationReason)
	}
}

func TestAWSRoleChainSource_FlowsThroughBuilderToJSON(t *testing.T) {
	// Drive the bridge through sir.Builder and verify the chain
	// surfaces in the marshaled SIR document. This is the closest
	// unit test to the success criterion "stave export-sir for a
	// cross-account fixture now shows the transitive role hops in
	// the JSON" — the CLI is Iteration 1.4, but the wiring it
	// will use must already work.
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	snap := crossAccountSnapshot(now.Add(-time.Hour))

	b := sir.NewBuilder(sir.WithRoleChainSource(NewAWSRoleChainSource()))
	doc, err := b.Build(
		[]controldef.ControlDefinition{},
		[]asset.Snapshot{snap},
		now,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(encoded)
	// The cross-account final role must appear in the output.
	if !strings.Contains(body, `"arn:aws:iam::444455556666:role/CrossAdmin"`) {
		t.Errorf("SIR JSON missing cross-account final role: %s", body)
	}
	// The cross-account hop flag must serialize as true.
	if !strings.Contains(body, `"cross_account":true`) {
		t.Errorf("SIR JSON missing cross_account=true flag: %s", body)
	}
}

func TestAWSRoleChainSource_NoIdentitiesYieldsEmptyMap(t *testing.T) {
	src := NewAWSRoleChainSource()
	got, err := src.RoleChains([]asset.Snapshot{
		{Source: asset.SourceDeployed, CapturedAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatalf("RoleChains: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %+v", got)
	}
}

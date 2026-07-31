package iam

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

const allowAllSCP = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

func TestReconProjection_FullRecon(t *testing.T) {
	id := &asset.CloudIdentity{
		ID:   "arn:aws:iam::111122223333:user/attacker-full",
		Type: "aws_iam_user",
		Properties: map[string]any{
			"identity": map[string]any{
				"kind":          "user",
				"scp_json":      allowAllSCP,
				"policies_json": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListUsers","iam:ListRoles","iam:GetUserPolicy","iam:GetPolicyVersion","iam:ListAttachedUserPolicies","iam:SimulatePrincipalPolicy","iam:CreateLoginProfile","iam:GetLoginProfile","iam:ListAccessKeys"],"Resource":"*"}]}`,
			},
		},
	}
	snap := &asset.Snapshot{Identities: []asset.CloudIdentity{*id}}
	ProjectChainProperties(snap)

	recon := getRecon(t, snap.Identities[0].Properties)
	assertBool(t, recon, "can_enumerate_principals", true)
	assertBool(t, recon, "can_read_principal_policies", true)
	assertBool(t, recon, "can_simulate_policies", true)
	assertBool(t, recon, "can_read_credentials", true)
	assertString(t, recon, "victim_selection_capability", "full")
}

func TestReconProjection_PartialRecon(t *testing.T) {
	id := &asset.CloudIdentity{
		ID:   "arn:aws:iam::111122223333:user/attacker-partial",
		Type: "aws_iam_user",
		Properties: map[string]any{
			"identity": map[string]any{
				"kind":          "user",
				"scp_json":      allowAllSCP,
				"policies_json": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListUsers","iam:ListRoles","iam:GetUserPolicy","iam:GetPolicyVersion","iam:ListAttachedUserPolicies","iam:CreateLoginProfile"],"Resource":"*"}]}`,
			},
		},
	}
	snap := &asset.Snapshot{Identities: []asset.CloudIdentity{*id}}
	ProjectChainProperties(snap)

	recon := getRecon(t, snap.Identities[0].Properties)
	assertBool(t, recon, "can_enumerate_principals", true)
	assertBool(t, recon, "can_read_principal_policies", true)
	assertBool(t, recon, "can_simulate_policies", false)
	assertString(t, recon, "victim_selection_capability", "partial")
}

func TestReconProjection_BlindEscalation(t *testing.T) {
	id := &asset.CloudIdentity{
		ID:   "arn:aws:iam::111122223333:user/attacker-blind",
		Type: "aws_iam_user",
		Properties: map[string]any{
			"identity": map[string]any{
				"kind":          "user",
				"scp_json":      allowAllSCP,
				"policies_json": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateLoginProfile"],"Resource":"*"}]}`,
			},
		},
	}
	snap := &asset.Snapshot{Identities: []asset.CloudIdentity{*id}}
	ProjectChainProperties(snap)

	recon := getRecon(t, snap.Identities[0].Properties)
	assertBool(t, recon, "can_enumerate_principals", false)
	assertBool(t, recon, "can_read_principal_policies", false)
	assertString(t, recon, "victim_selection_capability", "blind")
}

func TestReconProjection_NoCapability(t *testing.T) {
	id := &asset.CloudIdentity{
		ID:   "arn:aws:iam::111122223333:user/user-clean",
		Type: "aws_iam_user",
		Properties: map[string]any{
			"identity": map[string]any{
				"kind":          "user",
				"scp_json":      allowAllSCP,
				"policies_json": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::my-bucket/*"}]}`,
			},
		},
	}
	snap := &asset.Snapshot{Identities: []asset.CloudIdentity{*id}}
	ProjectChainProperties(snap)

	recon := getRecon(t, snap.Identities[0].Properties)
	assertBool(t, recon, "can_enumerate_principals", false)
	assertBool(t, recon, "can_simulate_policies", false)
	assertString(t, recon, "victim_selection_capability", "none")
}

func TestReconProjection_AssetOnly_FullRecon(t *testing.T) {
	a := asset.Asset{
		ID:     "arn:aws:iam::111122223333:user/attacker-full",
		Type:   "aws_iam_user",
		Vendor: "aws",
		Properties: map[string]any{
			"identity": map[string]any{
				"kind":          "user",
				"scp_json":      allowAllSCP,
				"policies_json": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListUsers","iam:ListRoles","iam:GetUserPolicy","iam:GetPolicyVersion","iam:ListAttachedUserPolicies","iam:SimulatePrincipalPolicy","iam:CreateLoginProfile","iam:GetLoginProfile","iam:ListAccessKeys"],"Resource":"*"}]}`,
			},
		},
	}
	snap := &asset.Snapshot{Assets: []asset.Asset{a}}
	ProjectChainProperties(snap)

	recon := getReconFromAsset(t, snap.Assets[0].Properties)
	assertBool(t, recon, "can_enumerate_principals", true)
	assertBool(t, recon, "can_read_principal_policies", true)
	assertBool(t, recon, "can_simulate_policies", true)
	assertBool(t, recon, "can_read_credentials", true)
	assertString(t, recon, "victim_selection_capability", "full")
}

func TestReconProjection_AssetOnly_PartialRecon(t *testing.T) {
	a := asset.Asset{
		ID:     "arn:aws:iam::111122223333:user/attacker-partial",
		Type:   "aws_iam_user",
		Vendor: "aws",
		Properties: map[string]any{
			"identity": map[string]any{
				"kind":          "user",
				"scp_json":      allowAllSCP,
				"policies_json": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListUsers","iam:ListRoles","iam:GetUserPolicy","iam:GetPolicyVersion","iam:ListAttachedUserPolicies","iam:CreateLoginProfile"],"Resource":"*"}]}`,
			},
		},
	}
	snap := &asset.Snapshot{Assets: []asset.Asset{a}}
	ProjectChainProperties(snap)

	recon := getReconFromAsset(t, snap.Assets[0].Properties)
	assertBool(t, recon, "can_enumerate_principals", true)
	assertBool(t, recon, "can_read_principal_policies", true)
	assertBool(t, recon, "can_simulate_policies", false)
	assertString(t, recon, "victim_selection_capability", "partial")
}

func TestReconProjection_MultiAsset_NoIdentities(t *testing.T) {
	snap := &asset.Snapshot{
		Assets: []asset.Asset{
			{
				ID:     "arn:aws:iam::111122223333:user/attacker-full",
				Type:   "aws_iam_user",
				Vendor: "aws",
				Properties: map[string]any{
					"identity": map[string]any{
						"kind":          "user",
						"scp_json":      allowAllSCP,
						"policies_json": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListUsers","iam:ListRoles","iam:GetUserPolicy","iam:GetPolicyVersion","iam:ListAttachedUserPolicies","iam:SimulatePrincipalPolicy"],"Resource":"*"}]}`,
					},
				},
			},
			{
				ID:     "arn:aws:iam::111122223333:user/user-safe",
				Type:   "aws_iam_user",
				Vendor: "aws",
				Properties: map[string]any{
					"identity": map[string]any{
						"kind":          "user",
						"scp_json":      allowAllSCP,
						"policies_json": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::bucket/*"}]}`,
					},
				},
			},
		},
	}
	ProjectChainProperties(snap)

	recon0 := getReconFromAsset(t, snap.Assets[0].Properties)
	assertString(t, recon0, "victim_selection_capability", "full")

	recon1 := getReconFromAsset(t, snap.Assets[1].Properties)
	assertString(t, recon1, "victim_selection_capability", "none")
}

func getReconFromAsset(t *testing.T, props map[string]any) map[string]any {
	t.Helper()
	identity, ok := props["identity"].(map[string]any)
	if !ok {
		t.Fatal("missing identity in asset properties")
	}
	recon, ok := identity["reconnaissance"].(map[string]any)
	if !ok {
		t.Fatal("missing identity.reconnaissance in asset properties")
	}
	return recon
}

func getRecon(t *testing.T, props map[string]any) map[string]any {
	t.Helper()
	identity, ok := props["identity"].(map[string]any)
	if !ok {
		t.Fatal("missing identity")
	}
	recon, ok := identity["reconnaissance"].(map[string]any)
	if !ok {
		t.Fatal("missing identity.reconnaissance")
	}
	return recon
}

func assertBool(t *testing.T, m map[string]any, key string, expected bool) {
	t.Helper()
	v, ok := m[key].(bool)
	if !ok {
		t.Fatalf("%s: not a bool, got %T (%v)", key, m[key], m[key])
	}
	if v != expected {
		t.Errorf("%s: got %v, want %v", key, v, expected)
	}
}

func assertString(t *testing.T, m map[string]any, key string, expected string) {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("%s: not a string, got %T (%v)", key, m[key], m[key])
	}
	if v != expected {
		t.Errorf("%s: got %q, want %q", key, v, expected)
	}
}

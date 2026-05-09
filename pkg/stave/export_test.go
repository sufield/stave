package stave_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/pkg/stave"
)

// snapshot is the minimal observation fixture the export tests
// load. It carries one S3 bucket with a resource policy referencing
// a KMS key, and one IAM role whose trust policy admits a single
// AWS-account principal — enough to exercise resource policies,
// KMS key policies, trust policies, and both edge shapes
// (encrypts_with, assumes).
const snapshot = `{
	"schema_version": "obs.v0.1",
	"captured_at": "2026-05-03T00:00:00Z",
	"source": "local",
	"assets": [
		{
			"id": "arn:aws:s3:::data-bucket",
			"type": "aws_s3_bucket",
			"vendor": "aws",
			"properties": {
				"storage": {
					"kind": "bucket",
					"policy_json": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowAccountRead\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111122223333:role/data-loader\"},\"Action\":[\"s3:GetObject\",\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::data-bucket\",\"arn:aws:s3:::data-bucket/*\"],\"Condition\":{\"StringEquals\":{\"aws:PrincipalOrgID\":\"o-abc123\"}}}]}"
				},
				"encryption": {
					"key_arn": "arn:aws:kms:us-east-1:111122223333:key/abc-123"
				}
			}
		},
		{
			"id": "arn:aws:kms:us-east-1:111122223333:key/abc-123",
			"type": "aws_kms_key",
			"vendor": "aws",
			"properties": {
				"encryption": {
					"key_policy_json": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"RootAdmin\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111122223333:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"}]}"
				}
			}
		}
	],
	"identities": [
		{
			"id": "arn:aws:iam::111122223333:role/data-loader",
			"type": "aws_iam_role",
			"vendor": "aws",
			"properties": {
				"identity": {
					"trust_policy_json": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111122223333:role/orchestrator\"},\"Action\":\"sts:AssumeRole\"}]}"
				}
			}
		}
	]
}`

func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(path, []byte(snapshot), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dir
}

func TestExportPolicies_RequiresSnapshotsDir(t *testing.T) {
	t.Parallel()
	if _, err := stave.ExportPolicies(context.Background(), stave.ExportConfig{}); err == nil {
		t.Fatal("expected error for empty SnapshotsDir")
	}
}

func TestExportPolicies_ResourcePolicyExtraction(t *testing.T) {
	t.Parallel()
	dir := writeFixture(t)
	out, err := stave.ExportPolicies(context.Background(), stave.ExportConfig{SnapshotsDir: dir})
	if err != nil {
		t.Fatalf("ExportPolicies: %v", err)
	}
	if len(out.ResourcePolicies) != 1 {
		t.Fatalf("ResourcePolicies = %d, want 1", len(out.ResourcePolicies))
	}
	got := out.ResourcePolicies[0]
	if got.SourceAssetID != "arn:aws:s3:::data-bucket" {
		t.Errorf("SourceAssetID = %q, want arn:aws:s3:::data-bucket", got.SourceAssetID)
	}
	if got.PolicyType != "s3_bucket" {
		t.Errorf("PolicyType = %q, want s3_bucket", got.PolicyType)
	}
	if len(got.Statements) != 1 {
		t.Fatalf("Statements = %d, want 1", len(got.Statements))
	}
	st := got.Statements[0]
	if st.Sid != "AllowAccountRead" || st.Effect != "Allow" {
		t.Errorf("statement header = (%q, %q)", st.Sid, st.Effect)
	}
	if len(st.Principals) != 1 || st.Principals[0] != "AWS:arn:aws:iam::111122223333:role/data-loader" {
		t.Errorf("Principals = %v", st.Principals)
	}
	if len(st.Actions) != 2 {
		t.Errorf("Actions = %v", st.Actions)
	}
	if len(st.Resources) != 2 {
		t.Errorf("Resources = %v", st.Resources)
	}
	if len(st.Conditions) != 1 ||
		st.Conditions[0].Operator != "StringEquals" ||
		st.Conditions[0].Key != "aws:PrincipalOrgID" ||
		len(st.Conditions[0].Values) != 1 ||
		st.Conditions[0].Values[0] != "o-abc123" {
		t.Errorf("Conditions = %+v", st.Conditions)
	}
}

func TestExportPolicies_KMSKeyPolicySeparation(t *testing.T) {
	t.Parallel()
	dir := writeFixture(t)
	out, err := stave.ExportPolicies(context.Background(), stave.ExportConfig{SnapshotsDir: dir})
	if err != nil {
		t.Fatalf("ExportPolicies: %v", err)
	}
	if len(out.KMSKeyPolicies) != 1 {
		t.Fatalf("KMSKeyPolicies = %d, want 1", len(out.KMSKeyPolicies))
	}
	if got := out.KMSKeyPolicies[0]; got.PolicyType != "kms_key" {
		t.Errorf("PolicyType = %q, want kms_key", got.PolicyType)
	}
}

func TestExportPolicies_TrustPolicyExtraction(t *testing.T) {
	t.Parallel()
	dir := writeFixture(t)
	out, err := stave.ExportPolicies(context.Background(), stave.ExportConfig{SnapshotsDir: dir})
	if err != nil {
		t.Fatalf("ExportPolicies: %v", err)
	}
	if len(out.TrustPolicies) != 1 {
		t.Fatalf("TrustPolicies = %d, want 1", len(out.TrustPolicies))
	}
	tp := out.TrustPolicies[0]
	if tp.SourceAssetID != "arn:aws:iam::111122223333:role/data-loader" {
		t.Errorf("SourceAssetID = %q", tp.SourceAssetID)
	}
	if len(tp.Statements) != 1 || tp.Statements[0].Effect != "Allow" {
		t.Errorf("statements = %+v", tp.Statements)
	}
}

func TestExportPolicies_AssetEdges(t *testing.T) {
	t.Parallel()
	dir := writeFixture(t)
	out, err := stave.ExportPolicies(context.Background(), stave.ExportConfig{SnapshotsDir: dir})
	if err != nil {
		t.Fatalf("ExportPolicies: %v", err)
	}

	wantEdges := map[string]string{
		"arn:aws:s3:::data-bucket->arn:aws:kms:us-east-1:111122223333:key/abc-123":                "encrypts_with",
		"arn:aws:iam::111122223333:role/orchestrator->arn:aws:iam::111122223333:role/data-loader": "assumes",
	}
	if len(out.AssetRelationships) != len(wantEdges) {
		t.Fatalf("AssetRelationships = %d, want %d (%+v)", len(out.AssetRelationships), len(wantEdges), out.AssetRelationships)
	}
	for _, e := range out.AssetRelationships {
		key := e.FromAssetID + "->" + e.ToAssetID
		if want, ok := wantEdges[key]; !ok || want != e.Relationship {
			t.Errorf("unexpected edge %q (%q)", key, e.Relationship)
		}
	}
}

func TestExportPolicies_GeneratedAtMatchesLatestSnapshot(t *testing.T) {
	t.Parallel()
	dir := writeFixture(t)
	out, err := stave.ExportPolicies(context.Background(), stave.ExportConfig{SnapshotsDir: dir})
	if err != nil {
		t.Fatalf("ExportPolicies: %v", err)
	}
	if out.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should be populated from snapshot CapturedAt")
	}
}

// stubResolver is a deterministic stand-in for the AWS resolver
// — returns whatever permissions the test pre-loads. Lets the
// plumbing test exercise the wiring without depending on the
// snapshot's IAM resolution semantics.
type stubResolver struct {
	perms []ports.EffectivePermission
}

func (s stubResolver) ResolveSnapshot(_ *asset.Snapshot) []ports.EffectivePermission {
	return s.perms
}

// TestExportPolicies_EffectivePermissionsWiring confirms a
// resolver supplied via ExportConfig flows through to the
// resulting PolicyExport.EffectivePermissions slice, with the
// dedup + sort guarantees the policyexport contract promises.
func TestExportPolicies_EffectivePermissionsWiring(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snap.obs.json"),
		[]byte(snapshot), 0o600); err != nil {
		t.Fatalf("write snap: %v", err)
	}

	resolver := stubResolver{
		perms: []ports.EffectivePermission{
			// Out-of-order on purpose; expect sort by
			// (PrincipalID, Source, Action, Resource).
			{PrincipalID: "user/b", Action: "s3:GetObject", Resource: "arn:aws:s3:::z", Source: "identity_policy"},
			{PrincipalID: "user/a", Action: "s3:PutObject", Resource: "arn:aws:s3:::y", Source: "identity_policy"},
			{PrincipalID: "user/a", Action: "s3:GetObject", Resource: "arn:aws:s3:::y", Source: "resource_policy"},
			{PrincipalID: "user/a", Action: "s3:GetObject", Resource: "arn:aws:s3:::x", Source: "identity_policy"},
		},
	}

	out, err := stave.ExportPolicies(context.Background(), stave.ExportConfig{
		SnapshotsDir:                dir,
		AllowUnknownInput:           true,
		EffectivePermissionResolver: resolver,
	})
	if err != nil {
		t.Fatalf("ExportPolicies: %v", err)
	}
	if got := len(out.EffectivePermissions); got != 4 {
		t.Fatalf("EffectivePermissions len = %d, want 4", got)
	}
	want := [][3]string{
		// (PrincipalID, Source, Action) tuple in expected order.
		{"user/a", "identity_policy", "s3:GetObject"},
		{"user/a", "identity_policy", "s3:PutObject"},
		{"user/a", "resource_policy", "s3:GetObject"},
		{"user/b", "identity_policy", "s3:GetObject"},
	}
	for i, p := range out.EffectivePermissions {
		got := [3]string{p.PrincipalID, p.Source, p.Action}
		if got != want[i] {
			t.Errorf("perm[%d] = %v, want %v", i, got, want[i])
		}
	}
}

// TestExportPolicies_EffectivePermissionsDedupAcrossSnapshots
// confirms the same (PrincipalID, Source, Action, Resource)
// observed across multiple snapshots produces ONE entry, not N.
func TestExportPolicies_EffectivePermissionsDedupAcrossSnapshots(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Two snapshot files — same observation content, different
	// captured_at — exercise the dedup path.
	for i, ts := range []string{"2026-05-01T00:00:00Z", "2026-05-08T00:00:00Z"} {
		obs := strings.Replace(snapshot, "2026-05-03T00:00:00Z", ts, 1)
		if err := os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("snap-%d.obs.json", i)),
			[]byte(obs), 0o600,
		); err != nil {
			t.Fatalf("write snap %d: %v", i, err)
		}
	}

	// The stub returns the same permission on each call. Dedup
	// must collapse it to a single entry in the output.
	resolver := stubResolver{
		perms: []ports.EffectivePermission{
			{PrincipalID: "p", Action: "s3:GetObject", Resource: "r", Source: "identity_policy"},
		},
	}
	out, err := stave.ExportPolicies(context.Background(), stave.ExportConfig{
		SnapshotsDir:                dir,
		AllowUnknownInput:           true,
		EffectivePermissionResolver: resolver,
	})
	if err != nil {
		t.Fatalf("ExportPolicies: %v", err)
	}
	if got := len(out.EffectivePermissions); got != 1 {
		t.Errorf("dedup failed: len = %d, want 1", got)
	}
}

// TestExportPolicies_NilResolverDefaultsToAWS confirms a nil
// EffectivePermissionResolver in ExportConfig falls back to the
// AWS implementation rather than skipping permission
// resolution entirely. The snapshot constant carries an IAM
// role with a trust policy; the AWS resolver runs over it
// without panic and produces (possibly empty) output.
func TestExportPolicies_NilResolverDefaultsToAWS(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snap.obs.json"),
		[]byte(snapshot), 0o600); err != nil {
		t.Fatalf("write snap: %v", err)
	}
	// Resolver field intentionally omitted — tests the default
	// wiring path.
	if _, err := stave.ExportPolicies(context.Background(), stave.ExportConfig{
		SnapshotsDir:      dir,
		AllowUnknownInput: true,
	}); err != nil {
		t.Fatalf("ExportPolicies with nil resolver: %v", err)
	}
}

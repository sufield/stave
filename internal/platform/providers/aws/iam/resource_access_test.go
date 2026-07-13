package iam

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestResourceAccessIndex_PublicPolicy(t *testing.T) {
	idx := NewResourceAccessIndex()
	err := AddResourcePolicy(idx,
		"arn:aws:s3:::public-bucket",
		`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		"123456789012",
	)
	if err != nil {
		t.Fatalf("AddResourcePolicy: %v", err)
	}

	entries := idx.EntriesFor("arn:aws:s3:::public-bucket")
	if len(entries) == 0 {
		t.Fatal("expected entries for public bucket")
	}

	hasPublic := false
	for _, e := range entries {
		if e.IsPublic {
			hasPublic = true
		}
	}
	if !hasPublic {
		t.Fatal("expected public entry for Principal: *")
	}
}

func TestResourceAccessIndex_CrossAccountGrant(t *testing.T) {
	idx := NewResourceAccessIndex()
	err := AddResourcePolicy(idx,
		"arn:aws:s3:::shared-bucket",
		`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:iam::999888777666:role/external"}]}`,
		"123456789012",
	)
	if err != nil {
		t.Fatalf("AddResourcePolicy: %v", err)
	}

	entries := idx.EntriesFor("arn:aws:s3:::shared-bucket")
	if len(entries) == 0 {
		t.Fatal("expected entries")
	}
	if !entries[0].IsCrossAccount {
		t.Fatal("expected cross-account flag")
	}
}

func TestResourceAccessIndex_SameAccountGrant(t *testing.T) {
	idx := NewResourceAccessIndex()
	err := AddResourcePolicy(idx,
		"arn:aws:s3:::internal-bucket",
		`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:iam::123456789012:role/app"}]}`,
		"123456789012",
	)
	if err != nil {
		t.Fatalf("AddResourcePolicy: %v", err)
	}

	entries := idx.EntriesFor("arn:aws:s3:::internal-bucket")
	if len(entries) == 0 {
		t.Fatal("expected entries")
	}
	if entries[0].IsCrossAccount {
		t.Fatal("expected same-account, not cross-account")
	}
}

func TestResourceAccessIndex_AbsentPolicy(t *testing.T) {
	idx := NewResourceAccessIndex()
	err := AddResourcePolicy(idx, "arn:aws:s3:::no-policy", "", "123456789012")
	if err != nil {
		t.Fatalf("AddResourcePolicy: %v", err)
	}
	entries := idx.EntriesFor("arn:aws:s3:::no-policy")
	if len(entries) != 0 {
		t.Fatal("expected no entries for absent policy")
	}
}

func TestResourceAccessIndex_DenySkipped(t *testing.T) {
	idx := NewResourceAccessIndex()
	err := AddResourcePolicy(idx,
		"arn:aws:s3:::deny-bucket",
		`{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`,
		"123456789012",
	)
	if err != nil {
		t.Fatalf("AddResourcePolicy: %v", err)
	}
	entries := idx.EntriesFor("arn:aws:s3:::deny-bucket")
	if len(entries) != 0 {
		t.Fatal("expected no entries for deny-only policy")
	}
}

func TestBuildResourceAccessIndex_S3BucketInfersAccount(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			{
				ID:   "arn:aws:iam::111122223333:role/app",
				Type: "aws_iam_role",
				Properties: map[string]any{},
			},
			{
				ID:   "arn:aws:s3:::cross-account-bucket",
				Type: "aws_s3_bucket",
				Properties: map[string]any{
					"storage": map[string]any{
						"policy_json": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:iam::999888777666:role/external"}]}`,
					},
				},
			},
		},
	}

	idx := BuildResourceAccessIndexFromSnapshots([]asset.Snapshot{snap})
	if idx == nil {
		t.Fatal("expected non-nil index")
	}

	entries := idx.EntriesFor("arn:aws:s3:::cross-account-bucket")
	if len(entries) == 0 {
		t.Fatal("expected entries for cross-account bucket")
	}
	if !entries[0].IsCrossAccount {
		t.Fatal("expected cross-account flag — S3 bucket account inferred from IAM asset in same snapshot")
	}
}

func TestBuildResourceAccessIndex_S3BucketSameAccount(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			{
				ID:   "arn:aws:iam::111122223333:role/app",
				Type: "aws_iam_role",
				Properties: map[string]any{},
			},
			{
				ID:   "arn:aws:s3:::same-account-bucket",
				Type: "aws_s3_bucket",
				Properties: map[string]any{
					"storage": map[string]any{
						"policy_json": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:iam::111122223333:role/internal"}]}`,
					},
				},
			},
		},
	}

	idx := BuildResourceAccessIndexFromSnapshots([]asset.Snapshot{snap})
	if idx == nil {
		t.Fatal("expected non-nil index")
	}

	entries := idx.EntriesFor("arn:aws:s3:::same-account-bucket")
	if len(entries) == 0 {
		t.Fatal("expected entries")
	}
	if entries[0].IsCrossAccount {
		t.Fatal("expected same-account — both principal and bucket belong to 111122223333")
	}
}

func TestHasNonDesignatedPHIAccess_AllDesignated(t *testing.T) {
	idx := NewResourceAccessIndex()
	_ = AddResourcePolicy(idx,
		"arn:aws:s3:::phi-bucket",
		`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:iam::123456789012:role/phi-processor"}]}`,
		"123456789012",
	)

	designated := map[string]struct{}{
		"arn:aws:iam::123456789012:role/phi-processor": {},
	}
	if idx.HasNonDesignatedPHIAccess("arn:aws:s3:::phi-bucket", designated) {
		t.Fatal("expected no non-designated access — all principals are designated")
	}
}

func TestHasNonDesignatedPHIAccess_NonDesignated(t *testing.T) {
	idx := NewResourceAccessIndex()
	_ = AddResourcePolicy(idx,
		"arn:aws:s3:::phi-bucket",
		`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:iam::123456789012:role/random-dev"}]}`,
		"123456789012",
	)

	designated := map[string]struct{}{
		"arn:aws:iam::123456789012:role/phi-processor": {},
	}
	if !idx.HasNonDesignatedPHIAccess("arn:aws:s3:::phi-bucket", designated) {
		t.Fatal("expected non-designated access detected")
	}
}

func TestHasNonDesignatedPHIAccess_PublicAlwaysNonDesignated(t *testing.T) {
	idx := NewResourceAccessIndex()
	_ = AddResourcePolicy(idx,
		"arn:aws:s3:::phi-bucket",
		`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		"123456789012",
	)

	designated := map[string]struct{}{} // empty — no one is designated
	if !idx.HasNonDesignatedPHIAccess("arn:aws:s3:::phi-bucket", designated) {
		t.Fatal("expected public access to be non-designated")
	}
}

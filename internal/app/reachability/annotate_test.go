package reachability

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/iam"
)

func TestAnnotateFindings_ViolationGetsAnnotation(t *testing.T) {
	idx := iam.NewResourceAccessIndex()
	idx.AddEntry("arn:aws:s3:::phi-records", iam.ResourceAccessEntry{
		PrincipalARN: "arn:aws:iam::123:role/AdminRole",
		Actions:      []string{"s3:*"},
	})
	idx.AddEntry("arn:aws:s3:::phi-records", iam.ResourceAccessEntry{
		PrincipalARN: "arn:aws:iam::123:role/ReadOnly",
		Actions:      []string{"s3:GetObject"},
	})

	findings := []remediation.Finding{
		{Finding: evaluation.Finding{
			ControlSeverity: policy.SeverityCritical,
			AssetID:         "arn:aws:s3:::phi-records",
		}},
	}

	AnnotateFindings(findings, idx)

	if findings[0].Reachability == nil {
		t.Fatal("expected reachability annotation")
	}
	r := findings[0].Reachability
	if r.TotalReachablePrincipals != 2 {
		t.Errorf("total = %d, want 2", r.TotalReachablePrincipals)
	}
	if r.PrivilegedPrincipalCount != 1 {
		t.Errorf("privileged = %d, want 1", r.PrivilegedPrincipalCount)
	}
	if r.HighestPrivilegePrincipal != "arn:aws:iam::123:role/AdminRole" {
		t.Errorf("highest = %q", r.HighestPrivilegePrincipal)
	}
}

func TestAnnotateFindings_ResourceNotInIndex(t *testing.T) {
	idx := iam.NewResourceAccessIndex()

	findings := []remediation.Finding{
		{Finding: evaluation.Finding{
			AssetID: "arn:aws:s3:::unknown-bucket",
		}},
	}

	AnnotateFindings(findings, idx)

	if findings[0].Reachability != nil {
		t.Error("expected nil reachability for resource not in index")
	}
}

func TestAnnotateFindings_NilIndex(t *testing.T) {
	findings := []remediation.Finding{
		{Finding: evaluation.Finding{AssetID: "arn:aws:s3:::bucket"}},
	}
	AnnotateFindings(findings, nil)
	if findings[0].Reachability != nil {
		t.Error("expected nil reachability with nil index")
	}
}

func TestAnnotateFindings_ExternalPrincipal(t *testing.T) {
	idx := iam.NewResourceAccessIndex()
	idx.AddEntry("arn:aws:s3:::public-bucket", iam.ResourceAccessEntry{
		PrincipalARN:   "*",
		Actions:        []string{"s3:GetObject"},
		IsPublic:       true,
		IsCrossAccount: false,
	})

	findings := []remediation.Finding{
		{Finding: evaluation.Finding{AssetID: "arn:aws:s3:::public-bucket"}},
	}

	AnnotateFindings(findings, idx)

	r := findings[0].Reachability
	if r == nil {
		t.Fatal("expected reachability")
	}
	if !r.ExternalPrincipalReachable {
		t.Error("expected external_principal_reachable = true for public")
	}
}

func TestBlastRadiusScore(t *testing.T) {
	// 2 privileged (20*2=40) + 5 total (2*5=10) + external (30) = 80
	idx := iam.NewResourceAccessIndex()
	idx.AddEntry("res", iam.ResourceAccessEntry{PrincipalARN: "a", Actions: []string{"s3:*"}})
	idx.AddEntry("res", iam.ResourceAccessEntry{PrincipalARN: "b", Actions: []string{"kms:*"}})
	idx.AddEntry("res", iam.ResourceAccessEntry{PrincipalARN: "c", Actions: []string{"s3:Get"}})
	idx.AddEntry("res", iam.ResourceAccessEntry{PrincipalARN: "d", Actions: []string{"s3:List"}})
	idx.AddEntry("res", iam.ResourceAccessEntry{PrincipalARN: "*", Actions: []string{"s3:Get"}, IsPublic: true})

	findings := []remediation.Finding{
		{Finding: evaluation.Finding{AssetID: "res"}},
	}
	AnnotateFindings(findings, idx)

	r := findings[0].Reachability
	if r == nil {
		t.Fatal("expected reachability")
	}
	if r.BlastRadiusScore != 80 {
		t.Errorf("blast_radius = %.0f, want 80 (2priv*20 + 5total*2 + external*30)", r.BlastRadiusScore)
	}
}

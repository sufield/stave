package catalogsearch

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func ctl(id, name string, sev policy.Severity) policy.ControlDefinition {
	return policy.ControlDefinition{
		ID:       kernel.ControlID(id),
		Name:     name,
		Severity: sev,
	}
}

func TestSearch_KeywordMatch(t *testing.T) {
	controls := []policy.ControlDefinition{
		ctl("CTL.S3.PUBLIC.001", "No public S3 buckets", policy.SeverityCritical),
		ctl("CTL.EC2.IMDSV2.001", "Require IMDSv2", policy.SeverityHigh),
	}

	results := Search(controls, Filter{Query: "public"})

	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("control = %s, want CTL.S3.PUBLIC.001", results[0].ControlID)
	}
}

func TestSearch_SeverityFilter(t *testing.T) {
	controls := []policy.ControlDefinition{
		ctl("CTL.A.001", "Critical control", policy.SeverityCritical),
		ctl("CTL.B.001", "High control", policy.SeverityHigh),
	}

	results := Search(controls, Filter{Severity: policy.SeverityCritical})

	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].ControlID != "CTL.A.001" {
		t.Errorf("control = %s, want CTL.A.001", results[0].ControlID)
	}
}

func TestSearchResults_DomainMethods(t *testing.T) {
	sr := SearchResults{
		{ControlID: "CTL.A", Severity: policy.SeverityCritical, Domain: "s3_bucket"},
		{ControlID: "CTL.B", Severity: policy.SeverityHigh, Domain: "ec2_instance"},
		{ControlID: "CTL.C", Severity: policy.SeverityCritical, Domain: "s3_bucket"},
	}

	if sr.Len() != 3 {
		t.Errorf("Len: got %d, want 3", sr.Len())
	}
	if crits := sr.BySeverity(policy.SeverityCritical); crits.Len() != 2 {
		t.Errorf("BySeverity Critical: got %d, want 2", crits.Len())
	}
	if s3s := sr.ByDomain("s3_bucket"); s3s.Len() != 2 {
		t.Errorf("ByDomain s3_bucket: got %d, want 2", s3s.Len())
	}
}

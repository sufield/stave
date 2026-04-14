package evidence

import (
	"testing"
)

func TestCitationIndex_Lookup(t *testing.T) {
	idx := NewCitationIndex()
	idx.Add("hipaa", "164.312(a)(1)", CitationEntry{
		ControlID: "CTL.S3.PUBLIC.001",
		Severity:  "critical",
	})
	idx.Add("hipaa", "164.312(a)(1)", CitationEntry{
		ControlID: "CTL.IAM.POLICY.ADMIN.001",
		Severity:  "critical",
	})

	entries := idx.Lookup("hipaa", "164.312(a)(1)")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestCitationIndex_LookupMissing(t *testing.T) {
	idx := NewCitationIndex()
	entries := idx.Lookup("hipaa", "nonexistent")
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestCitationIndex_Coverage(t *testing.T) {
	idx := NewCitationIndex()
	idx.Add("hipaa", "164.312(a)(1)", CitationEntry{ControlID: "CTL.S3.PUBLIC.001"})
	idx.Add("hipaa", "164.312(b)", CitationEntry{ControlID: "CTL.CLOUDTRAIL.ENABLED.001"})

	cov := idx.Coverage("hipaa", 10)
	if cov.CoveredRequirements != 2 {
		t.Fatalf("expected 2 covered, got %d", cov.CoveredRequirements)
	}
	if cov.TotalRequirements != 10 {
		t.Fatalf("expected 10 total, got %d", cov.TotalRequirements)
	}
	if cov.CoveragePercent != 20.0 {
		t.Fatalf("expected 20%%, got %.1f%%", cov.CoveragePercent)
	}
}

func TestCitationIndex_Frameworks(t *testing.T) {
	idx := NewCitationIndex()
	idx.Add("hipaa", "164.312(a)(1)", CitationEntry{ControlID: "CTL.S3.PUBLIC.001"})
	idx.Add("soc2", "CC6.1", CitationEntry{ControlID: "CTL.S3.PUBLIC.001"})
	idx.Add("hipaa", "164.312(b)", CitationEntry{ControlID: "CTL.CLOUDTRAIL.ENABLED.001"})

	frameworks := idx.Frameworks()
	if len(frameworks) != 2 {
		t.Fatalf("expected 2 frameworks, got %d", len(frameworks))
	}
	if frameworks[0] != "hipaa" || frameworks[1] != "soc2" {
		t.Fatalf("unexpected frameworks: %v", frameworks)
	}
}

func TestCitationIndex_RequirementsFor(t *testing.T) {
	idx := NewCitationIndex()
	idx.Add("hipaa", "164.312(b)", CitationEntry{ControlID: "CTL.CLOUDTRAIL.ENABLED.001"})
	idx.Add("hipaa", "164.312(a)(1)", CitationEntry{ControlID: "CTL.S3.PUBLIC.001"})

	reqs := idx.RequirementsFor("hipaa")
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requirements, got %d", len(reqs))
	}
	// Should be sorted
	if reqs[0] != "164.312(a)(1)" {
		t.Fatalf("expected sorted, got %v", reqs)
	}
}

func TestCitationIndex_Size(t *testing.T) {
	idx := NewCitationIndex()
	idx.Add("hipaa", "164.312(a)(1)", CitationEntry{ControlID: "CTL.S3.PUBLIC.001"})
	idx.Add("soc2", "CC6.1", CitationEntry{ControlID: "CTL.S3.PUBLIC.001"})
	if idx.Size() != 2 {
		t.Fatalf("expected size 2, got %d", idx.Size())
	}
}

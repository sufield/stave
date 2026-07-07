package main

import "testing"

func TestDeduplicateGaps_MergesSameProperty(t *testing.T) {
	results := []*EngineResult{
		{Engine: "botocore", GapsFound: []Gap{
			{Service: "elasticache", Property: "AuthTokenEnabled", Severity: "Medium", Source: "botocore", Confidence: "Medium"},
		}},
		{Engine: "offensive", GapsFound: []Gap{
			{Service: "elasticache", Property: "AuthTokenEnabled", Severity: "High", Source: "offensive", Confidence: "High"},
		}},
	}

	multi, single := deduplicateGaps(results)

	if len(multi) != 1 {
		t.Fatalf("expected 1 multi-engine gap, got %d", len(multi))
	}
	if len(single) != 0 {
		t.Fatalf("expected 0 single-engine gaps, got %d", len(single))
	}
	if multi[0].Source != "botocore + offensive" {
		t.Errorf("expected merged source, got %q", multi[0].Source)
	}
}

func TestDeduplicateGaps_KeepsHighestSeverity(t *testing.T) {
	results := []*EngineResult{
		{Engine: "a", GapsFound: []Gap{
			{Service: "s3", Property: "PublicAccess", Severity: "Medium", Source: "a"},
		}},
		{Engine: "b", GapsFound: []Gap{
			{Service: "s3", Property: "PublicAccess", Severity: "Critical", Source: "b"},
		}},
	}

	multi, _ := deduplicateGaps(results)

	if len(multi) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(multi))
	}
	if multi[0].Severity != "Critical" {
		t.Errorf("expected Critical severity, got %q", multi[0].Severity)
	}
}

func TestDeduplicateGaps_PreservesAllSources(t *testing.T) {
	results := []*EngineResult{
		{Engine: "a", GapsFound: []Gap{{Service: "iam", Property: "RolePolicy", Source: "a", Severity: "High"}}},
		{Engine: "b", GapsFound: []Gap{{Service: "iam", Property: "RolePolicy", Source: "b", Severity: "High"}}},
		{Engine: "c", GapsFound: []Gap{{Service: "iam", Property: "RolePolicy", Source: "c", Severity: "High"}}},
	}

	multi, _ := deduplicateGaps(results)

	if len(multi) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(multi))
	}
	if multi[0].Source != "a + b + c" {
		t.Errorf("expected 3 sources, got %q", multi[0].Source)
	}
}

func TestDeduplicateGaps_SingleEngine(t *testing.T) {
	results := []*EngineResult{
		{Engine: "botocore", GapsFound: []Gap{
			{Service: "s3", Property: "Encryption", Severity: "High", Source: "botocore"},
		}},
	}

	multi, single := deduplicateGaps(results)

	if len(multi) != 0 {
		t.Fatalf("expected 0 multi-engine gaps, got %d", len(multi))
	}
	if len(single) != 1 {
		t.Fatalf("expected 1 single-engine gap, got %d", len(single))
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank("Critical") <= severityRank("High") {
		t.Error("Critical should rank higher than High")
	}
	if severityRank("High") <= severityRank("Medium") {
		t.Error("High should rank higher than Medium")
	}
	if severityRank("Medium") <= severityRank("Low") {
		t.Error("Medium should rank higher than Low")
	}
}

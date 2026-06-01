package sirfacts

import "testing"

func TestFilterOutCatalog(t *testing.T) {
	t.Parallel()
	facts := []Fact{
		{Subject: "CTL.S3.PUBLIC.001", Predicate: "has_severity", Object: "high"},
		{Subject: "CTL.S3.PUBLIC.001", Predicate: "has_type", Object: "unsafe_state"},
		{Subject: "arn:aws:s3:::bucket", Predicate: "storage.kind", Object: "bucket"},
		{Subject: "arn:aws:s3:::bucket", Predicate: "storage.logging.enabled", Object: "false"},
		{Subject: "CTL.IAM.TRUST.001", Predicate: "has_domain", Object: "identity"},
	}

	filtered := FilterOutCatalog(facts)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 observation facts, got %d", len(filtered))
	}
	if filtered[0].Predicate != "storage.kind" {
		t.Errorf("first fact predicate=%q, want storage.kind", filtered[0].Predicate)
	}
	if filtered[1].Predicate != "storage.logging.enabled" {
		t.Errorf("second fact predicate=%q, want storage.logging.enabled", filtered[1].Predicate)
	}
}

func TestFilterOutCatalog_Empty(t *testing.T) {
	t.Parallel()
	filtered := FilterOutCatalog(nil)
	if len(filtered) != 0 {
		t.Fatalf("expected 0 facts from nil input, got %d", len(filtered))
	}
}

func TestFilterOutCatalog_NoCatalog(t *testing.T) {
	t.Parallel()
	facts := []Fact{
		{Subject: "arn:aws:s3:::b", Predicate: "storage.kind", Object: "bucket"},
	}
	filtered := FilterOutCatalog(facts)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 fact (nothing to strip), got %d", len(filtered))
	}
}

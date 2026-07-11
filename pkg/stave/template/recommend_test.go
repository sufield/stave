package template

import (
	"testing"

	"github.com/sufield/stave/pkg/stave/snapshot"
)

func TestRecommend_MatchesByPriority(t *testing.T) {
	templates := []Template{
		{
			Metadata: Metadata{Name: "low-priority"},
			RecommendWhen: RecommendWhen{
				Predicate: `summary.s3_bucket_count > 0`,
				Priority:  30,
			},
		},
		{
			Metadata: Metadata{Name: "high-priority"},
			RecommendWhen: RecommendWhen{
				Predicate: `summary.s3_bucket_count > 0 && summary.has_cloudtrail`,
				Priority:  70,
			},
		},
	}

	summary := snapshot.Summary{
		S3BucketCount: 5,
		HasCloudTrail: true,
		Services:      []string{"s3", "cloudtrail"},
	}

	results, err := Recommend(templates, summary)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 recommendations, got %d", len(results))
	}
	if results[0].Template.Metadata.Name != "high-priority" {
		t.Fatalf("expected high-priority first, got %s", results[0].Template.Metadata.Name)
	}
}

func TestRecommend_NoMatch(t *testing.T) {
	templates := []Template{
		{
			Metadata: Metadata{Name: "needs-cloudtrail"},
			RecommendWhen: RecommendWhen{
				Predicate: `summary.has_cloudtrail`,
				Priority:  50,
			},
		},
	}

	summary := snapshot.Summary{
		HasCloudTrail: false,
		Services:      []string{"s3"},
	}

	results, err := Recommend(templates, summary)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 0 {
		t.Fatalf("expected 0 recommendations, got %d", len(results))
	}
}

func TestRecommend_ExtractsMatchedFacts(t *testing.T) {
	templates := []Template{
		{
			Metadata: Metadata{Name: "multi-condition"},
			RecommendWhen: RecommendWhen{
				Predicate: `summary.s3_bucket_count > 0 && summary.has_cloudtrail`,
				Priority:  50,
			},
		},
	}

	summary := snapshot.Summary{
		S3BucketCount: 3,
		HasCloudTrail: true,
		Services:      []string{"s3", "cloudtrail"},
	}

	results, err := Recommend(templates, summary)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(results))
	}
	if len(results[0].MatchedFacts) != 2 {
		t.Fatalf("expected 2 matched facts, got %d: %v", len(results[0].MatchedFacts), results[0].MatchedFacts)
	}
}

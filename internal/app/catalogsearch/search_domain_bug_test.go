package catalogsearch

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestSearch_ExplicitControlDomainUsed(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:     kernel.ControlID("CTL.S3.PUBLIC.001"),
			Name:   "Public S3 Bucket",
			Domain: kernel.AssetDomain("aws_s3_bucket"),
		},
	}

	// Filter by explicit domain
	res := Search(controls, Filter{Domain: "aws_s3_bucket"})
	if len(res) != 1 {
		t.Fatalf("expected 1 search result matching domain 'aws_s3_bucket', got %d", len(res))
	}

	if res[0].Domain != "aws_s3_bucket" {
		t.Errorf("expected SearchResult.Domain to be 'aws_s3_bucket', got %q", res[0].Domain)
	}
}

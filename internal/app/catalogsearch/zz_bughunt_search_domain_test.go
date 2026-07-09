package catalogsearch

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_Search_DomainFilter_StrictMatch(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:       kernel.ControlID("CTL.EC2.KMS_OR_S3.001"),
			Name:     "EC2 control mentioning S3",
			Severity: policy.SeverityHigh,
		},
		{
			ID:       kernel.ControlID("CTL.S3.PUBLIC.001"),
			Name:     "Actual S3 control",
			Severity: policy.SeverityCritical,
		},
	}

	// Filter specifically for "s3" domain.
	results := Search(controls, Filter{Domain: "s3"})

	// It should only return S3 controls, not EC2 controls that happen to contain "s3" in their ID string.
	for _, res := range results {
		if res.ControlID == "CTL.EC2.KMS_OR_S3.001" {
			t.Errorf("domain filter false positive: returned EC2 control %q when filtering for 's3'", res.ControlID)
		}
	}
}

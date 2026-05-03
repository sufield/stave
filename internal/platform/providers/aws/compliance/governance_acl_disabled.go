package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// governanceACLDisabled checks that ACLs are disabled via BucketOwnerEnforced ownership.
type governanceACLDisabled struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &governanceACLDisabled{
			Definition: core.NewDefinition(
				core.WithID("GOVERNANCE.001"),
				core.WithDescription("Bucket ACLs must be disabled (ownership_controls == BucketOwnerEnforced)"),
				core.WithSeverity(policy.SeverityHigh),
				core.WithComplianceProfiles("hipaa", "cis-s3"),
				core.WithComplianceRef("hipaa", "§164.312(a)(1)"),
				core.WithProfileRationale("hipaa", "ACL control — disable legacy ACL grants"),
			),
		}
	})
}

// Evaluate checks that ownership_controls is BucketOwnerEnforced.
func (ctl *governanceACLDisabled) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, props S3Properties) *core.Outcome {
		if !props.ACLsDisabled() {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: ACLs are not disabled (ownership_controls=%q). ACL grants can bypass bucket policy and create unauditable access paths", a.ID, props.Ownership),
				"Set Object Ownership to BucketOwnerEnforced to disable all ACLs. Known exception: AWS Backup restore jobs require ACLs enabled on the destination bucket — document as an acknowledged exception if this bucket is an AWS Backup restore target.",
			)
			return &r
		}
		return nil
	})
}

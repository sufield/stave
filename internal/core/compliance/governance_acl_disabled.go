package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// governanceACLDisabled checks that ACLs are disabled via BucketOwnerEnforced ownership.
type governanceACLDisabled struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&governanceACLDisabled{
		Definition: NewDefinition(
			WithID("GOVERNANCE.001"),
			WithDescription("Bucket ACLs must be disabled (ownership_controls == BucketOwnerEnforced)"),
			WithSeverity(policy.SeverityHigh),
			WithComplianceProfiles("hipaa", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(a)(1)"),
			WithProfileRationale("hipaa", "ACL control — disable legacy ACL grants"),
		),
	})
}

// Evaluate checks that ownership_controls is BucketOwnerEnforced.
func (ctl *governanceACLDisabled) Evaluate(snap asset.Snapshot) Outcome {
	return ctl.evaluateS3Buckets(snap, func(a asset.Asset, props S3Properties) *Outcome {
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

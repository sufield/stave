package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

// governanceAclDisabled checks that ACLs are disabled via BucketOwnerEnforced ownership.
type governanceAclDisabled struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&governanceAclDisabled{
		Definition: NewDefinition(
			WithID("GOVERNANCE.001"),
			WithDescription("Bucket ACLs must be disabled (ownership_controls == BucketOwnerEnforced)"),
			WithSeverity(High),
			WithComplianceProfiles("hipaa", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(a)(1)"),
			WithProfileRationale("hipaa", "ACL control — disable legacy ACL grants"),
		),
	})
}

// Evaluate checks that ownership_controls is BucketOwnerEnforced.
func (inv *governanceAclDisabled) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		props := ParseS3Properties(a)
		if props.Ownership != "BucketOwnerEnforced" {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: ACLs are not disabled (ownership_controls=%q). ACL grants can bypass bucket policy and create unauditable access paths", a.ID, props.Ownership),
				"Set Object Ownership to BucketOwnerEnforced to disable all ACLs. Known exception: AWS Backup restore jobs require ACLs enabled on the destination bucket — document as an acknowledged exception if this bucket is an AWS Backup restore target.",
			)
		}
	}

	return inv.PassResult()
}

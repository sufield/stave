package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

type accessNetworkRestriction struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&accessNetworkRestriction{
		Definition: NewDefinition(
			WithID("ACCESS.003"),
			WithDescription("Bucket access must be restricted by VPC endpoint or IP condition"),
			WithSeverity(policy.SeverityHigh),
			WithComplianceProfiles("hipaa"),
			WithComplianceRef("hipaa", "§164.312(e)(1)"),
			WithProfileRationale("hipaa", "Transmission security — VPC endpoint or IP restriction"),
			WithProfileSeverityOverride("hipaa", policy.SeverityHigh),
		),
	})
}

func (ctl *accessNetworkRestriction) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		props := ParseS3Properties(a)
		if !props.Access.HasVPCCondition && !props.Access.HasIPCondition {
			return ctl.FailResult(
				fmt.Sprintf("Bucket %s: no VPC endpoint or IP condition restricts access — bucket is reachable from any network path", a.ID),
				"Add a VPC gateway endpoint for S3 and route bucket traffic through it, or add an IP condition (aws:SourceIp) to the bucket policy to restrict access to known CIDR ranges.",
			)
		}
	}
	return ctl.PassResult()
}

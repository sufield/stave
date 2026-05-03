package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

type accessNetworkRestriction struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &accessNetworkRestriction{
			Definition: core.NewDefinition(
				core.WithID("ACCESS.003"),
				core.WithDescription("Bucket access must be restricted by VPC endpoint or IP condition"),
				core.WithSeverity(policy.SeverityHigh),
				core.WithComplianceProfiles("hipaa"),
				core.WithComplianceRef("hipaa", "§164.312(e)(1)"),
				core.WithProfileRationale("hipaa", "Transmission security — VPC endpoint or IP restriction"),
				core.WithProfileSeverityOverride("hipaa", policy.SeverityHigh),
			),
		}
	})
}

func (ctl *accessNetworkRestriction) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, props S3Properties) *core.Outcome {
		if !props.Access.IsNetworkRestricted() {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: no VPC endpoint or IP condition restricts access — bucket is reachable from any network path", a.ID),
				"Add a VPC gateway endpoint for S3 and route bucket traffic through it, or add an IP condition (aws:SourceIp) to the bucket policy to restrict access to known CIDR ranges.",
			)
			return &r
		}
		return nil
	})
}

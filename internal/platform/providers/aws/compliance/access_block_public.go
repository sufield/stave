package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// accessBlockPublic checks that all four S3 Block Public Access flags are enabled
// at the bucket level. If account-level BPA is fully enabled but bucket-level
// is not set, severity downgrades to LOW.
type accessBlockPublic struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &accessBlockPublic{
			Definition: core.NewDefinition(
				core.WithID("ACCESS.001"),
				core.WithDescription("Block Public Access must be fully enabled at bucket level"),
				core.WithSeverity(policy.SeverityCritical),
				core.WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
				core.WithComplianceRef("hipaa", "§164.312(a)(1)"),
				core.WithProfileRationale("hipaa", "Access control — Block Public Access prevents public exposure of ePHI"),
			),
		}
	})
}

// Evaluate checks every S3 bucket asset in the snapshot for complete BPA enablement.
func (ctl *accessBlockPublic) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, props S3Properties) *core.Outcome {
		if props.Controls.IsPublicAccessFullyBlocked() {
			return nil
		}

		// Check account-level BPA as a mitigating factor.
		if props.Controls.AccountPublicAccessFullyBlocked {
			r := core.Outcome{
				Pass:           false,
				ControlID:      ctl.ID(),
				Severity:       policy.SeverityLow,
				Finding:        fmt.Sprintf("Bucket %s: bucket-level BPA not fully enabled. Account-level BPA active — bucket-level is defense in depth", a.ID),
				Remediation:    "Enable all four Block Public Access flags on the bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.",
				ComplianceRefs: ctl.ComplianceRefs(),
			}
			return &r
		}

		r := ctl.FailResult(
			fmt.Sprintf("Bucket %s: Block Public Access is not fully enabled — publicly accessible objects may exist", a.ID),
			"Enable all four Block Public Access flags on the bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.",
		)
		return &r
	})
}

func extractPolicyJSON(a asset.Asset) string {
	return ParseS3Properties(a).PolicyJSON
}

package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

type accessEndpointPolicy struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &accessEndpointPolicy{
			Definition: core.NewDefinition(
				core.WithID("ACCESS.006"),
				core.WithDescription("VPC endpoint policy must restrict S3 access to approved bucket ARNs"),
				core.WithSeverity(policy.SeverityHigh),
				core.WithComplianceProfiles("hipaa"),
				core.WithComplianceRef("hipaa", "§164.312(e)(1)"),
				core.WithProfileRationale("hipaa", "VPC endpoint policy restricts access to approved bucket ARNs"),
			),
		}
	})
}

func (ctl *accessEndpointPolicy) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, props S3Properties) *core.Outcome {
		vep := props.Network.VPCEndpointPolicy
		if !vep.IsEnforced() {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: no VPC endpoint policy attached — endpoint uses default full-access policy", a.ID),
				"Attach a VPC endpoint policy that restricts which S3 bucket ARNs are reachable through the endpoint.",
			)
			return &r
		}

		if vep.IsDefaultFullAccess {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: VPC endpoint policy is the default full-access policy (Allow *) — any principal on the VPC can reach any S3 bucket via this endpoint", a.ID),
				"Replace the default endpoint policy with one that restricts Resource to specific bucket ARNs and Action to required S3 operations only.",
			)
			return &r
		}

		return nil
	})
}

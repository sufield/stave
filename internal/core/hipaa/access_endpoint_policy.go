package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

type accessEndpointPolicy struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&accessEndpointPolicy{
		Definition: NewDefinition(
			WithID("ACCESS.006"),
			WithDescription("VPC endpoint policy must restrict S3 access to approved bucket ARNs"),
			WithSeverity(High),
			WithComplianceProfiles("hipaa"),
			WithComplianceRef("hipaa", "§164.312(e)(1)"),
			WithProfileRationale("hipaa", "VPC endpoint policy restricts access to approved bucket ARNs"),
		),
	})
}

func (inv *accessEndpointPolicy) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		props := ParseS3Properties(a)
		vep := props.Network.VPCEndpointPolicy
		if !vep.Present || !vep.Attached {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: no VPC endpoint policy attached — endpoint uses default full-access policy", a.ID),
				"Attach a VPC endpoint policy that restricts which S3 bucket ARNs are reachable through the endpoint.",
			)
		}

		if vep.IsDefaultFullAccess {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: VPC endpoint policy is the default full-access policy (Allow *) — any principal on the VPC can reach any S3 bucket via this endpoint", a.ID),
				"Replace the default endpoint policy with one that restricts Resource to specific bucket ARNs and Action to required S3 operations only.",
			)
		}
	}
	return inv.PassResult()
}

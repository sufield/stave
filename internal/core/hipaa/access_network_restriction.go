package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

type accessNetworkRestriction struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&accessNetworkRestriction{
		Definition: Build(
			WithID("ACCESS.003"),
			WithDescription("Bucket access must be restricted by VPC endpoint or IP condition"),
			WithSeverity(High),
			WithComplianceProfiles("hipaa"),
			WithComplianceRef("hipaa", "§164.312(e)(1)"),
			WithProfileRationale("hipaa", "Transmission security — VPC endpoint or IP restriction"),
			WithProfileSeverityOverride("hipaa", High),
		),
	})
}

func (inv *accessNetworkRestriction) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		acc := accessMap(a)
		if acc == nil {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: no access data available for network restriction check", a.ID),
				"Ensure the observation includes storage.access properties with has_vpc_condition and has_ip_condition fields.",
			)
		}

		hasVPC := toBool(acc["has_vpc_condition"])
		hasIP := toBool(acc["has_ip_condition"])

		if !hasVPC && !hasIP {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: no VPC endpoint or IP condition restricts access — bucket is reachable from any network path", a.ID),
				"Add a VPC gateway endpoint for S3 and route bucket traffic through it, or add an IP condition (aws:SourceIp) to the bucket policy to restrict access to known CIDR ranges.",
			)
		}
	}
	return inv.PassResult()
}

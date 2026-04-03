package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// accessPublicList checks that no S3 bucket policy grants s3:ListBucket
// to a wildcard principal (*).
type accessPublicList struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&accessPublicList{
		Definition: NewDefinition(
			WithID("ACCESS.011"),
			WithDescription("No bucket policy may grant s3:ListBucket to a public principal"),
			WithSeverity(policy.SeverityHigh),
			WithComplianceProfiles("hipaa", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(a)(1)"),
		),
	})
}

// Evaluate checks every S3 bucket for public ListBucket grants.
func (inv *accessPublicList) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		policyJSON := extractPolicyJSON(a)
		stmts, err := ParsePolicyStatements(policyJSON)
		if err != nil || len(stmts) == 0 {
			continue
		}

		for _, s := range stmts {
			if s.IsAllow() && s.HasWildcardPrincipal() && s.HasAction("s3:ListBucket") {
				sid := s.Sid
				if sid == "" {
					sid = "(unnamed)"
				}
				return inv.FailResult(
					fmt.Sprintf("Bucket %s: policy statement %q grants s3:ListBucket to Principal *. ListBucket enables full key enumeration defeating any object-key obscurity approach", a.ID, sid),
					"Remove the public ListBucket grant. If listing is required, restrict Principal to specific AWS accounts or IAM roles and add a Condition limiting source VPC or IP range.",
				)
			}
		}
	}

	return inv.PassResult()
}

package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

type accessPresignedURL struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &accessPresignedURL{
			Definition: core.NewDefinition(
				core.WithID("ACCESS.009"),
				core.WithDescription("PHI bucket policy must restrict presigned URL access via s3:signatureAge or s3:authType condition"),
				core.WithSeverity(policy.SeverityMedium),
				core.WithComplianceProfiles("hipaa"),
				core.WithComplianceRef("hipaa", "§164.312(a)(1)"),
				core.WithProfileRationale("hipaa", "Presigned URL restriction for PHI buckets"),
				core.WithProfileSeverityOverride("hipaa", policy.SeverityMedium),
			),
		}
	})
}

func (ctl *accessPresignedURL) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, _ S3Properties) *core.Outcome {
		policyJSON := extractPolicyJSON(a)
		if policyJSON == "" {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: no bucket policy — presigned URLs are unrestricted", a.ID),
				"Add a bucket policy with a Deny statement using s3:signatureAge (max age in ms) or s3:authType (require REST-HEADER) to restrict presigned URL access.",
			)
			return &r
		}

		stmts, err := ParsePolicyStatements(policyJSON)
		if err != nil || len(stmts) == 0 {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: bucket policy could not be parsed for presigned URL restrictions", a.ID),
				"Ensure the bucket policy is valid JSON with Statement entries.",
			)
			return &r
		}

		for _, stmt := range stmts {
			if stmt.RestrictsPresignedURLAccess() {
				return nil
			}
		}

		r := ctl.FailResult(
			fmt.Sprintf("Bucket %s: bucket policy does not contain s3:signatureAge or s3:authType guardrails — presigned URLs are unrestricted", a.ID),
			"Add a Deny statement with Condition NumericGreaterThan s3:signatureAge (e.g., 600000 for 10 minutes) or StringNotEquals s3:authType REST-HEADER to block presigned URL access.",
		)
		return &r
	})
}

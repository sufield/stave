package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

type accessPresignedURL struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&accessPresignedURL{
		Definition: NewDefinition(
			WithID("ACCESS.009"),
			WithDescription("PHI bucket policy must restrict presigned URL access via s3:signatureAge or s3:authType condition"),
			WithSeverity(policy.SeverityMedium),
			WithComplianceProfiles("hipaa"),
			WithComplianceRef("hipaa", "§164.312(a)(1)"),
			WithProfileRationale("hipaa", "Presigned URL restriction for PHI buckets"),
			WithProfileSeverityOverride("hipaa", policy.SeverityMedium),
		),
	})
}

func (ctl *accessPresignedURL) Evaluate(snap asset.Snapshot) Result {
	return ctl.evaluateS3Buckets(snap, func(a asset.Asset, _ S3Properties) *Result {
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
			if stmt.HasSignatureAgeGuardrail() || stmt.HasAuthTypeGuardrail() {
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

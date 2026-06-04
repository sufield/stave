package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// accessPublicList checks that no S3 bucket policy grants s3:ListBucket
// to a wildcard principal (*).
type accessPublicList struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &accessPublicList{
			Definition: core.NewDefinition(
				core.WithID("ACCESS.011"),
				core.WithDescription("No bucket policy may grant s3:ListBucket to a public principal"),
				core.WithSeverity(policy.SeverityHigh),
				core.WithComplianceProfiles("hipaa", "cis-s3"),
				core.WithComplianceRef("hipaa", "§164.312(a)(1)"),
			),
		}
	})
}

// Evaluate checks every S3 bucket for public ListBucket grants.
func (ctl *accessPublicList) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, _ S3Properties) *core.Outcome {
		policyJSON := extractPolicyJSON(a)
		stmts, err := ParsePolicyStatements(policyJSON)
		if err != nil {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: bucket policy is present but could not be parsed (%v); cannot verify it grants no public s3:ListBucket", a.ID, err),
				"Fix the malformed bucket policy JSON so it can be evaluated; an unparseable policy cannot be proven safe.",
			)
			return &r
		}
		if len(stmts) == 0 {
			return nil
		}

		// Index iteration — PolicyStatement now embeds typed
		// NormalizedPrincipal / NormalizedCondition (192-byte
		// struct), so range-by-value triggers a per-iteration
		// copy gocritic legitimately flags. Walking by index keeps
		// the call sites zero-copy while preserving the existing
		// method-call shape.
		for i := range stmts {
			s := &stmts[i]
			if s.IsPublicListGrant() {
				sid := s.Sid
				if sid == "" {
					sid = "(unnamed)"
				}
				r := ctl.FailResult(
					fmt.Sprintf("Bucket %s: policy statement %q grants s3:ListBucket to Principal *. ListBucket enables full key enumeration defeating any object-key obscurity approach", a.ID, sid),
					"Remove the public ListBucket grant. If listing is required, restrict Principal to specific AWS accounts or IAM roles and add a Condition limiting source VPC or IP range.",
				)
				return &r
			}
		}

		return nil
	})
}

package compliance

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// accessWildcardAction checks that no S3 bucket policy statement grants Allow with
// a wildcard action (s3:* or *).
type accessWildcardAction struct {
	core.Definition
}

// minimumSyncActions is the recommended minimum action set for common
// sync patterns, replacing an overly permissive s3:* grant.
var minimumSyncActions = []string{
	"s3:GetObject",
	"s3:PutObject",
	"s3:DeleteObject",
	"s3:ListBucket",
	"s3:GetBucketLocation",
}

func init() {
	core.RegisterControl(func() core.Control {
		return &accessWildcardAction{
			Definition: core.NewDefinition(
				core.WithID("ACCESS.002"),
				core.WithDescription("No bucket policy statement may grant Allow with wildcard action s3:*"),
				core.WithSeverity(policy.SeverityHigh),
				core.WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
				core.WithComplianceRef("hipaa", "§164.312(a)(2)(i)"),
				core.WithProfileRationale("hipaa", "Least privilege — no wildcard actions"),
			),
		}
	})
}

// Evaluate checks every S3 bucket for wildcard Allow statements.
func (ctl *accessWildcardAction) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, _ S3Properties) *core.Outcome {
		policyJSON := extractPolicyJSON(a)
		stmts, err := ParsePolicyStatements(policyJSON)
		if err != nil || len(stmts) == 0 {
			return nil // no policy or unparseable — not a violation
		}

		// Index iteration to avoid the per-iteration copy of the
		// typed PolicyStatement (192 bytes after Subset B).
		for i := range stmts {
			s := &stmts[i]
			if s.GrantsWildcardActions() {
				sid := s.Sid
				if sid == "" {
					sid = "(unnamed)"
				}
				r := ctl.FailResult(
					fmt.Sprintf("Bucket %s: policy statement %q grants Allow with wildcard action s3:* — this permits all S3 operations including delete and ACL modification", a.ID, sid),
					"Replace s3:* with the minimum required actions. For sync patterns use: "+strings.Join(minimumSyncActions, ", "),
				)
				return &r
			}
		}

		return nil
	})
}

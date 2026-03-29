package hipaa

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// accessWildcardAction checks that no S3 bucket policy statement grants Allow with
// a wildcard action (s3:* or *).
type accessWildcardAction struct {
	Definition
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
	ControlRegistry.MustRegister(&accessWildcardAction{
		Definition: Build(
			WithID("ACCESS.002"),
			WithDescription("No bucket policy statement may grant Allow with wildcard action s3:*"),
			WithSeverity(High),
			WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(a)(2)(i)"),
			WithProfileRationale("hipaa", "Least privilege — no wildcard actions"),
		),
	})
}

// Evaluate checks every S3 bucket for wildcard Allow statements.
func (inv *accessWildcardAction) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		policyJSON := extractPolicyJSON(a)
		stmts, err := ParsePolicyStatements(policyJSON)
		if err != nil || len(stmts) == 0 {
			continue // no policy or unparseable — not a violation
		}

		for _, s := range stmts {
			if s.IsAllow() && s.HasWildcardAction() {
				sid := s.Sid
				if sid == "" {
					sid = "(unnamed)"
				}
				return inv.FailResult(
					fmt.Sprintf("Bucket %s: policy statement %q grants Allow with wildcard action s3:* — this permits all S3 operations including delete and ACL modification", a.ID, sid),
					fmt.Sprintf("Replace s3:* with the minimum required actions. For sync patterns use: %s", strings.Join(minimumSyncActions, ", ")),
				)
			}
		}
	}

	return inv.PassResult()
}

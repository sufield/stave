package gaps

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// classifyRemediation maps a property path to an actionable
// remediation hint. Four classes, distinguished by who can close
// the gap:
//
//   - "tag":       the path is `<something>.tags.<key>`. Operator
//     or agent adds a tag via the cloud provider's
//     tag-resource API. FixableByAgent: true.
//   - "api":       the value requires a secondary cloud API call
//     (Access Advisor, CloudTrail data events, IAM
//     service-last-accessed) that is not in the
//     standard observation surface. FixableByAgent:
//     false — the agent cannot conjure the data.
//   - "collector": the value requires a collector-side analysis
//     (cross-inventory ghost checks, intent matching,
//     delegation walks). The collector code itself
//     must grow. FixableByAgent: false.
//   - "derived":   the value is a transform-time projection over
//     data the source already carries (typically
//     Steampipe columns). An agent authoring a
//     Steampipe → Stave mapping can add the field
//     mapping. FixableByAgent: true.
//
// The CLI command is a template, not a per-resource substitution.
// The brief explicitly defers per-asset-ID command rendering to a
// future `--verbose` flag.
//
// Classification is path-pattern driven (not a static per-property
// list), so new controls that follow the existing naming
// conventions for permission_drift / has_ghost_ / intent_match /
// access_advisor / unused_service / delegation classify
// automatically. New conventions land here as one more pattern
// rather than touching every property.
func classifyRemediation(path string, at kernel.AssetType, isIntent bool) Remediation {
	if _, key, found := strings.Cut(path, ".tags."); found {
		return Remediation{
			Type:           RemediationTag,
			FixableByAgent: true,
			Guidance:       "Add this tag to the resource via the cloud provider's tag-resource API.",
			Command:        tagCommand(at, key),
			Effort:         EffortPerAsset,
		}
	}

	rel := strings.TrimPrefix(path, "properties.")

	// "api" — properties whose value requires a secondary cloud
	// API call beyond the standard inventory surface. Stave can
	// evaluate them once the collector calls the right API, but
	// the agent loop cannot synthesise the result.
	if matchesAnySegment(rel, "permission_drift", "access_advisor", "unused_service", "unused_service_ratio") {
		return Remediation{
			Type:           RemediationAPI,
			FixableByAgent: false,
			Guidance:       "Requires a secondary cloud API call (Access Advisor / service-last-accessed) not exposed by the standard inventory. Collector must call the API and stamp the result.",
			Command:        fmt.Sprintf("Collector must compute %s from iam:GenerateServiceLastAccessedDetails (or equivalent); see docs/extractor-*.md.", rel),
			Effort:         EffortSecondaryAPI,
		}
	}

	// "collector" — properties whose value requires a cross-
	// inventory or analytical walk inside the collector. A
	// transform agent cannot derive these from a single row.
	if matchesSegment(rel, "has_ghost_") ||
		strings.Contains(rel, ".has_ghost_") ||
		matchesAnySegment(rel, "intent_match", "delegation") ||
		strings.Contains(rel, ".intent_match.") ||
		strings.Contains(rel, ".delegation.") {
		return Remediation{
			Type:           RemediationCollector,
			FixableByAgent: false,
			Guidance:       "Requires a collector-side analysis (cross-inventory or relational walk). The collector code must grow to cover it.",
			Command:        fmt.Sprintf("Collector must compute %s; see docs/extractor-*.md for the property-derivation guide.", rel),
			Effort:         EffortCollectorAnalysis,
		}
	}

	// "derived" — anything else. A transform-time projection over
	// data the source row already carries; an agent authoring a
	// Steampipe → Stave mapping can add the field.
	_ = isIntent // reserved: future "intent" remediation may surface a taxonomy doc reference.
	return Remediation{
		Type:           RemediationDerived,
		FixableByAgent: true,
		Guidance:       "Add this property to the Steampipe → Stave mapping; the source row likely carries the value.",
		Command:        fmt.Sprintf("Add %s to the field map for %s in contracts/steampipe/%s.yaml; see docs/extractor-prompt.md.", rel, at, at),
		Effort:         EffortMappingChange,
	}
}

// matchesSegment returns true when seg appears as a prefix of any
// dot-separated segment in rel. Used to spot ".has_ghost_" inside
// "identity.trust_policy.has_ghost_principal" — but NOT inside
// "has_ghost_principal_count" if a future control follows that
// shape, since matching by segment prevents accidental substring
// hits.
func matchesSegment(rel, seg string) bool {
	for p := range strings.SplitSeq(rel, ".") {
		if strings.HasPrefix(p, seg) {
			return true
		}
	}
	return false
}

// matchesAnySegment returns true when rel has at least one dot-
// segment equal to one of the supplied segments. Distinguishes
// "permission_drift.threshold_exceeded" (matches) from
// "permission_drift_count" (does not).
func matchesAnySegment(rel string, segs ...string) bool {
	for p := range strings.SplitSeq(rel, ".") {
		if slices.Contains(segs, p) {
			return true
		}
	}
	return false
}

// tagCommand returns the canonical AWS CLI tag-resource command
// template for the asset type. Per-service tagging APIs differ
// (s3api put-bucket-tagging vs iam tag-role vs ec2 create-tags
// vs kms tag-resource); the template picks the right verb so the
// operator copies a runnable shape, not a generic skeleton.
func tagCommand(at kernel.AssetType, key string) string {
	switch at {
	case "aws_s3_bucket":
		return fmt.Sprintf("aws s3api put-bucket-tagging --bucket <name> --tagging 'TagSet=[{Key=%s,Value=<value>}]'", key)
	case "aws_iam_role":
		return fmt.Sprintf("aws iam tag-role --role-name <name> --tags Key=%s,Value=<value>", key)
	case "aws_iam_user":
		return fmt.Sprintf("aws iam tag-user --user-name <name> --tags Key=%s,Value=<value>", key)
	case "aws_kms_key":
		return fmt.Sprintf("aws kms tag-resource --key-id <id> --tags TagKey=%s,TagValue=<value>", key)
	case "aws_ec2_instance", "aws_ec2_security_group", "aws_ebs_snapshot", "aws_ebs_volume", "aws_vpc", "aws_ec2_subnet":
		return fmt.Sprintf("aws ec2 create-tags --resources <id> --tags Key=%s,Value=<value>", key)
	case "aws_lambda_function":
		return fmt.Sprintf("aws lambda tag-resource --resource <arn> --tags %s=<value>", key)
	case "aws_sns_topic":
		return fmt.Sprintf("aws sns tag-resource --resource-arn <arn> --tags Key=%s,Value=<value>", key)
	case "aws_sqs_queue":
		return fmt.Sprintf("aws sqs tag-queue --queue-url <url> --tags %s=<value>", key)
	case "aws_cognito_user_pool", "aws_cognito_identity_pool":
		return fmt.Sprintf("aws cognito-idp tag-resource --resource-arn <arn> --tags %s=<value>", key)
	case "aws_cloudtrail_trail":
		return fmt.Sprintf("aws cloudtrail add-tags --resource-id <arn> --tags-list Key=%s,Value=<value>", key)
	case "aws_bedrock_agent":
		return fmt.Sprintf("aws bedrock-agent tag-resource --resource-arn <arn> --tags %s=<value>", key)
	}
	return fmt.Sprintf("# Tag %s on %s with key=%s (consult provider tagging API).", at, at, key)
}

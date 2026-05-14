package gaps

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// classifyRemediation maps a property path to an actionable
// remediation hint. Two classes:
//
//   - "tag":  the path is `<something>.tags.<key>`. The operator
//     adds a tag using the cloud provider's tag-resource
//     API; effort is seconds-per-asset.
//   - "collector": every other class. The collector or extractor
//     must populate the property; effort is a code change.
//
// The CLI command is a template, not a per-resource substitution.
// The brief explicitly defers per-asset-ID command rendering to a
// future `--verbose` flag.
func classifyRemediation(path string, at kernel.AssetType, isIntent bool) Remediation {
	if _, key, found := strings.Cut(path, ".tags."); found {
		return Remediation{
			Type:    "tag",
			Command: tagCommand(at, key),
			Effort:  "30 seconds per asset",
		}
	}
	// A handful of paths are well-known "collector must
	// compute this" cases: delegation, permission_drift,
	// intent_match families. Surface them with a more specific
	// doc pointer. Everything else falls through to the generic
	// "see the extractor guide" hint.
	rel := strings.TrimPrefix(path, "properties.")
	for _, prefix := range []string{
		"delegation.", "identity.delegation.",
		"permission_drift.", "identity.permission_drift.",
		"intent_match.", "identity.intent_match.",
	} {
		if strings.HasPrefix(rel, prefix) {
			return Remediation{
				Type:    "collector",
				Command: fmt.Sprintf("Collector must compute %s; see docs/extractor-*.md for the property-derivation guide.", rel),
				Effort:  "Collector code change",
			}
		}
	}
	_ = isIntent // reserved: future "intent" remediation may surface a taxonomy doc reference.
	return Remediation{
		Type:    "collector",
		Command: fmt.Sprintf("Collector must populate %s on %s observations; see docs/extractor-prompt.md.", rel, at),
		Effort:  "Collector code change",
	}
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

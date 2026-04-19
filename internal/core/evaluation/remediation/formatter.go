package remediation

import (
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// preserveTokens are placeholder tokens that must NEVER be substituted
// by the formatter. They carry semantic meaning the user resolves
// manually — e.g. `<current>` in multi-flag PAB commands means
// "preserve existing value for this flag", which the formatter
// cannot invent from asset metadata.
var preserveTokens = map[string]struct{}{
	"<current>": {},
}

// FormatRemediationAction substitutes placeholder tokens in a prose
// CLI template with values derived from the specific asset the
// finding applies to. Delivers docs/product/metrics.md § Metric 4's
// asset-parameterized-CLI target.
//
// Substitution rules:
//   - `<current>` is preserved verbatim (see preserveTokens).
//   - ARN-derived tokens (`<account>`, `<region>`) substitute when
//     AssetID parses as an AWS ARN; otherwise the placeholder stays.
//   - Short-identifier tokens (`<id>`, `<name>`, plus type-specific
//     `<cluster>`, `<bucket>`, `<role>`, etc.) substitute the asset's
//     short identifier (last ARN segment, or whole AssetID for
//     non-ARN formats).
//   - Unknown tokens are left unchanged with no warning: the template
//     may carry vocabulary this formatter doesn't cover, and
//     mangling is worse than leaving it.
//
// The function never fails; worst case is an unchanged template.
func FormatRemediationAction(template string, a asset.Asset) string {
	if template == "" {
		return ""
	}
	subs := buildSubstitutions(a)
	if len(subs) == 0 {
		return template
	}
	out := template
	for tok, val := range subs {
		if _, skip := preserveTokens[tok]; skip {
			continue
		}
		out = strings.ReplaceAll(out, tok, val)
	}
	return out
}

// buildSubstitutions derives a map of {token → value} from the asset's
// identity. Tokens without a derivable value are absent from the map
// (the template's token stays unchanged).
func buildSubstitutions(a asset.Asset) map[string]string {
	subs := map[string]string{}

	assetID := string(a.ID)
	shortID := extractShortIdentifier(assetID)

	// Generic short-id tokens. Populated for every asset.
	if shortID != "" {
		subs["<id>"] = shortID
		subs["<name>"] = shortID
	}

	// Type-specific short-id tokens. One asset matches one entry.
	switch string(a.Type) {
	case "aws_s3_bucket":
		subs["<bucket>"] = shortID
		subs["<bucket-name>"] = shortID
	case "aws_iam_role":
		subs["<role>"] = shortID
		subs["<role-name>"] = shortID
		subs["<role-arn>"] = assetID
	case "aws_iam_user":
		subs["<user>"] = shortID
		subs["<user-name>"] = shortID
		subs["<user-arn>"] = assetID
	case "aws_iam_policy":
		subs["<policy>"] = shortID
		subs["<policy-name>"] = shortID
		subs["<policy-arn>"] = assetID
	case "aws_eks_cluster":
		subs["<cluster>"] = shortID
		subs["<cluster-name>"] = shortID
	case "aws_kms_key":
		subs["<key-id>"] = shortID
		subs["<key-arn>"] = assetID
	case "aws_cloudtrail_trail":
		subs["<trail-name>"] = shortID
	case "aws_s3_access_point":
		subs["<access-point-name>"] = shortID
	case "aws_lambda_function":
		subs["<function>"] = shortID
		subs["<function-name>"] = shortID
	case "aws_ecs_service":
		subs["<service>"] = shortID
		subs["<service-name>"] = shortID
	case "aws_vpc":
		subs["<vpc-id>"] = shortID
	case "aws_sqs_queue":
		subs["<queue>"] = shortID
		subs["<queue-name>"] = shortID
	}

	// ARN-derived account + region tokens.
	if acct, region, ok := parseARNContext(assetID); ok {
		if acct != "" {
			subs["<account>"] = acct
			subs["<account-id>"] = acct
		}
		if region != "" {
			subs["<region>"] = region
		}
	}

	// Generic ARN token for any asset whose ID is an ARN.
	if strings.HasPrefix(assetID, "arn:aws:") {
		subs["<arn>"] = assetID
	}

	return subs
}

// extractShortIdentifier returns the "short" name of an asset
// suitable for <name>/<id> substitution. ARN inputs yield the last
// path component (after the final `/` or `:`). Non-ARN inputs are
// returned verbatim.
func extractShortIdentifier(assetID string) string {
	if assetID == "" {
		return ""
	}
	if !strings.HasPrefix(assetID, "arn:") {
		return assetID
	}
	// ARN format: arn:partition:service:region:account:resource
	// The resource part may contain "/" — take the segment after the
	// last "/" or, if none, after the last ":".
	if i := strings.LastIndex(assetID, "/"); i >= 0 {
		return assetID[i+1:]
	}
	if i := strings.LastIndex(assetID, ":"); i >= 0 {
		return assetID[i+1:]
	}
	return assetID
}

// parseARNContext extracts (account, region) from an ARN. Returns
// (account, region, true) on success, ("", "", false) otherwise.
// ARN format: arn:partition:service:region:account:resource — six
// colon-separated fields, any of which may be empty per AWS rules.
func parseARNContext(assetID string) (string, string, bool) {
	if !strings.HasPrefix(assetID, "arn:") {
		return "", "", false
	}
	parts := strings.SplitN(assetID, ":", 6)
	if len(parts) < 6 {
		return "", "", false
	}
	// parts[0]=arn, parts[1]=partition, parts[2]=service,
	// parts[3]=region, parts[4]=account, parts[5]=resource
	return parts[4], parts[3], true
}

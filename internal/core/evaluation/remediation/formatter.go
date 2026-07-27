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

	// Type-specific tokens from provider-registered mappings.
	for _, td := range TypeTokens[string(a.Type)] {
		if td.UseFullID {
			subs[td.Placeholder] = assetID
		} else {
			subs[td.Placeholder] = shortID
		}
	}

	// ARN-derived account + region tokens, plus the generic <arn>
	// token for any asset whose ID parses as an ARN. Consolidated
	// here so the parsing decision lives in one place.
	if ctx, ok := parseARNContext(assetID); ok {
		if ctx.Account != "" {
			subs["<account>"] = ctx.Account
			subs["<account-id>"] = ctx.Account
		}
		if ctx.Region != "" {
			subs["<region>"] = ctx.Region
		}
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

// ARNContext carries the AWS account and region extracted from an
// ARN. Named fields prevent the (account, region) callers from
// swapping the two strings — both are short, both are opaque, and
// the previous (string, string, bool) tuple shape made the swap
// silently compile.
type ARNContext struct {
	Account string
	Region  string
}

// parseARNContext extracts the account and region from an ARN.
// ok=false when the input is not an ARN-shaped string.
// ARN format: arn:partition:service:region:account:resource — six
// colon-separated fields, any of which may be empty per AWS rules.
func parseARNContext(assetID string) (ARNContext, bool) {
	if !strings.HasPrefix(assetID, "arn:") {
		return ARNContext{}, false
	}
	remaining := assetID[4:] // skip "arn:"
	var found bool

	// partition
	_, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return ARNContext{}, false
	}
	// service
	_, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return ARNContext{}, false
	}
	// region
	var region string
	region, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return ARNContext{}, false
	}
	// account (the resource is whatever remains, and may itself contain
	// colons — we don't parse it, so discard the tail)
	var account string
	account, _, found = strings.Cut(remaining, ":")
	if !found {
		return ARNContext{}, false
	}
	return ARNContext{Account: account, Region: region}, true
}

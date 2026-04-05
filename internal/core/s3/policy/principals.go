package policy

import (
	"regexp"
	"slices"
)

// reAccountID matches exactly 12 digits (AWS Account ID format).
var reAccountID = regexp.MustCompile(`^\d{12}$`)

// isAccountIDOnly reports whether the principal is a bare 12-digit account ID.
func isAccountIDOnly(principal string) bool {
	return reAccountID.MatchString(principal)
}

// extractPrincipalARNs extracts concrete AWS ARNs (excluding wildcards)
// from a decoded Principal field.
func extractPrincipalARNs(principal any) []string {
	var target any
	switch p := principal.(type) {
	case string:
		target = p
	case map[string]any:
		if awsEntry, ok := p[principalAWS]; ok {
			target = awsEntry
		}
	}
	if target == nil {
		return nil
	}

	candidates := NormalizeStringOrSlice(target)
	filtered := slices.DeleteFunc(candidates, func(arn string) bool {
		return arn == "" || isWildcardPrincipal(arn)
	})
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

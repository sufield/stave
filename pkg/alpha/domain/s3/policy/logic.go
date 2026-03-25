// Package policy provides S3 bucket policy analysis including action classification,
// principal extraction, and network scope evaluation.
package policy

import (
	"regexp"
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

type actionMask uint8

const (
	actionRead actionMask = 1 << iota
	actionList
	actionWrite
	actionDelete
	actionACLRead
	actionACLWrite

	actionAll = actionRead |
		actionList |
		actionWrite |
		actionDelete |
		actionACLRead |
		actionACLWrite
)

type networkScope string

var (
	// AWS Account IDs are exactly 12 digits.
	reAccountID = regexp.MustCompile(`^\d{12}$`)
)

func (s networkScope) rank() int {
	switch string(s) {
	case scopeVPCRestricted:
		return 3
	case scopeIPRestricted:
		return 2
	case scopeOrgRestricted:
		return 1
	default:
		return 0 // public
	}
}

func (s networkScope) weakerThan(other networkScope) bool {
	return s.rank() < other.rank()
}

var actionRegistry = map[string]actionMask{
	wildcard:   actionAll,
	s3Wildcard: actionAll,

	actionGetObject:          actionRead,
	actionListBucket:         actionList,
	actionListBucketVersions: actionList,
	actionPutObject:          actionWrite,
	actionPutObjectACL:       actionWrite | actionACLWrite,
	actionPutBucketPolicy:    actionWrite,
	actionDeleteObject:       actionDelete,
	actionDeleteBucket:       actionDelete,
	actionPutBucketACL:       actionACLWrite,
	actionGetBucketACL:       actionACLRead,
	actionGetObjectACL:       actionACLRead,
}

func (m actionMask) has(flag actionMask) bool {
	return m&flag != 0
}

func (s Statement) ResolveActions() (actionMask, bool) {
	return resolveActionMask([]string(s.Action))
}

func resolveActionMask(actions []string) (actionMask, bool) {
	var (
		mask            actionMask
		hasFullWildcard bool
	)

	for _, action := range actions {
		action = strings.ToLower(action)
		am, isFullWildcard := classifyPolicyAction(action)
		mask |= am
		hasFullWildcard = hasFullWildcard || isFullWildcard

		if mask == actionAll && hasFullWildcard {
			break
		}
	}
	return mask, hasFullWildcard
}

func classifyPolicyAction(action string) (actionMask, bool) {
	if mask, ok := actionRegistry[action]; ok {
		isFullWildcard := action == wildcard || action == s3Wildcard
		return mask, isFullWildcard
	}

	switch {
	case strings.HasPrefix(action, actionPrefixGet):
		return actionRead, false
	case strings.HasPrefix(action, actionPrefixList):
		return actionList, false
	default:
		return 0, false
	}
}

func hasWildcardResource(resources []string) bool {
	for _, res := range resources {
		if res == wildcard || res == s3GlobalResource {
			return true
		}
	}
	return false
}

// isAccountIDOnly identifies whether the principal is a specific AWS account ID.
func isAccountIDOnly(principal string) bool {
	return reAccountID.MatchString(principal)
}

// isWriteAction returns true if the given IAM action grants write or delete access.
func isWriteAction(action string) bool {
	action = strings.ToLower(action)
	switch action {
	case wildcard, s3Wildcard,
		actionPutObject, actionDeleteObject,
		actionPutBucketPolicy, actionDeleteBucket,
		actionPutObjectACL, actionPutBucketACL:
		return true
	}
	return strings.HasPrefix(action, actionPrefixPut) ||
		strings.HasPrefix(action, actionPrefixDelete)
}

// extractPrincipalARNs extracts string ARNs from a Principal field, excluding "*".
func extractPrincipalARNs(principal any) []string {
	var raw any
	switch p := principal.(type) {
	case string:
		raw = p
	case map[string]any:
		var ok bool
		raw, ok = p[principalAWS]
		if !ok {
			return nil
		}
	default:
		return nil
	}
	return filterConcreteARNs(NormalizeStringOrSlice(raw))
}

// filterConcreteARNs removes empty strings and wildcards from ARN lists.
func filterConcreteARNs(arns []string) []string {
	var out []string
	for _, arn := range arns {
		if arn != "" && arn != wildcard {
			out = append(out, arn)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// conditionScope returns the most restrictive scope label for a single statement.
// Precedence: vpc > ip > org.
func conditionScope(ca ConditionAnalysis) networkScope {
	if ca.HasVPCCondition {
		return networkScope(scopeVPCRestricted)
	}
	if ca.HasIPCondition {
		return networkScope(scopeIPRestricted)
	}
	if ca.HasOrgCondition {
		return networkScope(scopeOrgRestricted)
	}
	return networkScope(scopePublic)
}

// toKernelNetworkScope maps the adapter-private networkScope to the domain type.
func toKernelNetworkScope(s networkScope) kernel.NetworkScope {
	switch string(s) {
	case scopePublic:
		return kernel.NetworkScopePublic
	case scopeIPRestricted:
		return kernel.NetworkScopeIPRestricted
	case scopeVPCRestricted:
		return kernel.NetworkScopeVPCRestricted
	case scopeOrgRestricted:
		return kernel.NetworkScopeOrgRestricted
	default:
		return kernel.NetworkScopeUnknown
	}
}

// NormalizeStringOrSlice converts a string or []string to []string.
func NormalizeStringOrSlice(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return val
	}
	return nil
}

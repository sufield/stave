package policy

import (
	"regexp"
	"strings"

	"github.com/samber/lo"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

type policyActionMask uint8

const (
	policyActionRead policyActionMask = 1 << iota
	policyActionList
	policyActionWrite
	policyActionDelete
	policyActionACLRead
	policyActionACLWrite

	policyActionAll = policyActionRead |
		policyActionList |
		policyActionWrite |
		policyActionDelete |
		policyActionACLRead |
		policyActionACLWrite
)

type networkScope string

var (
	// AWS Account IDs are exactly 12 digits.
	reAccountID = regexp.MustCompile(`^\d{12}$`)
)

func (s networkScope) rank() int {
	switch string(s) {
	case policyScopeVPCRestricted:
		return 3
	case policyScopeIPRestricted:
		return 2
	case policyScopeOrgRestricted:
		return 1
	default:
		return 0 // public
	}
}

func (s networkScope) weakerThan(other networkScope) bool {
	return s.rank() < other.rank()
}

var policyActionRegistry = map[string]policyActionMask{
	policyWildcard:   policyActionAll,
	policyS3Wildcard: policyActionAll,

	policyActionGetObject:          policyActionRead,
	policyActionListBucket:         policyActionList,
	policyActionListBucketVersions: policyActionList,
	policyActionPutObject:          policyActionWrite,
	policyActionPutObjectACL:       policyActionWrite | policyActionACLWrite,
	policyActionPutBucketPolicy:    policyActionWrite,
	policyActionDeleteObject:       policyActionDelete,
	policyActionDeleteBucket:       policyActionDelete,
	policyActionPutBucketACL:       policyActionACLWrite,
	policyActionGetBucketACL:       policyActionACLRead,
	policyActionGetObjectACL:       policyActionACLRead,
}

func (m policyActionMask) has(flag policyActionMask) bool {
	return m&flag != 0
}

func (s Statement) ResolveActions() (policyActionMask, bool) {
	return resolveActionMask([]string(s.Action))
}

func resolveActionMask(actions []string) (policyActionMask, bool) {
	var (
		mask            policyActionMask
		hasFullWildcard bool
	)

	for _, action := range actions {
		action = strings.ToLower(action)
		actionMask, isFullWildcard := classifyPolicyAction(action)
		mask |= actionMask
		hasFullWildcard = hasFullWildcard || isFullWildcard

		if mask == policyActionAll && hasFullWildcard {
			break
		}
	}
	return mask, hasFullWildcard
}

func classifyPolicyAction(action string) (policyActionMask, bool) {
	if mask, ok := policyActionRegistry[action]; ok {
		isFullWildcard := action == policyWildcard || action == policyS3Wildcard
		return mask, isFullWildcard
	}

	switch {
	case strings.HasPrefix(action, policyActionPrefixGet):
		return policyActionRead, false
	case strings.HasPrefix(action, policyActionPrefixList):
		return policyActionList, false
	default:
		return 0, false
	}
}

func hasWildcardResource(resources []string) bool {
	return lo.SomeBy(resources, func(res string) bool {
		return res == policyWildcard || res == policyS3GlobalResource
	})
}

// isAccountIDOnly identifies whether the principal is a specific AWS account ID.
func isAccountIDOnly(principal string) bool {
	return reAccountID.MatchString(principal)
}

// isWriteAction returns true if the given IAM action grants write or delete access.
func isWriteAction(action string) bool {
	action = strings.ToLower(action)
	switch action {
	case policyWildcard, policyS3Wildcard,
		policyActionPutObject, policyActionDeleteObject,
		policyActionPutBucketPolicy, policyActionDeleteBucket,
		policyActionPutObjectACL, policyActionPutBucketACL:
		return true
	}
	return strings.HasPrefix(action, policyActionPrefixPut) ||
		strings.HasPrefix(action, policyActionPrefixDelete)
}

// extractPrincipalARNs extracts string ARNs from a Principal field, excluding "*".
func extractPrincipalARNs(principal any) []string {
	var raw any
	switch p := principal.(type) {
	case string:
		raw = p
	case map[string]any:
		var ok bool
		raw, ok = p[policyPrincipalAWS]
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
	out := lo.Filter(arns, func(arn string, _ int) bool {
		return arn != "" && arn != policyWildcard
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// conditionScope returns the most restrictive scope label for a single statement.
// Precedence: vpc > ip > org.
func conditionScope(ca ConditionAnalysis) networkScope {
	if ca.HasVPCCondition {
		return networkScope(policyScopeVPCRestricted)
	}
	if ca.HasIPCondition {
		return networkScope(policyScopeIPRestricted)
	}
	if ca.HasOrgCondition {
		return networkScope(policyScopeOrgRestricted)
	}
	return networkScope(policyScopePublic)
}

// toKernelNetworkScope maps the adapter-private networkScope to the domain type.
func toKernelNetworkScope(s networkScope) kernel.NetworkScope {
	switch string(s) {
	case policyScopePublic:
		return kernel.NetworkScopePublic
	case policyScopeIPRestricted:
		return kernel.NetworkScopeIPRestricted
	case policyScopeVPCRestricted:
		return kernel.NetworkScopeVPCRestricted
	case policyScopeOrgRestricted:
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
		return lo.FilterMap(val, func(item any, _ int) (string, bool) {
			s, ok := item.(string)
			return s, ok
		})
	case []string:
		return val
	}
	return nil
}

// Package policy provides S3 bucket policy analysis including action classification,
// principal extraction, and network scope evaluation.
package policy

import (
	"regexp"
	"slices"
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// actionMask uses bit-flags to represent categories of IAM actions.
type actionMask uint8

const (
	actionRead actionMask = 1 << iota
	actionList
	actionWrite
	actionDelete
	actionACLRead
	actionACLWrite

	actionAll = actionRead | actionList | actionWrite | actionDelete | actionACLRead | actionACLWrite
)

// has checks if the mask contains a specific flag.
func (m actionMask) has(flag actionMask) bool {
	return m&flag != 0
}

var (
	// AWS Account IDs are exactly 12 digits.
	reAccountID = regexp.MustCompile(`^\d{12}$`)

	// actionRegistry maps common S3 actions to their functional categories.
	actionRegistry = map[string]actionMask{
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
)

// ResolveActions aggregates all actions in a statement into a single bitmask.
func (s Statement) ResolveActions() (actionMask, bool) {
	var (
		mask            actionMask
		hasFullWildcard bool
	)
	for _, action := range s.Action {
		m, isWild := classifyAction(strings.ToLower(action))
		mask |= m
		hasFullWildcard = hasFullWildcard || isWild
		if mask == actionAll && hasFullWildcard {
			break
		}
	}
	return mask, hasFullWildcard
}

// classifyAction identifies the category of an individual IAM action string.
func classifyAction(action string) (actionMask, bool) {
	if mask, ok := actionRegistry[action]; ok {
		return mask, action == wildcard || action == s3Wildcard
	}
	switch {
	case strings.HasPrefix(action, actionPrefixGet):
		return actionRead, false
	case strings.HasPrefix(action, actionPrefixList):
		return actionList, false
	case strings.HasPrefix(action, actionPrefixPut):
		return actionWrite, false
	case strings.HasPrefix(action, actionPrefixDelete):
		return actionDelete, false
	default:
		return 0, false
	}
}

// isWriteAction returns true if the given IAM action grants write, delete,
// or ACL-write access. Uses classifyAction to stay in sync with the registry.
func isWriteAction(action string) bool {
	mask, _ := classifyAction(strings.ToLower(action))
	return mask.has(actionWrite) || mask.has(actionDelete) || mask.has(actionACLWrite)
}

func hasWildcardResource(resources []string) bool {
	for _, res := range resources {
		if res == wildcard || res == s3GlobalResource {
			return true
		}
	}
	return false
}

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
		return arn == "" || arn == wildcard
	})
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

// resolveConditionScope maps a ConditionAnalysis directly to a kernel.NetworkScope.
// Precedence: vpc > ip > org > public.
func resolveConditionScope(ca ConditionAnalysis) kernel.NetworkScope {
	switch {
	case ca.HasVPCCondition:
		return kernel.NetworkScopeVPCRestricted
	case ca.HasIPCondition:
		return kernel.NetworkScopeIPRestricted
	case ca.HasOrgCondition:
		return kernel.NetworkScopeOrgRestricted
	default:
		return kernel.NetworkScopePublic
	}
}

// NormalizeStringOrSlice handles the AWS JSON polymorphism of single string vs array.
func NormalizeStringOrSlice(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []string:
		return val
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

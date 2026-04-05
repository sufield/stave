package policy

import (
	"slices"
	"strings"
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

// actionRegistry maps common S3 actions to their functional categories.
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
		return mask, isWildcardAction(action)
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
// or ACL-write access.
func isWriteAction(action string) bool {
	mask, _ := classifyAction(strings.ToLower(action))
	return mask.has(actionWrite) || mask.has(actionDelete) || mask.has(actionACLWrite)
}

// hasWildcardResource reports whether any resource matches all S3 objects.
func hasWildcardResource(resources []string) bool {
	return slices.ContainsFunc(resources, isWildcardResource)
}

package policy

import (
	"slices"
	"strings"
)

// ActionMask uses bit-flags to represent categories of IAM actions.
type ActionMask uint8

// IAM action category bitmask constants.
const (
	ActionRead ActionMask = 1 << iota
	ActionList
	ActionWrite
	ActionDelete
	actionACLRead
	actionACLWrite

	actionAll = ActionRead | ActionList | ActionWrite | ActionDelete | actionACLRead | actionACLWrite
)

// has checks if the mask contains a specific flag.
func (m ActionMask) has(flag ActionMask) bool {
	return m&flag != 0
}

// actionRegistry maps common S3 actions to their functional categories.
var actionRegistry = map[string]ActionMask{
	wildcard:   actionAll,
	s3Wildcard: actionAll,

	actionGetObject:          ActionRead,
	actionListBucket:         ActionList,
	actionListBucketVersions: ActionList,
	actionPutObject:          ActionWrite,
	actionPutObjectACL:       ActionWrite | actionACLWrite,
	actionPutBucketPolicy:    ActionWrite,
	actionDeleteObject:       ActionDelete,
	actionDeleteBucket:       ActionDelete,
	actionPutBucketACL:       actionACLWrite,
	actionGetBucketACL:       actionACLRead,
	actionGetObjectACL:       actionACLRead,
}

// ResolveActions aggregates all actions in a statement into a single bitmask.
func (s Statement) ResolveActions() (ActionMask, bool) {
	var (
		mask            ActionMask
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
func classifyAction(action string) (ActionMask, bool) {
	if mask, ok := actionRegistry[action]; ok {
		return mask, isWildcardAction(action)
	}
	switch {
	case strings.HasPrefix(action, actionPrefixGet):
		return ActionRead, false
	case strings.HasPrefix(action, actionPrefixList):
		return ActionList, false
	case strings.HasPrefix(action, actionPrefixPut):
		return ActionWrite, false
	case strings.HasPrefix(action, actionPrefixDelete):
		return ActionDelete, false
	default:
		return 0, false
	}
}

// isWriteAction returns true if the given IAM action grants write, delete,
// or ACL-write access.
func isWriteAction(action string) bool {
	mask, _ := classifyAction(strings.ToLower(action))
	return mask.has(ActionWrite) || mask.has(ActionDelete) || mask.has(actionACLWrite)
}

// GrantsReadAccess reports whether the statement's actions include object read
// capability (s3:GetObject, s3:*, or *).
func (s Statement) GrantsReadAccess() bool {
	mask, _ := s.ResolveActions()
	return mask.has(ActionRead)
}

// hasWildcardResource reports whether any resource matches all S3 objects.
func hasWildcardResource(resources []string) bool {
	return slices.ContainsFunc(resources, isWildcardResource)
}

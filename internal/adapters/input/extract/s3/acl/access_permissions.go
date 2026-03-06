package acl

// accessPermissionMask is used by exposure classification helpers.
type accessPermissionMask uint32

const (
	accessPermRead accessPermissionMask = 1 << iota
	accessPermWrite
	accessPermList
	accessPermACLRead
	accessPermACLWrite
	accessPermDelete

	accessPermAll = accessPermRead | accessPermWrite | accessPermList | accessPermACLRead | accessPermACLWrite | accessPermDelete
)

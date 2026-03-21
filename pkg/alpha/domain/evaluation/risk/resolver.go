package risk

// PermissionResolver maps a single action string to its Permission bits.
// Implementations handle vendor-specific lookup (exact match, prefix, trie).
type PermissionResolver interface {
	Resolve(action string) Permission
}

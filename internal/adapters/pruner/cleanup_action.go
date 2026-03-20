package pruner

// CleanupAction represents the kind of cleanup operation (delete or move).
type CleanupAction string

const (
	// ActionDelete indicates snapshot files will be permanently deleted.
	ActionDelete CleanupAction = "DELETE"
	// ActionMove indicates snapshot files will be moved to an archive directory.
	ActionMove CleanupAction = "MOVE"
)

// ModeString returns the wire-format mode string for JSON output.
// If dryRun is true, the mode is "DRY_RUN" regardless of action.
func (a CleanupAction) ModeString(dryRun bool) string {
	if dryRun {
		return "DRY_RUN"
	}
	return string(a)
}

package fix

// Remediator abstracts user interaction during the fix-loop workflow.
// Adopters implement this interface to control how the engine confirms
// remediation steps and reports progress.
//
// For headless / CI pipelines, use NopRemediator.
// For interactive CLI sessions, implement a version that prompts the user.
type Remediator interface {
	// ConfirmFix asks whether to proceed with the fix for the given asset.
	// Headless implementations should return true unconditionally.
	ConfirmFix(controlID, assetID string) bool

	// LogProgress reports a human-readable status message during the loop.
	// Implementations may write to a terminal, structured log, or discard.
	LogProgress(msg string)
}

// NopRemediator auto-approves every fix and discards progress messages.
// Use this for automated pipelines and headless execution.
type NopRemediator struct{}

func (NopRemediator) ConfirmFix(string, string) bool { return true }
func (NopRemediator) LogProgress(string)             {}

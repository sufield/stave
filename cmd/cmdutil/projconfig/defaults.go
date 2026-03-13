package projconfig

// This file provides simple value accessors for the Evaluator.
// It separates the "Value" (what the code needs) from the "Provenance"
// (where the value came from), which is handled by the Evaluator's resolve methods.

// --- Value-Only Accessors ---

// MaxUnsafe returns the effective max-unsafe duration string.
func (e *Evaluator) MaxUnsafe() string {
	return e.resolveMaxUnsafe().Value
}

// SnapshotRetention returns the retention for the current default tier.
func (e *Evaluator) SnapshotRetention() string {
	return e.SnapshotRetentionForTier(e.RetentionTier())
}

// SnapshotRetentionForTier returns the retention duration for a specific tier.
func (e *Evaluator) SnapshotRetentionForTier(tier string) string {
	return e.resolveSnapshotRetention(tier).Value
}

// RetentionTier returns the default retention tier name.
func (e *Evaluator) RetentionTier() string {
	return e.resolveRetentionTier().Value
}

// HasConfiguredTier checks if a specific tier exists in the project configuration.
func (e *Evaluator) HasConfiguredTier(tier string) bool {
	if e.Project == nil || len(e.Project.RetentionTiers) == 0 {
		return false
	}
	_, exists := e.Project.RetentionTiers[NormalizeTier(tier)]
	return exists
}

// CIFailurePolicy returns the failure policy as a typed GatePolicy.
func (e *Evaluator) CIFailurePolicy() GatePolicy {
	return GatePolicy(e.resolveCIFailurePolicy().Value)
}

// --- CLI Default Accessors ---

// OutputMode returns the preferred CLI output format ("text" or "json").
func (e *Evaluator) OutputMode() string {
	return e.resolveCLIOutput().Value
}

// Quiet returns whether quiet mode is enabled by default.
func (e *Evaluator) Quiet() bool {
	return e.resolveCLIQuiet().Value
}

// Sanitize returns whether output sanitization is enabled by default.
func (e *Evaluator) Sanitize() bool {
	return e.resolveCLISanitize().Value
}

// PathMode returns the preferred path display mode ("base" or "full").
func (e *Evaluator) PathMode() string {
	return e.resolveCLIPathMode().Value
}

// AllowUnknownInput returns whether to allow unknown snapshots.
func (e *Evaluator) AllowUnknownInput() bool {
	return e.resolveCLIAllowUnknownInput().Value
}

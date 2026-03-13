package projconfig

// defaults.go provides simple default-value accessors that delegate to the
// Evaluator in config_resolution.go. Each function creates a default evaluator
// (env → project → user → built-in) and returns the scalar value.

// ResolveMaxUnsafeDefault returns the max-unsafe default from env/config/built-in.
func ResolveMaxUnsafeDefault() string {
	return defaultEvaluator().MaxUnsafe().Value
}

// ResolveSnapshotRetentionDefault returns snapshot retention default.
func ResolveSnapshotRetentionDefault() string {
	return defaultEvaluator().SnapshotRetention(ResolveRetentionTierDefault()).Value
}

// ResolveSnapshotRetentionForTier returns retention for a specific tier.
func ResolveSnapshotRetentionForTier(tier string) string {
	return defaultEvaluator().SnapshotRetention(tier).Value
}

// ResolveRetentionTierDefault returns the default retention tier.
func ResolveRetentionTierDefault() string {
	return defaultEvaluator().RetentionTier().Value
}

// HasConfiguredRetentionTier returns true if the project config has a tier defined.
func HasConfiguredRetentionTier(tier string) bool {
	cfg, ok := FindProjectConfig()
	if !ok || len(cfg.RetentionTiers) == 0 {
		return false
	}
	_, exists := cfg.RetentionTiers[NormalizeRetentionTier(tier)]
	return exists
}

// ResolveCIFailurePolicyDefault returns the CI failure policy default.
func ResolveCIFailurePolicyDefault() GatePolicy {
	return GatePolicy(defaultEvaluator().CIFailurePolicy().Value)
}

// ResolveOutputModeDefault returns the output mode default.
func ResolveOutputModeDefault() string {
	return defaultEvaluator().CLIOutput().Value
}

// ResolveQuietDefault returns the quiet default.
func ResolveQuietDefault() bool {
	return defaultEvaluator().CLIQuiet().AsBool()
}

// ResolveSanitizeDefault returns the sanitize default.
func ResolveSanitizeDefault() bool {
	return defaultEvaluator().CLISanitize().AsBool()
}

// ResolvePathModeDefault returns the path-mode default.
func ResolvePathModeDefault() string {
	return defaultEvaluator().CLIPathMode().Value
}

// ResolveAllowUnknownInputDefault returns the allow-unknown-input default.
func ResolveAllowUnknownInputDefault() bool {
	return defaultEvaluator().CLIAllowUnknownInput().AsBool()
}

package projconfig

// defaults.go provides simple default-value accessors that delegate to the
// source-tracked resolvers in config_resolution.go. This eliminates the
// duplicated env→project→user→default resolution chains that previously
// existed in both files.

// projectConfigPtrAndPath returns a pointer to the project config and its
// path, or (nil, "") if no project config is found.
func projectConfigPtrAndPath() (*ProjectConfig, string) {
	cfg, path, ok := FindProjectConfigWithPath()
	if !ok {
		return nil, ""
	}
	return cfg, path
}

// ResolveMaxUnsafeDefault returns the max-unsafe default from env/config/built-in.
func ResolveMaxUnsafeDefault() string {
	cfg, path := projectConfigPtrAndPath()
	return ResolveMaxUnsafeWithSource(cfg, path).Value
}

// ResolveSnapshotRetentionDefault returns snapshot retention default.
func ResolveSnapshotRetentionDefault() string {
	return ResolveSnapshotRetentionForTier(ResolveRetentionTierDefault())
}

// ResolveSnapshotRetentionForTier returns retention for a specific tier.
func ResolveSnapshotRetentionForTier(tier string) string {
	cfg, path := projectConfigPtrAndPath()
	return ResolveSnapshotRetentionWithSource(cfg, path, tier).Value
}

// ResolveRetentionTierDefault returns the default retention tier.
func ResolveRetentionTierDefault() string {
	cfg, path := projectConfigPtrAndPath()
	return ResolveRetentionTierWithSource(cfg, path).Value
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
func ResolveCIFailurePolicyDefault() string {
	cfg, path := projectConfigPtrAndPath()
	return ResolveCIFailurePolicyWithSource(cfg, path).Value
}

// ResolveOutputModeDefault returns the output mode default.
func ResolveOutputModeDefault() string {
	return ResolveCLIOutputWithSource().Value
}

// ResolveQuietDefault returns the quiet default.
func ResolveQuietDefault() bool {
	return ResolveCLIQuietWithSource().Bool
}

// ResolveSanitizeDefault returns the sanitize default.
func ResolveSanitizeDefault() bool {
	return ResolveCLISanitizeWithSource().Bool
}

// ResolvePathModeDefault returns the path-mode default.
func ResolvePathModeDefault() string {
	return ResolveCLIPathModeWithSource().Value
}

// ResolveAllowUnknownInputDefault returns the allow-unknown-input default.
func ResolveAllowUnknownInputDefault() bool {
	return ResolveCLIAllowUnknownInputWithSource().Bool
}

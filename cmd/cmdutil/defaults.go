package cmdutil

import (
	"os"
	"strings"

	"github.com/sufield/stave/internal/envvar"
)

// ResolveMaxUnsafeDefault returns the max-unsafe default from env/config/built-in.
func ResolveMaxUnsafeDefault() string {
	if v := strings.TrimSpace(os.Getenv(envvar.MaxUnsafe.Name)); v != "" {
		return v
	}
	if cfg, ok := FindProjectConfig(); ok {
		if v := strings.TrimSpace(cfg.MaxUnsafe); v != "" {
			return v
		}
	}
	if cfg, ok := FindUserConfig(); ok {
		if v := strings.TrimSpace(cfg.MaxUnsafe); v != "" {
			return v
		}
	}
	return DefaultMaxUnsafeDuration
}

// ResolveSnapshotRetentionDefault returns snapshot retention default.
func ResolveSnapshotRetentionDefault() string {
	return ResolveSnapshotRetentionForTier(ResolveRetentionTierDefault())
}

// ResolveSnapshotRetentionForTier returns retention for a specific tier.
func ResolveSnapshotRetentionForTier(tier string) string {
	if v := strings.TrimSpace(os.Getenv(envvar.SnapshotRetention.Name)); v != "" {
		return v
	}
	if v, ok := resolveRetentionFromProjectConfig(tier); ok {
		return v
	}
	if v, ok := resolveRetentionFromUserConfig(); ok {
		return v
	}
	return DefaultSnapshotRetention
}

func resolveRetentionFromProjectConfig(tier string) (string, bool) {
	cfg, ok := FindProjectConfig()
	if !ok {
		return "", false
	}
	if tc, exists := cfg.RetentionTiers[NormalizeRetentionTier(tier)]; exists {
		if v := strings.TrimSpace(tc.OlderThan); v != "" {
			return v, true
		}
	}
	if v := strings.TrimSpace(cfg.SnapshotRetention); v != "" {
		return v, true
	}
	return "", false
}

func resolveRetentionFromUserConfig() (string, bool) {
	cfg, ok := FindUserConfig()
	if !ok {
		return "", false
	}
	if v := strings.TrimSpace(cfg.SnapshotRetention); v != "" {
		return v, true
	}
	return "", false
}

// ResolveRetentionTierDefault returns the default retention tier.
func ResolveRetentionTierDefault() string {
	if v := strings.TrimSpace(os.Getenv(envvar.RetentionTier.Name)); v != "" {
		return NormalizeRetentionTier(v)
	}
	if cfg, ok := FindProjectConfig(); ok {
		if v := strings.TrimSpace(cfg.RetentionTier); v != "" {
			return NormalizeRetentionTier(v)
		}
	}
	if cfg, ok := FindUserConfig(); ok {
		if v := strings.TrimSpace(cfg.RetentionTier); v != "" {
			return NormalizeRetentionTier(v)
		}
	}
	return DefaultRetentionTier
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
	if v := strings.TrimSpace(os.Getenv(envvar.CIFailurePolicy.Name)); v != "" {
		return v
	}
	if cfg, ok := FindProjectConfig(); ok {
		if v := strings.TrimSpace(cfg.CIFailurePolicy); v != "" {
			return v
		}
	}
	if cfg, ok := FindUserConfig(); ok {
		if v := strings.TrimSpace(cfg.CIFailurePolicy); v != "" {
			return v
		}
	}
	return DefaultCIFailurePolicy
}

// ResolveOutputModeDefault returns the output mode default.
func ResolveOutputModeDefault() string {
	if cfg, ok := FindUserConfig(); ok {
		v := strings.ToLower(strings.TrimSpace(cfg.CLIDefaults.Output))
		if v == "json" || v == "text" {
			return v
		}
	}
	return "text"
}

// ResolveQuietDefault returns the quiet default.
func ResolveQuietDefault() bool {
	if cfg, ok := FindUserConfig(); ok && cfg.CLIDefaults.Quiet != nil {
		return *cfg.CLIDefaults.Quiet
	}
	return false
}

// ResolveSanitizeDefault returns the sanitize default.
func ResolveSanitizeDefault() bool {
	if cfg, ok := FindUserConfig(); ok && cfg.CLIDefaults.Sanitize != nil {
		return *cfg.CLIDefaults.Sanitize
	}
	return false
}

// ResolvePathModeDefault returns the path-mode default.
func ResolvePathModeDefault() string {
	if cfg, ok := FindUserConfig(); ok {
		v := strings.ToLower(strings.TrimSpace(cfg.CLIDefaults.PathMode))
		if v == "base" || v == "full" {
			return v
		}
	}
	return "base"
}

// ResolveAllowUnknownInputDefault returns the allow-unknown-input default.
func ResolveAllowUnknownInputDefault() bool {
	if cfg, ok := FindUserConfig(); ok && cfg.CLIDefaults.AllowUnknownInput != nil {
		return *cfg.CLIDefaults.AllowUnknownInput
	}
	return false
}

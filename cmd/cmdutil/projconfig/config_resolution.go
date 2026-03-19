package projconfig

import (
	"errors"
	"log/slog"

	appconfig "github.com/sufield/stave/internal/app/config"
)

// ConfigKeyCompletions returns config key completions including retention tier
// variants from the project config.
func ConfigKeyCompletions() []string {
	tiers := []string{appconfig.DefaultRetentionTier}

	if cfg, ok, cfgErr := FindProjectConfig(); cfgErr != nil {
		slog.Warn("failed to load project config for completions", "error", cfgErr)
	} else if ok {
		if t := appconfig.NormalizeTier(cfg.RetentionTier); t != "" {
			tiers = append(tiers, t)
		}
		for tier := range cfg.RetentionTiers {
			if t := appconfig.NormalizeTier(tier); t != "" {
				tiers = append(tiers, t)
			}
		}
	}

	return appconfig.BuildKeyCompletions(tiers)
}

// DefaultEvaluator is the package-level evaluator set during initialization.
// Use Global() to access it safely.
var DefaultEvaluator *appconfig.Evaluator

// configLoadErr records any error encountered when lazily building the
// package-level evaluator. Commands should call GlobalConfigError() early
// in their RunE/PreRunE to fail fast on malformed config files.
var configLoadErr error

// Global returns the package-level evaluator. Use of this should be minimized
// in favor of passing a local Evaluator instance where possible.
//
// Global always returns a usable evaluator (never nil), even if config loading
// failed. Call GlobalConfigError() to detect whether the evaluator was built
// with degraded (default) values due to a parse or permission error.
func Global() *appconfig.Evaluator {
	if DefaultEvaluator == nil {
		return defaultEvaluator()
	}
	return DefaultEvaluator
}

// GlobalConfigError returns any error that occurred when loading project or
// user configuration for the package-level evaluator. Commands that depend on
// correct config values should check this early and abort if non-nil.
func GlobalConfigError() error {
	// Force lazy init so configLoadErr is populated.
	_ = Global()
	return configLoadErr
}

// defaultEvaluator creates a fresh evaluator from the filesystem.
// Any loading errors are stored in configLoadErr so that callers
// of GlobalConfigError() can detect degraded operation.
func defaultEvaluator() *appconfig.Evaluator {
	var errs []error

	pCfg, pPath, err := FindProjectConfigWithPath("")
	if err != nil {
		slog.Warn("failed to load project config", "error", err)
		errs = append(errs, err)
	}
	uCfg, uPath, _, uErr := FindUserConfigWithPath()
	if uErr != nil {
		slog.Warn("failed to load user config", "error", uErr)
		errs = append(errs, uErr)
	}

	configLoadErr = errors.Join(errs...)
	return appconfig.NewEvaluator(pCfg, pPath, uCfg, uPath)
}

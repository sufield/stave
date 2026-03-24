package projconfig

import (
	"errors"

	appconfig "github.com/sufield/stave/internal/app/config"
)

// DefaultEvaluator is the package-level evaluator set during initialization.
// Use Global() to access it safely.
var DefaultEvaluator *appconfig.Evaluator

// configLoadErr records any error encountered when lazily building the
// package-level evaluator. Commands should call GlobalConfigError() early
// in their RunE/PreRunE to fail fast on malformed config files.
var configLoadErr error

// configWarnings holds config-load warnings for deferred replay.
// These are collected during lazy init (before the logger is configured)
// and replayed by bootstrap after initLogger().
var configWarnings []error

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

// ConfigWarnings returns config-load warnings collected during lazy init.
// Bootstrap calls this after initLogger() to replay warnings through the
// configured logger instead of the pre-bootstrap default.
func ConfigWarnings() []error {
	_ = Global() // force lazy init
	return configWarnings
}

// defaultEvaluator creates a fresh evaluator from the filesystem.
// Any loading errors are stored in configLoadErr so that callers
// of GlobalConfigError() can detect degraded operation.
func defaultEvaluator() *appconfig.Evaluator {
	var errs []error

	pCfg, pPath, err := FindProjectConfigWithPath("")
	if err != nil {
		errs = append(errs, err)
	}
	uCfg, uPath, _, uErr := FindUserConfigWithPath()
	if uErr != nil {
		errs = append(errs, uErr)
	}

	configLoadErr = errors.Join(errs...)
	configWarnings = errs
	return appconfig.NewEvaluator(pCfg, pPath, uCfg, uPath)
}

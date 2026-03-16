package projconfig

import (
	appconfig "github.com/sufield/stave/internal/app/config"
)

// DefaultEvaluator is the package-level evaluator set during initialization.
// Use Global() to access it safely.
var DefaultEvaluator *appconfig.Evaluator

// Global returns the package-level evaluator. Use of this should be minimized
// in favor of passing a local Evaluator instance where possible.
func Global() *appconfig.Evaluator {
	if DefaultEvaluator == nil {
		return defaultEvaluator()
	}
	return DefaultEvaluator
}

// defaultEvaluator creates a fresh evaluator from the filesystem.
func defaultEvaluator() *appconfig.Evaluator {
	pCfg, pPath, _ := FindProjectConfigWithPath("")
	uCfg, uPath, _ := FindUserConfigWithPath()
	return appconfig.NewEvaluator(pCfg, pPath, uCfg, uPath)
}

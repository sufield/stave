package projconfig

import (
	"errors"

	appconfig "github.com/sufield/stave/internal/app/config"
)

// ResolverResult holds the output of building a resolver from the filesystem.
type ResolverResult struct {
	// Resolver is always non-nil. When config loading fails, it is built
	// with default values and Err indicates the degraded state.
	Resolver *appconfig.GovernanceResolver

	// Err is non-nil when project or user configuration could not be loaded
	// (parse errors, permission failures, resolver construction errors).
	// Commands that depend on correct config values should check this
	// early and abort if non-nil.
	Err error

	// Warnings collects config-load issues for deferred replay through
	// the structured logger. Bootstrap replays these after initLogger().
	Warnings []error
}

// BuildResolver constructs a config resolver from the filesystem by loading
// project and user configuration. It always returns a usable resolver (never
// nil), even if config loading failed — check Err to detect degraded operation.
//
// This function is stateless: it does not cache the result or store it in
// package-level variables. Callers should store the resolver in Cobra's
// context (via cmdctx.WithResolver) for downstream commands to retrieve.
func BuildResolver() ResolverResult {
	var errs []error

	pCfg, pPath, err := FindProjectConfigWithPath("")
	if err != nil {
		errs = append(errs, err)
	}
	uCfg, uPath, _, uErr := FindUserConfigWithPath()
	if uErr != nil {
		errs = append(errs, uErr)
	}

	return ResolverResult{
		Resolver: appconfig.NewResolver(pCfg, pPath, uCfg, uPath),
		Err:      errors.Join(errs...),
		Warnings: errs,
	}
}

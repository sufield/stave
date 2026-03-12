package doctor

// Run executes the standard suite of diagnostic checks.
// It returns a slice of Check results and a boolean that is true if any
// check has FAIL status.
func Run(ctx *Context) ([]Check, bool) {
	if ctx == nil {
		ctx = NewContext()
	} else {
		ctx.FillDefaults()
	}

	registry := NewRegistry(StandardChecks()...)
	return RunWithRegistry(*ctx, registry)
}

// StandardChecks returns the default list of diagnostic functions.
func StandardChecks() []CheckFunc {
	return []CheckFunc{
		checkVersionInfo,
		checkOSVersion,
		checkShell,
		checkCI,
		checkContainer,
		checkWorkspaceWritable,
		checkGit,
		checkAWS,
		checkJQ,
		checkGraphviz,
		checkClipboard,
		checkOfflineProxyEnv,
	}
}

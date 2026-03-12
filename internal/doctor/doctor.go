package doctor

// Run executes the standard suite of diagnostic checks.
// It returns a slice of Check results and true if all checks passed (no FAIL status).
func Run(ctx *Context) ([]Check, bool) {
	return NewRegistry(StandardChecks()...).Run(ctx)
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

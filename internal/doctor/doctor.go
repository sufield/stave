package doctor

// Run executes the standard suite of diagnostic checks.
// It returns a slice of Diagnostic results and true if all checks passed (no FAIL status).
func Run(ctx *SystemEnvironment) ([]Diagnostic, bool) {
	return NewCheckSuite(StandardChecks()...).Run(ctx)
}

// StandardChecks returns the default list of diagnostic functions.
func StandardChecks() []Probe {
	return []Probe{
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

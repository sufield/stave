package doctor

// Run executes the standard suite of diagnostic probes.
// It returns a slice of Diagnostic results and true if all probes passed (no FAIL status).
func Run(ctx *SystemEnvironment) ([]Diagnostic, bool) {
	return NewSuite(StandardChecks()...).Execute(ctx)
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

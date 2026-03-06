package doctor

var AllChecks = defaultChecks()

func Run(ctx Context) ([]Check, bool) {
	return RunWithRegistry(ctx, NewRegistry(AllChecks...))
}

func defaultChecks() []CheckFunc {
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

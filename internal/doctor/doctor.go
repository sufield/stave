package doctor

func Run(ctx Context) ([]Check, bool) {
	return RunWithRegistry(ctx, NewRegistry(defaultChecks()...))
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

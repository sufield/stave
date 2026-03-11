package securityaudit

type defaultDiagnosticsService struct {
	run func(cwd, binaryPath, staveVersion string)
}

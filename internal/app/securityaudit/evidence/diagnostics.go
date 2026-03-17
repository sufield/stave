package evidence

type DefaultDiagnosticsService struct {
	Run func(cwd, binaryPath, staveVersion string)
}

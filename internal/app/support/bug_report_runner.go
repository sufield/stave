package support

import (
	"archive/zip"
	"fmt"
	"io"
)

// BugReportResult captures key run outputs.
type BugReportResult struct {
	OutPath string
}

// PreparedOutput holds the result of preparing a bug report output file.
type PreparedOutput struct {
	Cwd     string
	OutPath string
	File    io.WriteCloser
}

// BugReportDeps supplies side-effect operations used by the CLI wrapper.
type BugReportDeps struct {
	PrepareOutput  func() (PreparedOutput, error)
	PopulateBundle func(zw *zip.Writer, cwd string) error
	WriteSummary   func(outPath string) error
}

// RunBugReport executes bug-report orchestration independent of Cobra plumbing.
func RunBugReport(deps BugReportDeps) (BugReportResult, error) {
	if deps.PrepareOutput == nil || deps.PopulateBundle == nil || deps.WriteSummary == nil {
		return BugReportResult{}, fmt.Errorf("bug report dependencies are required")
	}

	prepared, err := deps.PrepareOutput()
	if err != nil {
		return BugReportResult{}, err
	}
	defer prepared.File.Close()

	zw := zip.NewWriter(prepared.File)
	if err := deps.PopulateBundle(zw, prepared.Cwd); err != nil {
		return BugReportResult{}, err
	}
	if err := zw.Close(); err != nil {
		return BugReportResult{}, fmt.Errorf("finalize bundle: %w", err)
	}
	if err := deps.WriteSummary(prepared.OutPath); err != nil {
		return BugReportResult{}, err
	}
	return BugReportResult{OutPath: prepared.OutPath}, nil
}

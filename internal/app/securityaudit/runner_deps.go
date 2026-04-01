package securityaudit

import (
	"io/fs"
	"time"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// RunnerDeps holds injectable infrastructure dependencies for Runner.
// Each field replaces a direct import of a platform or adapter package.
type RunnerDeps struct {
	ReadFile             func(path string) ([]byte, error)
	HashFile             func(path string) (kernel.Digest, error)
	HashBytes            func(data []byte) kernel.Digest
	VulnerabilityScanner evidence.VulnerabilityScanner
	SignatureVerifier    ports.Verifier
	RunDiagnostics       func(cwd, binaryPath, staveVersion string)
	ResolveCrosswalk     func(raw []byte, frameworks, checkIDs []string, now time.Time) (evidence.CrosswalkResult, error)

	// OS-level functions injected to keep the app layer free of direct os.* calls.
	StatFile     func(string) (fs.FileInfo, error)
	Getenv       func(string) string
	IsPrivileged func() bool
	WalkDir      func(string, evidence.WalkFunc) error
	Getwd        func() (string, error)
}

// toParams extracts the evidence collection parameters from a full audit request.
func (req Request) toParams() evidence.Params {
	return evidence.Params{
		Now:                  req.Now,
		Cwd:                  req.Cwd,
		BinaryPath:           req.BinaryPath,
		OutDir:               req.OutDir,
		ComplianceFrameworks: req.ComplianceFrameworks,
		SBOMFormat:           req.SBOMFormat,
		VulnSource:           req.VulnSource,
		LiveVulnCheck:        req.LiveVulnCheck,
		ReleaseBundleDir:     req.ReleaseBundleDir,
		RequireOffline:       req.RequireOffline,
	}
}

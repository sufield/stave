package securityaudit

import (
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	domainsecaudit "github.com/sufield/stave/internal/domain/securityaudit"
)

// RunnerDeps holds injectable infrastructure dependencies for SecurityAuditRunner.
// Each field replaces a direct import of a platform or adapter package.
type RunnerDeps struct {
	ReadFile          func(path string) ([]byte, error)
	HashFile          func(path string) (kernel.Digest, error)
	HashBytes         func(data []byte) kernel.Digest
	GovulncheckRunner GovulncheckRunner
	SignatureVerifier ports.Verifier
	RunDiagnostics    func(cwd, binaryPath, staveVersion string)
	ResolveCrosswalk  func(raw []byte, frameworks, checkIDs []string, now time.Time) (CrosswalkResult, error)
}

// CrosswalkResult holds the resolved crosswalk mapping, matching the shape of
// compliance.CrosswalkResolution without importing that package.
type CrosswalkResult struct {
	ByCheck        map[string][]domainsecaudit.ControlRef
	MissingChecks  []string
	ResolutionJSON []byte
}

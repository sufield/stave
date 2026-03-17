package securityaudit

import (
	"io/fs"
	"time"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
)

// RunnerDeps holds injectable infrastructure dependencies for SecurityAuditRunner.
// Each field replaces a direct import of a platform or adapter package.
type RunnerDeps struct {
	ReadFile          func(path string) ([]byte, error)
	HashFile          func(path string) (kernel.Digest, error)
	HashBytes         func(data []byte) kernel.Digest
	GovulncheckRunner evidence.GovulncheckRunner
	SignatureVerifier ports.Verifier
	RunDiagnostics    func(cwd, binaryPath, staveVersion string)
	ResolveCrosswalk  func(raw []byte, frameworks, checkIDs []string, now time.Time) (evidence.CrosswalkResult, error)

	// OS-level functions injected to keep the app layer free of direct os.* calls.
	StatFile     func(string) (fs.FileInfo, error)
	Getenv       func(string) string
	IsPrivileged func() bool
	WalkDir      func(string, evidence.WalkFunc) error
	Getwd        func() (string, error)
}

// GovulncheckRunner is an alias for the evidence package type.
type GovulncheckRunner = evidence.GovulncheckRunner

// CrosswalkResult is an alias for the evidence package type.
type CrosswalkResult = evidence.CrosswalkResult

// WalkFunc is an alias for the evidence package type.
type WalkFunc = evidence.WalkFunc

// --- Re-exported enum types for backward compatibility ---

// SBOMFormat identifies the SBOM output standard.
type SBOMFormat = evidence.SBOMFormat

const (
	SBOMFormatSPDX      = evidence.SBOMFormatSPDX
	SBOMFormatCycloneDX = evidence.SBOMFormatCycloneDX
)

// VulnSource identifies the vulnerability evidence strategy.
type VulnSource = evidence.VulnSource

const (
	VulnSourceHybrid = evidence.VulnSourceHybrid
	VulnSourceLocal  = evidence.VulnSourceLocal
	VulnSourceCI     = evidence.VulnSourceCI
)

// Re-export provider interfaces so callers importing only the root package
// can still reference them by name if needed.

// BuildInfoProvider collects Go build metadata.
type BuildInfoProvider = evidence.BuildInfoProvider

// SBOMGenerator produces a Software Bill of Materials.
type SBOMGenerator = evidence.SBOMGenerator

// VulnEvidenceProvider resolves vulnerability evidence.
type VulnEvidenceProvider = evidence.VulnEvidenceProvider

// BinaryInspector inspects binary artifacts for integrity and hardening.
type BinaryInspector = evidence.BinaryInspector

// PolicyInspector inspects runtime policy compliance.
type PolicyInspector = evidence.PolicyInspector

// CrosswalkResolver maps security checks to compliance frameworks.
type CrosswalkResolver = evidence.CrosswalkResolver

// Compile-time interface satisfaction checks.
var (
	_ BuildInfoProvider    = evidence.DefaultBuildInfoProvider{}
	_ SBOMGenerator        = evidence.DefaultSBOMGenerator{}
	_ VulnEvidenceProvider = evidence.DefaultVulnProvider{}
	_ BinaryInspector      = evidence.DefaultBinaryInspector{}
	_ PolicyInspector      = evidence.DefaultPolicyInspector{}
	_ CrosswalkResolver    = evidence.DefaultCrosswalkResolver{}
)

// toParams extracts the evidence collection parameters from a full audit request.
func (req SecurityAuditRequest) toParams() evidence.Params {
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

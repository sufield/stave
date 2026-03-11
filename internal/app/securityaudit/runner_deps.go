package securityaudit

import (
	"context"
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

// Evidence provider interfaces. Each defines the contract for a single
// evidence-collection step in the security audit pipeline.

// BuildInfoProvider collects Go build metadata.
type BuildInfoProvider interface {
	Collect(now time.Time) (buildInfoSnapshot, error)
}

// SBOMGenerator produces a Software Bill of Materials.
type SBOMGenerator interface {
	Generate(input buildInfoSnapshot, format SBOMFormat, now time.Time) (sbomSnapshot, error)
}

// VulnEvidenceProvider resolves vulnerability evidence.
type VulnEvidenceProvider interface {
	Resolve(ctx context.Context, req SecurityAuditRequest) (vulnerabilitySnapshot, error)
}

// BinaryInspector inspects binary artifacts for integrity and hardening.
type BinaryInspector interface {
	Inspect(req SecurityAuditRequest, buildInfo buildInfoSnapshot) (binaryInspectionSnapshot, error)
}

// PolicyInspector inspects runtime policy compliance.
type PolicyInspector interface {
	Inspect(ctx context.Context, req SecurityAuditRequest) (policyInspectionSnapshot, error)
}

// CrosswalkResolver maps security checks to compliance frameworks.
type CrosswalkResolver interface {
	Resolve(ctx context.Context, req SecurityAuditRequest, checkIDs []string) (crosswalkSnapshot, error)
}

// Compile-time interface satisfaction checks.
var (
	_ BuildInfoProvider    = defaultBuildInfoProvider{}
	_ SBOMGenerator        = defaultSBOMGenerator{}
	_ VulnEvidenceProvider = defaultVulnEvidenceProvider{}
	_ BinaryInspector      = defaultBinaryInspector{}
	_ PolicyInspector      = defaultPolicyInspector{}
	_ CrosswalkResolver    = defaultCrosswalkResolver{}
)

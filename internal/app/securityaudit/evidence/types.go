// Package evidence provides evidence collection for security audits.
// It gathers build metadata, SBOMs, vulnerability reports, binary
// integrity data, and runtime policy inspections.
package evidence

import (
	"context"
	"fmt"
	"io/fs"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/domain/securityaudit"
)

// --- Enums ---

// SBOMFormat identifies the SBOM output standard.
type SBOMFormat string

const (
	SBOMFormatSPDX      SBOMFormat = "spdx"
	SBOMFormatCycloneDX SBOMFormat = "cyclonedx"
)

// VulnSource identifies the vulnerability evidence strategy.
type VulnSource string

const (
	VulnSourceHybrid VulnSource = "hybrid"
	VulnSourceLocal  VulnSource = "local"
	VulnSourceCI     VulnSource = "ci"
)

// VulnSourceUsed identifies the actual evidence source outcome (vs VulnSource which is the strategy).
type VulnSourceUsed string

const (
	VulnSourceUsedLive       VulnSourceUsed = "local_live_check"
	VulnSourceUsedFailed     VulnSourceUsed = "live_check_failed"
	VulnSourceUsedNone       VulnSourceUsed = "none"
	VulnSourceUsedLocalCache VulnSourceUsed = "local_cache"
	VulnSourceUsedCIArtifact VulnSourceUsed = "ci_artifact"
)

// VulnFreshness describes the age/provenance of vulnerability evidence.
// Values are either named tokens or RFC3339 timestamps from file stat.
type VulnFreshness string

const (
	FreshnessUnknown VulnFreshness = "unknown"
	FreshnessLive    VulnFreshness = "live"
	FreshnessCached  VulnFreshness = "cached"
)

// FreshnessFromTime creates a VulnFreshness from a file modification time.
func FreshnessFromTime(t time.Time) VulnFreshness {
	return VulnFreshness(t.UTC().Format(time.RFC3339))
}

// ParseSBOMFormat validates and returns an SBOMFormat.
func ParseSBOMFormat(s string) (SBOMFormat, error) {
	switch SBOMFormat(s) {
	case SBOMFormatSPDX, SBOMFormatCycloneDX:
		return SBOMFormat(s), nil
	default:
		return "", fmt.Errorf("unsupported --sbom-format %q (supported: spdx, cyclonedx)", s)
	}
}

// ParseVulnSource validates and returns a VulnSource.
func ParseVulnSource(s string) (VulnSource, error) {
	switch VulnSource(s) {
	case VulnSourceHybrid, VulnSourceLocal, VulnSourceCI:
		return VulnSource(s), nil
	default:
		return "", fmt.Errorf("unsupported --vuln-source %q (supported: hybrid, local, ci)", s)
	}
}

// --- Collection Parameters ---

// Params holds the subset of audit request fields that evidence collectors need.
type Params struct {
	Now                  time.Time
	Cwd                  string
	BinaryPath           string
	OutDir               string
	ComplianceFrameworks []string
	SBOMFormat           SBOMFormat
	VulnSource           VulnSource
	LiveVulnCheck        bool
	ReleaseBundleDir     string
	RequireOffline       bool
}

// --- Snapshot Types ---

type BuildInfoSnapshot struct {
	Available bool
	GoVersion string
	Settings  map[string]string
	Main      BuildModuleSnapshot
	Deps      []BuildModuleSnapshot
	RawJSON   []byte
}

type BuildModuleSnapshot struct {
	Path    string
	Version string
	Sum     string
}

type SBOMSnapshot struct {
	FileName        string
	DependencyCount int
	RawJSON         []byte
}

type VulnerabilitySnapshot struct {
	Available    bool
	SourceUsed   VulnSourceUsed
	Freshness    VulnFreshness
	FindingCount int
	RawJSON      []byte
	Details      string
}

type BinaryInspectionSnapshot struct {
	BinaryPath        string
	SHA256            string
	ChecksumJSON      []byte
	SignatureJSON     []byte
	SignatureAttempt  bool
	SignatureVerified bool
	SignatureDetail   string
	HardeningLevel    securityaudit.Status
	HardeningDetail   string
}

type NetworkInspection struct {
	RuntimeNetworkOK  bool
	RuntimeViolations []string
	NetworkDeclJSON   []byte
}

type CredentialInspection struct {
	CredentialPolicyOK   bool
	CredentialViolations []string
}

type FilesystemInspection struct {
	FilesystemReads    []string
	FilesystemWrites   []string
	FilesystemDeclJSON []byte
}

type OperationalInspection struct {
	RedactionPolicyOK      bool
	TelemetryDeclaredNone  bool
	AuditLoggingConfigured bool
	RunningAsPrivileged    bool
}

type PolicyInspectionSnapshot struct {
	Network      NetworkInspection
	Credential   CredentialInspection
	Filesystem   FilesystemInspection
	Operational  OperationalInspection
	ProxyVarsSet []string
	IAMActions   []string
}

type CrosswalkSnapshot struct {
	ByCheck        map[string][]securityaudit.ControlRef
	MissingChecks  []string
	ResolutionJSON []byte
}

// --- Bundle ---

// Bundle holds all collected evidence snapshots with their error states.
type Bundle struct {
	BuildInfo    BuildInfoSnapshot
	SBOM         SBOMSnapshot
	SBOMErr      error
	Vuln         VulnerabilitySnapshot
	VulnErr      error
	Binary       BinaryInspectionSnapshot
	BinaryErr    error
	Policy       PolicyInspectionSnapshot
	PolicyErr    error
	Crosswalk    CrosswalkSnapshot
	CrosswalkErr error
}

// --- Provider Interfaces ---

// BuildInfoProvider collects Go build metadata.
type BuildInfoProvider interface {
	Collect(now time.Time) (BuildInfoSnapshot, error)
}

// SBOMGenerator produces a Software Bill of Materials.
type SBOMGenerator interface {
	Generate(input BuildInfoSnapshot, format SBOMFormat, now time.Time) (SBOMSnapshot, error)
}

// VulnEvidenceProvider resolves vulnerability evidence.
type VulnEvidenceProvider interface {
	Resolve(ctx context.Context, params Params) (VulnerabilitySnapshot, error)
}

// BinaryInspector inspects binary artifacts for integrity and hardening.
type BinaryInspector interface {
	Inspect(params Params, buildInfo BuildInfoSnapshot) (BinaryInspectionSnapshot, error)
}

// PolicyInspector inspects runtime policy compliance.
type PolicyInspector interface {
	Inspect(ctx context.Context, params Params) (PolicyInspectionSnapshot, error)
}

// CrosswalkResolver maps security checks to compliance frameworks.
type CrosswalkResolver interface {
	Resolve(ctx context.Context, params Params, checkIDs []string) (CrosswalkSnapshot, error)
}

// --- Dependency Injection ---

// WalkFunc is the callback signature for directory walking.
type WalkFunc func(path string, info fs.FileInfo, err error) error

// GovulncheckRunner executes govulncheck and returns its combined output.
type GovulncheckRunner func(ctx context.Context, cwd string) ([]byte, error)

// CrosswalkResult holds the resolved crosswalk mapping.
type CrosswalkResult struct {
	ByCheck        map[string][]securityaudit.ControlRef
	MissingChecks  []string
	ResolutionJSON []byte
}

// Deps holds injectable infrastructure dependencies for evidence collectors.
type Deps struct {
	ReadFile          func(path string) ([]byte, error)
	HashFile          func(path string) (kernel.Digest, error)
	GovulncheckRunner GovulncheckRunner
	SignatureVerifier ports.Verifier
	StatFile          func(string) (fs.FileInfo, error)
	Getenv            func(string) string
	IsPrivileged      func() bool
	WalkDir           func(string, WalkFunc) error
	ResolveCrosswalk  func(raw []byte, frameworks, checkIDs []string, now time.Time) (CrosswalkResult, error)
}

// Collectors holds the configured evidence provider implementations.
type Collectors struct {
	BuildInfo BuildInfoProvider
	SBOM      SBOMGenerator
	Vuln      VulnEvidenceProvider
	Binary    BinaryInspector
	Policy    PolicyInspector
	Crosswalk CrosswalkResolver
}

// NewCollectors creates evidence collectors from the given infrastructure dependencies.
func NewCollectors(deps Deps) Collectors {
	return Collectors{
		BuildInfo: DefaultBuildInfoProvider{},
		SBOM:      DefaultSBOMGenerator{},
		Vuln:      DefaultVulnProvider{RunGovulncheck: deps.GovulncheckRunner, ReadFile: deps.ReadFile, StatFile: deps.StatFile},
		Binary:    DefaultBinaryInspector{SignatureVerifier: deps.SignatureVerifier, HashFile: deps.HashFile, ReadFile: deps.ReadFile, StatFile: deps.StatFile},
		Policy:    DefaultPolicyInspector{ReadFile: deps.ReadFile, StatFile: deps.StatFile, Getenv: deps.Getenv, IsPrivileged: deps.IsPrivileged, WalkDir: deps.WalkDir},
		Crosswalk: DefaultCrosswalkResolver{ReadFile: deps.ReadFile, ResolveFn: deps.ResolveCrosswalk, StatFile: deps.StatFile},
	}
}

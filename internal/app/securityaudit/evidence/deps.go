package evidence

import (
	"context"
	"io/fs"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/securityaudit"
)

// WalkFunc is the callback signature for directory walking.
type WalkFunc func(path string, info fs.FileInfo, err error) error

// VulnerabilityScanner executes govulncheck and returns its combined output.
type VulnerabilityScanner func(ctx context.Context, cwd string) ([]byte, error)

// CrosswalkResult holds the resolved crosswalk mapping.
type CrosswalkResult struct {
	ByCheck        map[string][]securityaudit.ControlRef
	MissingChecks  []string
	ResolutionJSON []byte
}

// Deps holds injectable infrastructure dependencies for evidence collectors.
type Deps struct {
	ReadFile             func(path string) ([]byte, error)
	HashFile             func(path string) (kernel.Digest, error)
	VulnerabilityScanner VulnerabilityScanner
	SignatureVerifier    ports.Verifier
	StatFile             func(string) (fs.FileInfo, error)
	Getenv               func(string) string
	IsPrivileged         func() bool
	WalkDir              func(string, WalkFunc) error
	ResolveCrosswalk     func(raw []byte, frameworks, checkIDs []string, now time.Time) (CrosswalkResult, error)
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
		Vuln:      DefaultVulnProvider{RunGovulncheck: deps.VulnerabilityScanner, ReadFile: deps.ReadFile, StatFile: deps.StatFile},
		Binary:    DefaultBinaryInspector{SignatureVerifier: deps.SignatureVerifier, HashFile: deps.HashFile, ReadFile: deps.ReadFile, StatFile: deps.StatFile},
		Policy:    DefaultPolicyInspector{ReadFile: deps.ReadFile, StatFile: deps.StatFile, Getenv: deps.Getenv, IsPrivileged: deps.IsPrivileged, WalkDir: deps.WalkDir},
		Crosswalk: DefaultCrosswalkResolver{ReadFile: deps.ReadFile, ResolveFn: deps.ResolveCrosswalk, StatFile: deps.StatFile},
	}
}

package evidence

import (
	"github.com/sufield/stave/internal/core/outcome"
	"github.com/sufield/stave/internal/core/securityaudit"
)

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
	HardeningLevel    outcome.Status
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

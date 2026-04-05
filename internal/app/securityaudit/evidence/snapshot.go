package evidence

import (
	"github.com/sufield/stave/internal/core/outcome"
	"github.com/sufield/stave/internal/core/securityaudit"
)

// BuildInfoSnapshot represents a buildinfosnapshot value.
type BuildInfoSnapshot struct {
	Available bool
	GoVersion string
	Settings  map[string]string
	Main      BuildModuleSnapshot
	Deps      []BuildModuleSnapshot
	RawJSON   []byte
}

// BuildModuleSnapshot represents a buildmodulesnapshot value.
type BuildModuleSnapshot struct {
	Path    string
	Version string
	Sum     string
}

// SBOMSnapshot represents a sbomsnapshot value.
type SBOMSnapshot struct {
	FileName        string
	DependencyCount int
	RawJSON         []byte
}

// VulnerabilitySnapshot represents a vulnerabilitysnapshot value.
type VulnerabilitySnapshot struct {
	Available    bool
	SourceUsed   VulnSourceUsed
	Freshness    VulnFreshness
	FindingCount int
	RawJSON      []byte
	Details      string
}

// BinaryInspectionSnapshot represents a binaryinspectionsnapshot value.
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

// NetworkInspection represents a networkinspection value.
type NetworkInspection struct {
	RuntimeNetworkOK  bool
	RuntimeViolations []string
	NetworkDeclJSON   []byte
}

// CredentialInspection represents a credentialinspection value.
type CredentialInspection struct {
	CredentialPolicyOK   bool
	CredentialViolations []string
}

// FilesystemInspection represents a filesysteminspection value.
type FilesystemInspection struct {
	FilesystemReads    []string
	FilesystemWrites   []string
	FilesystemDeclJSON []byte
}

// OperationalInspection represents a operationalinspection value.
type OperationalInspection struct {
	RedactionPolicyOK      bool
	TelemetryDeclaredNone  bool
	AuditLoggingConfigured bool
	RunningAsPrivileged    bool
}

// PolicyInspectionSnapshot represents a policyinspectionsnapshot value.
type PolicyInspectionSnapshot struct {
	Network      NetworkInspection
	Credential   CredentialInspection
	Filesystem   FilesystemInspection
	Operational  OperationalInspection
	ProxyVarsSet []string
	IAMActions   []string
}

// CrosswalkSnapshot represents a crosswalksnapshot value.
type CrosswalkSnapshot struct {
	ByCheck        map[string][]securityaudit.ControlRef
	MissingChecks  []string
	ResolutionJSON []byte
}

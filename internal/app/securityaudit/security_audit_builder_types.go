package securityaudit

import "github.com/sufield/stave/internal/domain/securityaudit"

type buildInfoSnapshot struct {
	Available bool
	GoVersion string
	Settings  map[string]string
	Main      buildModuleSnapshot
	Deps      []buildModuleSnapshot
	RawJSON   []byte
}

type buildModuleSnapshot struct {
	Path    string
	Version string
	Sum     string
}

type sbomSnapshot struct {
	FileName        string
	DependencyCount int
	RawJSON         []byte
}

type vulnerabilitySnapshot struct {
	Available    bool
	SourceUsed   string
	Freshness    string
	FindingCount int
	RawJSON      []byte
	Details      string
}

type binaryInspectionSnapshot struct {
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

type networkInspection struct {
	RuntimeNetworkOK  bool
	RuntimeViolations []string
	NetworkDeclJSON   []byte
}

type credentialInspection struct {
	CredentialPolicyOK   bool
	CredentialViolations []string
}

type filesystemInspection struct {
	FilesystemReads    []string
	FilesystemWrites   []string
	FilesystemDeclJSON []byte
}

type operationalInspection struct {
	RedactionPolicyOK      bool
	TelemetryDeclaredNone  bool
	AuditLoggingConfigured bool
	RunningAsPrivileged    bool
}

type policyInspectionSnapshot struct {
	Network      networkInspection
	Credential   credentialInspection
	Filesystem   filesystemInspection
	Operational  operationalInspection
	ProxyVarsSet []string
	IAMActions   []string
}

type crosswalkSnapshot struct {
	ByCheck        map[string][]securityaudit.ControlRef
	MissingChecks  []string
	ResolutionJSON []byte
}

type evidenceBundle struct {
	buildInfo    buildInfoSnapshot
	sbom         sbomSnapshot
	sbomErr      error
	vuln         vulnerabilitySnapshot
	vulnErr      error
	binary       binaryInspectionSnapshot
	binaryErr    error
	policy       policyInspectionSnapshot
	policyErr    error
	crosswalk    crosswalkSnapshot
	crosswalkErr error
}

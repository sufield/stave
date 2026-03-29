package securityaudit

import (
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// ReportFormat identifies a supported security-audit output format.
type ReportFormat string

const (
	ReportFormatJSON     ReportFormat = "json"
	ReportFormatMarkdown ReportFormat = "markdown"
	ReportFormatSARIF    ReportFormat = "sarif"
)

// AllReportFormats returns all supported report format strings in stable order.
func AllReportFormats() []string {
	return []string{
		string(ReportFormatJSON),
		string(ReportFormatMarkdown),
		string(ReportFormatSARIF),
	}
}

// Status represents the outcome of an audit check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// String implements fmt.Stringer.
func (s Status) String() string { return string(s) }

// Pillar identifies the enterprise category for an audit check.
type Pillar string

const (
	PillarSupplyChain Pillar = "supply_chain"
	PillarRuntime     Pillar = "runtime_behavior_permissions"
	PillarPrivacy     Pillar = "data_privacy"
	PillarControls    Pillar = "internal_security_controls"
)

// Severity represents a normalized level of security risk.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// AllSeverityStrings returns all severity level strings in descending order of risk.
func AllSeverityStrings() []string {
	return []string{
		string(SeverityCritical),
		string(SeverityHigh),
		string(SeverityMedium),
		string(SeverityLow),
		string(SeverityNone),
	}
}

// Rank returns a numeric value (0–4) for the severity.
// Higher values indicate more severe risk.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Gte reports whether s is at least as severe as the threshold.
// Every severity (including None) is >= None, so a threshold of None
// never gates any finding.
func (s Severity) Gte(threshold Severity) bool {
	return s.Rank() >= threshold.Rank()
}

// String implements fmt.Stringer.
func (s Severity) String() string { return string(s) }

// ParseSeverity converts a string to a validated Severity.
func ParseSeverity(raw string) (Severity, error) {
	norm := Severity(strings.ToUpper(strings.TrimSpace(raw)))
	switch norm {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return norm, nil
	case SeverityNone, "":
		return SeverityNone, nil
	default:
		return "", fmt.Errorf("invalid severity %q: use CRITICAL, HIGH, MEDIUM, LOW, or NONE", raw)
	}
}

// ParseSeverityList parses a comma-separated string of severity levels.
// Deduplicates input and returns values in encountered order.
// Returns [CRITICAL, HIGH] when raw is empty (secure default).
func ParseSeverityList(raw string) ([]Severity, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []Severity{SeverityCritical, SeverityHigh}, nil
	}

	parts := strings.Split(raw, ",")
	out := make([]Severity, 0, len(parts))
	seen := make(map[Severity]struct{}, len(parts))

	for _, p := range parts {
		sev, err := ParseSeverity(p)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[sev]; !exists {
			seen[sev] = struct{}{}
			out = append(out, sev)
		}
	}
	return out, nil
}

// --- Report Components ---

// ControlRef maps an audit finding to a regulatory or internal framework requirement.
type ControlRef struct {
	Framework string `json:"framework" yaml:"framework"`
	ControlID string `json:"control_id" yaml:"control_id"`
	Rationale string `json:"rationale" yaml:"rationale"`
}

// EvidenceRef identifies a supporting artifact generated during the audit.
type EvidenceRef struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Description string `json:"description,omitempty"`
}

// ArtifactEntry represents a single file in the security audit bundle.
type ArtifactEntry struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Content   []byte `json:"-"` // Never serialized
}

// ArtifactManifest tracks all files in a security audit bundle.
type ArtifactManifest struct {
	SchemaVersion  kernel.Schema   `json:"schema_version"`
	GeneratedAt    time.Time       `json:"generated_at"`
	BundleDir      string          `json:"bundle_dir"`
	MainReportPath string          `json:"main_report_path"`
	Files          []ArtifactEntry `json:"files"`
}

// --- Artifact Filenames ---

const (
	ArtifactBuildInfo        = "build_info.json"
	ArtifactSBOMSPDX         = "sbom.spdx.json"
	ArtifactSBOMCycloneDX    = "sbom.cdx.json"
	ArtifactVulnReport       = "vuln_report.json"
	ArtifactBinaryChecksums  = "binary_checksums.json"
	ArtifactSignatureVerify  = "signature_verification.json"
	ArtifactNetworkEgress    = "network_egress_declaration.json"
	ArtifactFilesystemAccess = "filesystem_access_declaration.json"
	ArtifactControlCrosswalk = "control_crosswalk_resolution.json"
)

// --- Check IDs ---

// CheckID is a typed identifier for a security audit check.
type CheckID string

// String implements fmt.Stringer.
func (c CheckID) String() string { return string(c) }

const (
	CheckBuildInfoPresent   CheckID = "SC.BUILDINFO.PRESENT"
	CheckSBOMGenerated      CheckID = "SC.SBOM.GENERATED"
	CheckVulnResults        CheckID = "SC.VULN.RESULTS"
	CheckBinarySHA256       CheckID = "SC.BINARY.SHA256"
	CheckSignatureVerified  CheckID = "SC.SIGNATURE.VERIFIED"
	CheckRuntimeNetworkNone CheckID = "RB.NETWORK.RUNTIME_NONE"
	CheckOfflineEnforcement CheckID = "RB.OFFLINE.ENFORCEMENT"
	CheckFSAccessDisclosure CheckID = "RB.FS.ACCESS.DISCLOSURE"
	CheckPrivilegeNoSudo    CheckID = "RB.PRIVILEGE.NO_SUDO"
	CheckIAMS3MinPerms      CheckID = "RB.IAM.S3.MINPERMS"
	CheckCredentialStorage  CheckID = "DP.CREDENTIAL.STORAGE" //nolint:gosec // audit check ID, not a credential
	CheckSanitizationPolicy CheckID = "DP.SANITIZATION.POLICY"
	CheckTelemetryDecl      CheckID = "DP.TELEMETRY.DISCLOSURE"
	CheckPrivacyMode        CheckID = "DP.PRIVACY.MODE"
	CheckBuildHardening     CheckID = "IC.BUILD.HARDENING"
	CheckAuditLogging       CheckID = "IC.AUDIT.LOGGING"
	CheckControlMapping     CheckID = "IC.CONTROL.MAPPING"
	CheckControlMapMissing  CheckID = "IC.CONTROL.MAPPING_MISSING"
)

// allChecks is the canonical registry; unexported to prevent mutation.
var allChecks = []CheckID{
	CheckBuildInfoPresent, CheckSBOMGenerated, CheckVulnResults, CheckBinarySHA256, CheckSignatureVerified,
	CheckRuntimeNetworkNone, CheckOfflineEnforcement, CheckFSAccessDisclosure, CheckPrivilegeNoSudo, CheckIAMS3MinPerms,
	CheckCredentialStorage, CheckSanitizationPolicy, CheckTelemetryDecl, CheckPrivacyMode,
	CheckBuildHardening, CheckAuditLogging, CheckControlMapping, CheckControlMapMissing,
}

// AllCheckIDs returns the complete registry of V1 audit checks.
// Returns a defensive copy to prevent mutation of the global registry.
func AllCheckIDs() []CheckID {
	cp := make([]CheckID, len(allChecks))
	copy(cp, allChecks)
	return cp
}

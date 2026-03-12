package securityaudit

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Status represents the binary or ternary outcome of a specific audit check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// Pillar identifies the functional enterprise category for an audit check.
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

// Rank returns a numeric value representing the severity level (higher is more severe).
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

// Gte reports whether the severity is greater than or equal to the provided threshold.
func (s Severity) Gte(threshold Severity) bool {
	if threshold == SeverityNone {
		return false
	}
	return s.Rank() >= threshold.Rank()
}

// ParseSeverity converts a string token into a validated Severity.
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
// It deduplicates the input and returns a slice in the original encountered order.
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

// ControlRef maps an audit finding to a specific regulatory or internal framework requirement.
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

// ArtifactEntry represents a single file entry in the security audit bundle.
type ArtifactEntry struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Content   []byte `json:"-"`
}

// ArtifactManifest tracks all files contained within a security audit bundle.
type ArtifactManifest struct {
	SchemaVersion  kernel.Schema   `json:"schema_version"`
	GeneratedAt    string          `json:"generated_at"`
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

const (
	CheckBuildInfoPresent   = "SC.BUILDINFO.PRESENT"
	CheckSBOMGenerated      = "SC.SBOM.GENERATED"
	CheckVulnResults        = "SC.VULN.RESULTS"
	CheckBinarySHA256       = "SC.BINARY.SHA256"
	CheckSignatureVerified  = "SC.SIGNATURE.VERIFIED"
	CheckRuntimeNetworkNone = "RB.NETWORK.RUNTIME_NONE"
	CheckOfflineEnforcement = "RB.OFFLINE.ENFORCEMENT"
	CheckFSAccessDisclosure = "RB.FS.ACCESS.DISCLOSURE"
	CheckPrivilegeNoSudo    = "RB.PRIVILEGE.NO_SUDO"
	CheckIAMS3MinPerms      = "RB.IAM.S3.MINPERMS"
	CheckCredentialStorage  = "DP.CREDENTIAL.STORAGE" // #nosec G101
	CheckSanitizationPolicy = "DP.SANITIZATION.POLICY"
	CheckTelemetryDecl      = "DP.TELEMETRY.DISCLOSURE"
	CheckPrivacyMode        = "DP.PRIVACY.MODE"
	CheckBuildHardening     = "IC.BUILD.HARDENING"
	CheckAuditLogging       = "IC.AUDIT.LOGGING"
	CheckControlMapping     = "IC.CONTROL.MAPPING"
	CheckControlMapMissing  = "IC.CONTROL.MAPPING_MISSING"
)

// AllCheckIDs returns the complete registry of V1 audit checks.
func AllCheckIDs() []string {
	return []string{
		CheckBuildInfoPresent, CheckSBOMGenerated, CheckVulnResults, CheckBinarySHA256, CheckSignatureVerified,
		CheckRuntimeNetworkNone, CheckOfflineEnforcement, CheckFSAccessDisclosure, CheckPrivilegeNoSudo, CheckIAMS3MinPerms,
		CheckCredentialStorage, CheckSanitizationPolicy, CheckTelemetryDecl, CheckPrivacyMode,
		CheckBuildHardening, CheckAuditLogging, CheckControlMapping, CheckControlMapMissing,
	}
}

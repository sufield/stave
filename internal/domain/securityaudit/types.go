package securityaudit

import (
	"fmt"
	"strings"
)

// Status represents the outcome of one audit check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// Pillar groups checks by enterprise audit category.
type Pillar string

const (
	PillarSupplyChain Pillar = "supply_chain"
	PillarRuntime     Pillar = "runtime_behavior_permissions"
	PillarPrivacy     Pillar = "data_privacy"
	PillarControls    Pillar = "internal_security_controls"
)

// Severity represents a normalized risk level.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// ControlRef maps a finding to an external compliance control.
type ControlRef struct {
	Framework string `json:"framework" yaml:"framework"`
	ControlID string `json:"control_id" yaml:"control_id"`
	Rationale string `json:"rationale" yaml:"rationale"`
}

// EvidenceRef points to an artifact file generated during the audit run.
type EvidenceRef struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Description string `json:"description,omitempty"`
}

// ArtifactEntry is one file in the generated bundle.
type ArtifactEntry struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Content   []byte `json:"-"`
}

// ArtifactManifest tracks bundle files and metadata.
type ArtifactManifest struct {
	SchemaVersion  string          `json:"schema_version"`
	GeneratedAt    string          `json:"generated_at"`
	BundleDir      string          `json:"bundle_dir"`
	MainReportPath string          `json:"main_report_path"`
	Files          []ArtifactEntry `json:"files"`
}

// ParseSeverity parses a severity token.
func ParseSeverity(raw string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(SeverityCritical):
		return SeverityCritical, nil
	case string(SeverityHigh):
		return SeverityHigh, nil
	case string(SeverityMedium):
		return SeverityMedium, nil
	case string(SeverityLow):
		return SeverityLow, nil
	default:
		return "", fmt.Errorf("invalid severity %q (use CRITICAL,HIGH,MEDIUM,LOW)", raw)
	}
}

// ParseFailOnSeverity parses --fail-on values.
func ParseFailOnSeverity(raw string) (Severity, error) {
	normalized := strings.ToUpper(strings.TrimSpace(raw))
	if normalized == string(SeverityNone) {
		return SeverityNone, nil
	}
	return ParseSeverity(normalized)
}

// ParseSeverityList parses comma-separated severities.
func ParseSeverityList(raw string) ([]Severity, error) {
	if strings.TrimSpace(raw) == "" {
		return []Severity{SeverityCritical, SeverityHigh}, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]Severity, 0, len(parts))
	seen := map[Severity]bool{}
	for _, part := range parts {
		sev, err := ParseSeverity(part)
		if err != nil {
			return nil, err
		}
		if seen[sev] {
			continue
		}
		seen[sev] = true
		out = append(out, sev)
	}
	return out, nil
}

// SeverityRank maps severity to descending numeric rank.
func SeverityRank(sev Severity) int {
	switch sev {
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

// AtOrAbove reports whether sev is >= threshold.
func AtOrAbove(sev, threshold Severity) bool {
	if threshold == SeverityNone {
		return false
	}
	return SeverityRank(sev) >= SeverityRank(threshold)
}

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
	CheckCredentialStorage  = "DP.CREDENTIAL.STORAGE" // #nosec G101 -- check ID, not a credential
	CheckSanitizationPolicy    = "DP.SANITIZATION.POLICY"
	CheckTelemetryDecl      = "DP.TELEMETRY.DISCLOSURE"
	CheckPrivacyMode        = "DP.PRIVACY.MODE"
	CheckBuildHardening     = "IC.BUILD.HARDENING"
	CheckAuditLogging       = "IC.AUDIT.LOGGING"
	CheckControlMapping     = "IC.CONTROL.MAPPING"
	CheckControlMapMissing  = "IC.CONTROL.MAPPING_MISSING"
)

// AllCheckIDs returns the complete V1 check catalog.
func AllCheckIDs() []string {
	return []string{
		CheckBuildInfoPresent,
		CheckSBOMGenerated,
		CheckVulnResults,
		CheckBinarySHA256,
		CheckSignatureVerified,
		CheckRuntimeNetworkNone,
		CheckOfflineEnforcement,
		CheckFSAccessDisclosure,
		CheckPrivilegeNoSudo,
		CheckIAMS3MinPerms,
		CheckCredentialStorage,
		CheckSanitizationPolicy,
		CheckTelemetryDecl,
		CheckPrivacyMode,
		CheckBuildHardening,
		CheckAuditLogging,
		CheckControlMapping,
		CheckControlMapMissing,
	}
}

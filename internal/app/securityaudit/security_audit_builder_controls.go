package securityaudit

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

func findingFromHardening(in evidence.BinaryInspectionSnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckBuildHardening,
			Pillar:         securityaudit.PillarControls,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Build hardening metadata unavailable",
			Details:        err.Error(),
			AuditorHint:    "Could not inspect build hardening metadata.",
			Recommendation: "Build with standard metadata and rerun security-audit.",
		}
	}
	status := in.HardeningLevel
	title := "Build hardening checks passed"
	reco := "Retain reproducible build flags in release pipeline."
	if status == securityaudit.StatusWarn {
		title = "Build hardening requires review"
		reco = "Enable hardened build flags (e.g., PIE where supported)."
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckBuildHardening,
		Pillar:         securityaudit.PillarControls,
		Status:         status,
		Severity:       securityaudit.SeverityMedium,
		Title:          title,
		Details:        in.HardeningDetail,
		AuditorHint:    "Hardening metadata is best-effort and OS/build-mode dependent.",
		Recommendation: reco,
	}
}

var auditLoggingSpec = findingSpec{ //nolint:gosec // audit template, not a credential
	ID:       securityaudit.CheckAuditLogging,
	Pillar:   securityaudit.PillarControls,
	Severity: securityaudit.SeverityMedium,

	ErrStatus: securityaudit.StatusWarn,
	ErrTitle:  "Audit logging check incomplete",
	ErrHint:   "Could not verify local audit logging support.",
	ErrReco:   "Verify logging configuration and rerun security-audit.",

	PassTitle:   "Audit logging available",
	PassDetails: "CLI logging subsystem is present and configurable via --log-file/--log-format.",
	PassHint:    "Operational events can be captured locally for review.",
	PassReco:    "Route logs to protected storage for audit retention.",

	FailStatus:  securityaudit.StatusWarn,
	FailTitle:   "Audit logging not configured",
	FailDetails: "Logging subsystem exists but no explicit audit-log policy was detected.",
	FailHint:    "Tamper-evident log posture depends on deployment configuration.",
	FailReco:    "Configure log file destination and retention controls for audited workflows.",
}

func findingFromAuditLogging(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	return buildFinding(auditLoggingSpec, err, in.Operational.AuditLoggingConfigured, "", "")
}

func findingFromCrosswalk(in evidence.CrosswalkSnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckControlMapping,
			Pillar:         securityaudit.PillarControls,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Control mapping resolution failed",
			Details:        err.Error(),
			AuditorHint:    "Compliance mappings are required for evidence traceability.",
			Recommendation: "Fix control_crosswalk.v1.yaml syntax/coverage and rerun.",
		}
	}
	if len(in.MissingChecks) > 0 {
		return securityaudit.Finding{
			ID:             securityaudit.CheckControlMapping,
			Pillar:         securityaudit.PillarControls,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Control mapping has gaps",
			Details:        fmt.Sprintf("%d checks have no control mapping after filtering.", len(in.MissingChecks)),
			AuditorHint:    "Incomplete crosswalk weakens auditability across frameworks.",
			Recommendation: "Add missing check mappings in control_crosswalk.v1.yaml.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckControlMapping,
		Pillar:         securityaudit.PillarControls,
		Status:         securityaudit.StatusPass,
		Severity:       securityaudit.SeverityMedium,
		Title:          "Control mapping resolved",
		Details:        "All security-audit checks are mapped to selected compliance frameworks.",
		AuditorHint:    "Crosswalk evidence is complete for selected frameworks.",
		Recommendation: "Keep crosswalk versioned and reviewed with policy updates.",
	}
}

func findingFromCrosswalkMissing(in evidence.CrosswalkSnapshot) securityaudit.Finding {
	return securityaudit.Finding{
		ID:             securityaudit.CheckControlMapMissing,
		Pillar:         securityaudit.PillarControls,
		Status:         securityaudit.StatusWarn,
		Severity:       securityaudit.SeverityMedium,
		Title:          "Crosswalk entries missing",
		Details:        strings.Join(in.MissingChecks, ", "),
		AuditorHint:    "These checks are not mapped to selected frameworks.",
		Recommendation: "Map missing checks in control_crosswalk.v1.yaml.",
	}
}

func mapEvidenceRefs(checkID securityaudit.CheckID) []string {
	switch checkID {
	case securityaudit.CheckBuildInfoPresent:
		return []string{securityaudit.ArtifactBuildInfo}
	case securityaudit.CheckSBOMGenerated:
		return []string{securityaudit.ArtifactSBOMSPDX, securityaudit.ArtifactSBOMCycloneDX}
	case securityaudit.CheckVulnResults:
		return []string{securityaudit.ArtifactVulnReport}
	case securityaudit.CheckBinarySHA256:
		return []string{securityaudit.ArtifactBinaryChecksums}
	case securityaudit.CheckSignatureVerified:
		return []string{securityaudit.ArtifactSignatureVerify, securityaudit.ArtifactBinaryChecksums}
	case securityaudit.CheckRuntimeNetworkNone, securityaudit.CheckOfflineEnforcement:
		return []string{securityaudit.ArtifactNetworkEgress}
	case securityaudit.CheckFSAccessDisclosure:
		return []string{securityaudit.ArtifactFilesystemAccess}
	case securityaudit.CheckControlMapping, securityaudit.CheckControlMapMissing:
		return []string{securityaudit.ArtifactControlCrosswalk}
	default:
		return nil
	}
}

func errorStringOrDefault(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return fallback
	}
	return msg
}

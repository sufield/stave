package securityaudit

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/domain/securityaudit"
)

func findingFromHardening(in binaryInspectionSnapshot, err error) securityaudit.Finding {
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

func findingFromAuditLogging(in policyInspectionSnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckAuditLogging,
			Pillar:         securityaudit.PillarControls,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Audit logging check incomplete",
			Details:        err.Error(),
			AuditorHint:    "Could not verify local audit logging support.",
			Recommendation: "Verify logging configuration and rerun security-audit.",
		}
	}
	if in.Operational.AuditLoggingConfigured {
		return securityaudit.Finding{
			ID:             securityaudit.CheckAuditLogging,
			Pillar:         securityaudit.PillarControls,
			Status:         securityaudit.StatusPass,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Audit logging available",
			Details:        "CLI logging subsystem is present and configurable via --log-file/--log-format.",
			AuditorHint:    "Operational events can be captured locally for review.",
			Recommendation: "Route logs to protected storage for audit retention.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckAuditLogging,
		Pillar:         securityaudit.PillarControls,
		Status:         securityaudit.StatusWarn,
		Severity:       securityaudit.SeverityMedium,
		Title:          "Audit logging not configured",
		Details:        "Logging subsystem exists but no explicit audit-log policy was detected.",
		AuditorHint:    "Tamper-evident log posture depends on deployment configuration.",
		Recommendation: "Configure log file destination and retention controls for audited workflows.",
	}
}

func findingFromCrosswalk(in crosswalkSnapshot, err error) securityaudit.Finding {
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

func findingFromCrosswalkMissing(in crosswalkSnapshot) securityaudit.Finding {
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

func mapEvidenceRefs(checkID string) []string {
	switch checkID {
	case securityaudit.CheckBuildInfoPresent:
		return []string{"build_info.json"}
	case securityaudit.CheckSBOMGenerated:
		return []string{"sbom.spdx.json", "sbom.cdx.json"}
	case securityaudit.CheckVulnResults:
		return []string{"vuln_report.json"}
	case securityaudit.CheckBinarySHA256:
		return []string{"binary_checksums.json"}
	case securityaudit.CheckSignatureVerified:
		return []string{"signature_verification.json", "binary_checksums.json"}
	case securityaudit.CheckRuntimeNetworkNone, securityaudit.CheckOfflineEnforcement:
		return []string{"network_egress_declaration.json"}
	case securityaudit.CheckFSAccessDisclosure:
		return []string{"filesystem_access_declaration.json"}
	case securityaudit.CheckControlMapping, securityaudit.CheckControlMapMissing:
		return []string{"control_crosswalk_resolution.json"}
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

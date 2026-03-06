package securityaudit

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/domain/securityaudit"
)

func findingFromBuildInfo(in buildInfoSnapshot) securityaudit.Finding {
	if in.Available {
		return securityaudit.Finding{
			ID:             securityaudit.CheckBuildInfoPresent,
			Pillar:         securityaudit.PillarSupplyChain,
			Status:         securityaudit.StatusPass,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Build metadata available",
			Details:        fmt.Sprintf("Build info detected (go version: %s).", in.GoVersion),
			AuditorHint:    "Dependencies can be enumerated from runtime metadata.",
			Recommendation: "Retain build metadata in release binaries to preserve SBOM traceability.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckBuildInfoPresent,
		Pillar:         securityaudit.PillarSupplyChain,
		Status:         securityaudit.StatusFail,
		Severity:       securityaudit.SeverityHigh,
		Title:          "Build metadata unavailable",
		Details:        "runtime/debug build info is not available in this binary.",
		AuditorHint:    "Without build info, runtime SBOM provenance is incomplete.",
		Recommendation: "Rebuild with standard Go build metadata enabled and rerun security-audit.",
	}
}

func findingFromSBOM(in sbomSnapshot, err error) securityaudit.Finding {
	if err == nil && len(in.RawJSON) > 0 {
		return securityaudit.Finding{
			ID:             securityaudit.CheckSBOMGenerated,
			Pillar:         securityaudit.PillarSupplyChain,
			Status:         securityaudit.StatusPass,
			Severity:       securityaudit.SeverityHigh,
			Title:          "SBOM generated",
			Details:        fmt.Sprintf("Generated %s with %d dependencies.", in.FileName, in.DependencyCount),
			AuditorHint:    "Standardized SBOM is available for third-party risk review.",
			Recommendation: "Archive the SBOM artifact with release evidence.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckSBOMGenerated,
		Pillar:         securityaudit.PillarSupplyChain,
		Status:         securityaudit.StatusFail,
		Severity:       securityaudit.SeverityHigh,
		Title:          "SBOM generation failed",
		Details:        errorStringOrDefault(err, "SBOM generation did not produce output."),
		AuditorHint:    "Missing SBOM blocks dependency-level supply-chain review.",
		Recommendation: "Run with --sbom spdx or --sbom cyclonedx and ensure build info is present.",
	}
}

func findingFromVuln(in vulnerabilitySnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckVulnResults,
			Pillar:         securityaudit.PillarSupplyChain,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Vulnerability evidence unresolved",
			Details:        err.Error(),
			AuditorHint:    "Audit cannot prove vulnerability posture without evidence.",
			Recommendation: "Provide CI vuln artifact or run with --live-vuln-check.",
		}
	}
	if !in.Available {
		return securityaudit.Finding{
			ID:             securityaudit.CheckVulnResults,
			Pillar:         securityaudit.PillarSupplyChain,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityHigh,
			Title:          "No vulnerability evidence found",
			Details:        in.Details,
			AuditorHint:    "Hybrid policy requires local or CI vulnerability evidence.",
			Recommendation: "Run govulncheck locally (`--live-vuln-check`) or attach CI evidence.",
		}
	}
	if in.FindingCount > 0 {
		return securityaudit.Finding{
			ID:             securityaudit.CheckVulnResults,
			Pillar:         securityaudit.PillarSupplyChain,
			Status:         securityaudit.StatusFail,
			Severity:       securityaudit.SeverityCritical,
			Title:          "Known vulnerabilities detected",
			Details:        fmt.Sprintf("Vulnerability evidence source=%s reports %d findings.", in.SourceUsed, in.FindingCount),
			AuditorHint:    "At least one vulnerability requires remediation before release approval.",
			Recommendation: "Remediate affected modules and rerun security-audit until zero findings.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckVulnResults,
		Pillar:         securityaudit.PillarSupplyChain,
		Status:         securityaudit.StatusPass,
		Severity:       securityaudit.SeverityHigh,
		Title:          "No known vulnerabilities in evidence",
		Details:        fmt.Sprintf("Source=%s, findings=0.", in.SourceUsed),
		AuditorHint:    "Evidence indicates no known vulnerable dependencies at check time.",
		Recommendation: "Retain vuln_report.json as release evidence.",
	}
}

func findingFromBinaryHash(in binaryInspectionSnapshot, err error) securityaudit.Finding {
	if err == nil && strings.TrimSpace(in.SHA256) != "" {
		return securityaudit.Finding{
			ID:             securityaudit.CheckBinarySHA256,
			Pillar:         securityaudit.PillarSupplyChain,
			Status:         securityaudit.StatusPass,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Binary checksum generated",
			Details:        fmt.Sprintf("SHA-256 computed for %s.", in.BinaryPath),
			AuditorHint:    "Checksum enables integrity verification against release artifacts.",
			Recommendation: "Compare checksum with trusted release manifests.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckBinarySHA256,
		Pillar:         securityaudit.PillarSupplyChain,
		Status:         securityaudit.StatusFail,
		Severity:       securityaudit.SeverityHigh,
		Title:          "Binary checksum unavailable",
		Details:        errorStringOrDefault(err, "Failed to compute running binary hash."),
		AuditorHint:    "Integrity checks cannot be performed without binary digest.",
		Recommendation: "Ensure the binary path is accessible and rerun security-audit.",
	}
}

func findingFromSignature(in binaryInspectionSnapshot, err error) securityaudit.Finding {
	if err != nil && in.SignatureAttempt {
		return securityaudit.Finding{
			ID:             securityaudit.CheckSignatureVerified,
			Pillar:         securityaudit.PillarSupplyChain,
			Status:         securityaudit.StatusFail,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Release signature verification failed",
			Details:        err.Error(),
			AuditorHint:    "Release artifact integrity could not be verified.",
			Recommendation: "Provide a valid --release-bundle-dir with SHA256SUMS and signatures.",
		}
	}
	if !in.SignatureAttempt {
		return securityaudit.Finding{
			ID:             securityaudit.CheckSignatureVerified,
			Pillar:         securityaudit.PillarSupplyChain,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Release signature verification skipped",
			Details:        "No --release-bundle-dir supplied; verification not attempted.",
			AuditorHint:    "Signature verification is optional unless release artifacts are provided.",
			Recommendation: "Provide --release-bundle-dir to verify checksum/signature evidence.",
		}
	}
	if in.SignatureVerified {
		return securityaudit.Finding{
			ID:             securityaudit.CheckSignatureVerified,
			Pillar:         securityaudit.PillarSupplyChain,
			Status:         securityaudit.StatusPass,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Release signature evidence verified",
			Details:        in.SignatureDetail,
			AuditorHint:    "Checksum/signature bundle matched the running binary.",
			Recommendation: "Archive signature verification artifact for release audit records.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckSignatureVerified,
		Pillar:         securityaudit.PillarSupplyChain,
		Status:         securityaudit.StatusWarn,
		Severity:       securityaudit.SeverityMedium,
		Title:          "Release signature verification inconclusive",
		Details:        in.SignatureDetail,
		AuditorHint:    "Evidence bundle was provided but did not produce a definitive verification.",
		Recommendation: "Confirm release bundle completeness and rerun security-audit.",
	}
}

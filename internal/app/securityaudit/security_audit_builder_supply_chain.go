package securityaudit

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

var buildInfoSpec = findingSpec{ //nolint:gosec // audit template, not a credential
	ID:       securityaudit.CheckBuildInfoPresent,
	Pillar:   securityaudit.PillarSupplyChain,
	Severity: securityaudit.SeverityHigh,

	ErrStatus: securityaudit.StatusFail,

	PassTitle: "Build metadata available",
	PassHint:  "Dependencies can be enumerated from runtime metadata.",
	PassReco:  "Retain build metadata in release binaries to preserve SBOM traceability.",

	FailStatus:  securityaudit.StatusFail,
	FailTitle:   "Build metadata unavailable",
	FailDetails: "runtime/debug build info is not available in this binary.",
	FailHint:    "Without build info, runtime SBOM provenance is incomplete.",
	FailReco:    "Rebuild with standard Go build metadata enabled and rerun security-audit.",
}

func findingFromBuildInfo(in evidence.BuildInfoSnapshot) securityaudit.Finding {
	return buildFinding(buildInfoSpec, nil, in.Available,
		fmt.Sprintf("Build info detected (go version: %s).", in.GoVersion), "")
}

var sbomSpec = findingSpec{ //nolint:gosec // audit template, not a credential
	ID:       securityaudit.CheckSBOMGenerated,
	Pillar:   securityaudit.PillarSupplyChain,
	Severity: securityaudit.SeverityHigh,

	ErrStatus: securityaudit.StatusFail,
	ErrTitle:  "SBOM generation failed",
	ErrHint:   "Missing SBOM blocks dependency-level supply-chain review.",
	ErrReco:   "Run with --sbom spdx or --sbom cyclonedx and ensure build info is present.",

	PassTitle: "SBOM generated",
	PassHint:  "Standardized SBOM is available for third-party risk review.",
	PassReco:  "Archive the SBOM artifact with release evidence.",

	FailStatus: securityaudit.StatusFail,
	FailTitle:  "SBOM generation failed",
	FailHint:   "Missing SBOM blocks dependency-level supply-chain review.",
	FailReco:   "Run with --sbom spdx or --sbom cyclonedx and ensure build info is present.",
}

func findingFromSBOM(in evidence.SBOMSnapshot, err error) securityaudit.Finding {
	pass := err == nil && len(in.RawJSON) > 0
	passDetails := ""
	if pass {
		passDetails = fmt.Sprintf("Generated %s with %d dependencies.", in.FileName, in.DependencyCount)
	}
	failDetails := errorStringOrDefault(err, "SBOM generation did not produce output.")
	return buildFinding(sbomSpec, nil, pass, passDetails, failDetails)
}

var binaryHashSpec = findingSpec{ //nolint:gosec // audit template, not a credential
	ID:       securityaudit.CheckBinarySHA256,
	Pillar:   securityaudit.PillarSupplyChain,
	Severity: securityaudit.SeverityHigh,

	ErrStatus: securityaudit.StatusFail,

	PassTitle: "Binary checksum generated",
	PassHint:  "Checksum enables integrity verification against release artifacts.",
	PassReco:  "Compare checksum with trusted release manifests.",

	FailStatus: securityaudit.StatusFail,
	FailTitle:  "Binary checksum unavailable",
	FailHint:   "Integrity checks cannot be performed without binary digest.",
	FailReco:   "Ensure the binary path is accessible and rerun security-audit.",
}

func findingFromBinaryHash(in evidence.BinaryInspectionSnapshot, err error) securityaudit.Finding {
	pass := err == nil && strings.TrimSpace(in.SHA256) != ""
	passDetails := ""
	if pass {
		passDetails = fmt.Sprintf("SHA-256 computed for %s.", in.BinaryPath)
	}
	failDetails := errorStringOrDefault(err, "Failed to compute running binary hash.")
	return buildFinding(binaryHashSpec, nil, pass, passDetails, failDetails)
}

// findingFromVuln is complex (4-path with severity escalation) — kept explicit.
func findingFromVuln(in evidence.VulnerabilitySnapshot, err error) securityaudit.Finding {
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

// findingFromSignature is complex (4-path with flag checks) — kept explicit.
func findingFromSignature(in evidence.BinaryInspectionSnapshot, err error) securityaudit.Finding {
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

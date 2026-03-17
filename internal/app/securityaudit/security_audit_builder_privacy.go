package securityaudit

import (
	"strings"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/internal/domain/securityaudit"
)

func findingFromCredentialStorage(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckCredentialStorage,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Credential handling inspection incomplete",
			Details:        err.Error(),
			AuditorHint:    "Could not verify credential-env handling restrictions from source.",
			Recommendation: "Run security-audit from repository root.",
		}
	}
	if !in.Credential.CredentialPolicyOK {
		return securityaudit.Finding{
			ID:             securityaudit.CheckCredentialStorage,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         securityaudit.StatusFail,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Credential environment variable references detected",
			Details:        strings.Join(in.Credential.CredentialViolations, "; "),
			AuditorHint:    "Runtime code references forbidden credential environment variables.",
			Recommendation: "Remove credential-env usage from runtime paths.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckCredentialStorage,
		Pillar:         securityaudit.PillarPrivacy,
		Status:         securityaudit.StatusPass,
		Severity:       securityaudit.SeverityHigh,
		Title:          "Credential storage policy enforced",
		Details:        "No forbidden credential environment variable reads detected.",
		AuditorHint:    "Runtime avoids direct credential-env reads in offline data model.",
		Recommendation: "Retain this policy in CI static checks.",
	}
}

func findingFromRedaction(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckSanitizationPolicy,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Sanitization policy verification incomplete",
			Details:        err.Error(),
			AuditorHint:    "Could not verify sanitization controls from source.",
			Recommendation: "Ensure internal/sanitize package is present and rerun.",
		}
	}
	if !in.Operational.RedactionPolicyOK {
		return securityaudit.Finding{
			ID:             securityaudit.CheckSanitizationPolicy,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         securityaudit.StatusFail,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Sanitization policy unavailable",
			Details:        "Sanitization package/features were not detected.",
			AuditorHint:    "Potential risk of sensitive identifier leakage in outputs.",
			Recommendation: "Enable and test output sanitization policy paths.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckSanitizationPolicy,
		Pillar:         securityaudit.PillarPrivacy,
		Status:         securityaudit.StatusPass,
		Severity:       securityaudit.SeverityMedium,
		Title:          "Sanitization policy declared",
		Details:        "Sanitization controls are available for output sanitization.",
		AuditorHint:    "Supports privacy-preserving sharing workflows.",
		Recommendation: "Use --sanitize for sharable reports.",
	}
}

func findingFromTelemetry(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckTelemetryDecl,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Telemetry disclosure incomplete",
			Details:        err.Error(),
			AuditorHint:    "Unable to complete telemetry declaration checks.",
			Recommendation: "Run from source checkout and verify network policy artifacts.",
		}
	}
	if !in.Operational.TelemetryDeclaredNone {
		return securityaudit.Finding{
			ID:             securityaudit.CheckTelemetryDecl,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         securityaudit.StatusFail,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Telemetry endpoints not declared as none",
			Details:        "Runtime policy inspection indicates potential undeclared network behavior.",
			AuditorHint:    "Telemetry disclosure must explicitly state no outbound data.",
			Recommendation: "Remove undeclared egress paths or declare justified endpoints.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckTelemetryDecl,
		Pillar:         securityaudit.PillarPrivacy,
		Status:         securityaudit.StatusPass,
		Severity:       securityaudit.SeverityHigh,
		Title:          "Telemetry disclosure: none",
		Details:        "No telemetry endpoints declared; offline policy is consistent.",
		AuditorHint:    "Supports privacy reviews for restricted environments.",
		Recommendation: "Maintain explicit no-telemetry declaration in docs and policy artifacts.",
	}
}

func findingFromPrivacyMode(in evidence.PolicyInspectionSnapshot, req SecurityAuditRequest, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckPrivacyMode,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Privacy mode assertion incomplete",
			Details:        err.Error(),
			AuditorHint:    "Could not fully evaluate privacy-mode assertions.",
			Recommendation: "Rerun with source checkout and full artifact generation.",
		}
	}
	if !req.PrivacyMode {
		return securityaudit.Finding{
			ID:             securityaudit.CheckPrivacyMode,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityLow,
			Title:          "Privacy mode not asserted",
			Details:        "Run did not enable --privacy-mode assertions.",
			AuditorHint:    "Privacy-mode checks are available but were not requested.",
			Recommendation: "Enable --privacy-mode for stricter data-handling assertions.",
		}
	}
	if in.Operational.TelemetryDeclaredNone && in.Operational.RedactionPolicyOK && in.Credential.CredentialPolicyOK {
		return securityaudit.Finding{
			ID:             securityaudit.CheckPrivacyMode,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         securityaudit.StatusPass,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Privacy mode assertions passed",
			Details:        "Telemetry=none, sanitization policy present, credential policy checks passed.",
			AuditorHint:    "Requested privacy assertions are satisfied.",
			Recommendation: "Use privacy-mode output as audit evidence in restricted environments.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckPrivacyMode,
		Pillar:         securityaudit.PillarPrivacy,
		Status:         securityaudit.StatusFail,
		Severity:       securityaudit.SeverityMedium,
		Title:          "Privacy mode assertions failed",
		Details:        "One or more privacy assertions failed (telemetry/sanitization/credential policy).",
		AuditorHint:    "Requested strict privacy posture is not fully satisfied.",
		Recommendation: "Resolve failing privacy checks and rerun with --privacy-mode.",
	}
}

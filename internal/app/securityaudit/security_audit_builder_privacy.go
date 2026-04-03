package securityaudit

import (
	"strings"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/outcome"
	"github.com/sufield/stave/internal/core/securityaudit"
)

var credentialSpec = findingSpec{ //nolint:gosec // audit template, not a credential
	ID:       securityaudit.CheckCredentialStorage,
	Pillar:   securityaudit.PillarPrivacy,
	Severity: policy.SeverityHigh,

	ErrStatus: outcome.Warn,
	ErrTitle:  "Credential handling inspection incomplete",
	ErrHint:   "Could not verify credential-env handling restrictions from source.",
	ErrReco:   "Run security-audit from repository root.",

	PassTitle:   "Credential storage policy enforced",
	PassDetails: "No forbidden credential environment variable reads detected.",
	PassHint:    "Runtime avoids direct credential-env reads in offline data model.",
	PassReco:    "Retain this policy in CI static checks.",

	FailStatus: outcome.Fail,
	FailTitle:  "Credential environment variable references detected",
	FailHint:   "Runtime code references forbidden credential environment variables.",
	FailReco:   "Remove credential-env usage from runtime paths.",
}

func findingFromCredentialStorage(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	return buildFinding(credentialSpec, err, in.Credential.CredentialPolicyOK,
		"", strings.Join(in.Credential.CredentialViolations, "; "))
}

var redactionSpec = findingSpec{ //nolint:gosec // audit template, not a credential
	ID:       securityaudit.CheckSanitizationPolicy,
	Pillar:   securityaudit.PillarPrivacy,
	Severity: policy.SeverityMedium,

	ErrStatus: outcome.Warn,
	ErrTitle:  "Sanitization policy verification incomplete",
	ErrHint:   "Could not verify sanitization controls from source.",
	ErrReco:   "Ensure internal/sanitize package is present and rerun.",

	PassTitle:   "Sanitization policy declared",
	PassDetails: "Sanitization controls are available for output sanitization.",
	PassHint:    "Supports privacy-preserving sharing workflows.",
	PassReco:    "Use --sanitize for sharable reports.",

	FailStatus:  outcome.Fail,
	FailTitle:   "Sanitization policy unavailable",
	FailDetails: "Sanitization package/features were not detected.",
	FailHint:    "Potential risk of sensitive identifier leakage in outputs.",
	FailReco:    "Enable and test output sanitization policy paths.",
}

func findingFromRedaction(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	return buildFinding(redactionSpec, err, in.Operational.RedactionPolicyOK, "", "")
}

var telemetrySpec = findingSpec{ //nolint:gosec // audit template, not a credential
	ID:       securityaudit.CheckTelemetryDecl,
	Pillar:   securityaudit.PillarPrivacy,
	Severity: policy.SeverityHigh,

	ErrStatus: outcome.Warn,
	ErrTitle:  "Telemetry disclosure incomplete",
	ErrHint:   "Unable to complete telemetry declaration checks.",
	ErrReco:   "Run from source checkout and verify network policy artifacts.",

	PassTitle:   "Telemetry disclosure: none",
	PassDetails: "No telemetry endpoints declared; offline policy is consistent.",
	PassHint:    "Supports privacy reviews for restricted environments.",
	PassReco:    "Maintain explicit no-telemetry declaration in docs and policy artifacts.",

	FailStatus:  outcome.Fail,
	FailTitle:   "Telemetry endpoints not declared as none",
	FailDetails: "Runtime policy inspection indicates potential undeclared network behavior.",
	FailHint:    "Telemetry disclosure must explicitly state no outbound data.",
	FailReco:    "Remove undeclared egress paths or declare justified endpoints.",
}

func findingFromTelemetry(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	return buildFinding(telemetrySpec, err, in.Operational.TelemetryDeclaredNone, "", "")
}

// findingFromPrivacyMode is complex (4-path with Request parameter) — kept explicit.
func findingFromPrivacyMode(in evidence.PolicyInspectionSnapshot, req Request, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckPrivacyMode,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         outcome.Warn,
			Severity:       policy.SeverityMedium,
			Title:          "Privacy mode assertion incomplete",
			Details:        err.Error(),
			AuditorHint:    "Could not fully evaluate privacy-mode assertions.",
			Recommendation: "Rerun with source checkout and full artifact generation.",
		}
	}
	if !req.PrivacyEnabled {
		return securityaudit.Finding{
			ID:             securityaudit.CheckPrivacyMode,
			Pillar:         securityaudit.PillarPrivacy,
			Status:         outcome.Warn,
			Severity:       policy.SeverityLow,
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
			Status:         outcome.Pass,
			Severity:       policy.SeverityMedium,
			Title:          "Privacy mode assertions passed",
			Details:        "Telemetry=none, sanitization policy present, credential policy checks passed.",
			AuditorHint:    "Requested privacy assertions are satisfied.",
			Recommendation: "Use privacy-mode output as audit evidence in restricted environments.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckPrivacyMode,
		Pillar:         securityaudit.PillarPrivacy,
		Status:         outcome.Fail,
		Severity:       policy.SeverityMedium,
		Title:          "Privacy mode assertions failed",
		Details:        "One or more privacy assertions failed (telemetry/sanitization/credential policy).",
		AuditorHint:    "Requested strict privacy posture is not fully satisfied.",
		Recommendation: "Resolve failing privacy checks and rerun with --privacy-mode.",
	}
}

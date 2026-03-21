package securityaudit

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

func findingFromRuntimeNetwork(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckRuntimeNetworkNone,
			Pillar:         securityaudit.PillarRuntime,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Runtime network policy inspection incomplete",
			Details:        err.Error(),
			AuditorHint:    "Source-level network import inspection did not complete.",
			Recommendation: "Run security-audit from repository root with source files available.",
		}
	}
	if !in.Network.RuntimeNetworkOK {
		return securityaudit.Finding{
			ID:             securityaudit.CheckRuntimeNetworkNone,
			Pillar:         securityaudit.PillarRuntime,
			Status:         securityaudit.StatusFail,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Runtime network imports detected",
			Details:        strings.Join(in.Network.RuntimeViolations, "; "),
			AuditorHint:    "Runtime path includes banned network-capable imports.",
			Recommendation: "Remove banned imports or explicitly justify/allowlist the file-path mapping.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckRuntimeNetworkNone,
		Pillar:         securityaudit.PillarRuntime,
		Status:         securityaudit.StatusPass,
		Severity:       securityaudit.SeverityHigh,
		Title:          "No banned runtime network imports",
		Details:        "Runtime import inspection found no banned network-capable imports.",
		AuditorHint:    "Supports offline runtime behavior expectations.",
		Recommendation: "Keep banned import tests enabled in CI.",
	}
}

func findingFromOffline(in evidence.PolicyInspectionSnapshot, req Request, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckOfflineEnforcement,
			Pillar:         securityaudit.PillarRuntime,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Offline enforcement check incomplete",
			Details:        err.Error(),
			AuditorHint:    "Proxy environment verification failed unexpectedly.",
			Recommendation: "Run in a stable shell and rerun security-audit.",
		}
	}
	if req.RequireOffline && len(in.ProxyVarsSet) > 0 {
		return securityaudit.Finding{
			ID:             securityaudit.CheckOfflineEnforcement,
			Pillar:         securityaudit.PillarRuntime,
			Status:         securityaudit.StatusFail,
			Severity:       securityaudit.SeverityHigh,
			Title:          "Offline enforcement failed",
			Details:        fmt.Sprintf("Proxy environment variables are set: %s", strings.Join(in.ProxyVarsSet, ", ")),
			AuditorHint:    "--require-offline was requested and policy checks found proxy settings.",
			Recommendation: "Unset proxy variables or run without --require-offline.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckOfflineEnforcement,
		Pillar:         securityaudit.PillarRuntime,
		Status:         securityaudit.StatusPass,
		Severity:       securityaudit.SeverityHigh,
		Title:          "Offline enforcement passed",
		Details:        "Proxy environment checks satisfy offline policy expectations.",
		AuditorHint:    "Offline mode remains deterministic unless explicitly opting into live checks.",
		Recommendation: "Use --require-offline in CI for strict enforcement.",
	}
}

func findingFromFSDisclosure(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckFSAccessDisclosure,
			Pillar:         securityaudit.PillarRuntime,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Filesystem disclosure incomplete",
			Details:        err.Error(),
			AuditorHint:    "Read/write footprint declaration could not be generated.",
			Recommendation: "Rerun security-audit with writable bundle directory.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckFSAccessDisclosure,
		Pillar:         securityaudit.PillarRuntime,
		Status:         securityaudit.StatusPass,
		Severity:       securityaudit.SeverityMedium,
		Title:          "Filesystem access declared",
		Details:        fmt.Sprintf("Declared %d read paths and %d write paths.", len(in.Filesystem.FilesystemReads), len(in.Filesystem.FilesystemWrites)),
		AuditorHint:    "Bundle includes explicit read/write footprint for review.",
		Recommendation: "Review filesystem_access_declaration.json with local policy owners.",
	}
}

func findingFromPrivilege(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckPrivilegeNoSudo,
			Pillar:         securityaudit.PillarRuntime,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Privilege check inconclusive",
			Details:        err.Error(),
			AuditorHint:    "Could not determine effective privilege level reliably.",
			Recommendation: "Run under a standard non-root account.",
		}
	}
	if in.Operational.RunningAsPrivileged {
		return securityaudit.Finding{
			ID:             securityaudit.CheckPrivilegeNoSudo,
			Pillar:         securityaudit.PillarRuntime,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityMedium,
			Title:          "Running with elevated privilege",
			Details:        "Command is running as root/administrator even though it is not required.",
			AuditorHint:    "Least-privilege principle recommends non-elevated execution.",
			Recommendation: "Run the command as a standard user account.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckPrivilegeNoSudo,
		Pillar:         securityaudit.PillarRuntime,
		Status:         securityaudit.StatusPass,
		Severity:       securityaudit.SeverityMedium,
		Title:          "No elevated privilege required",
		Details:        "Audit run executed without root/admin requirement.",
		AuditorHint:    "Supports least-privilege deployment posture.",
		Recommendation: "Keep execution profiles non-privileged in CI and local automation.",
	}
}

func findingFromIAM(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckIAMS3MinPerms,
			Pillar:         securityaudit.PillarRuntime,
			Status:         securityaudit.StatusWarn,
			Severity:       securityaudit.SeverityHigh,
			Title:          "IAM minimum-permissions declaration unavailable",
			Details:        err.Error(),
			AuditorHint:    "Unable to disclose required S3 permissions from source-of-truth manifest.",
			Recommendation: "Regenerate IAM manifest and docs from the extractor mapping.",
		}
	}
	if len(in.IAMActions) == 0 {
		return securityaudit.Finding{
			ID:             securityaudit.CheckIAMS3MinPerms,
			Pillar:         securityaudit.PillarRuntime,
			Status:         securityaudit.StatusFail,
			Severity:       securityaudit.SeverityHigh,
			Title:          "IAM minimum permissions missing",
			Details:        "No required S3 IAM actions were declared.",
			AuditorHint:    "Permissions transparency requires explicit minimum-action list.",
			Recommendation: "Populate manifest_iam.go and regenerate docs/security/iam-minimum-s3-ingest.md.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckIAMS3MinPerms,
		Pillar:         securityaudit.PillarRuntime,
		Status:         securityaudit.StatusPass,
		Severity:       securityaudit.SeverityHigh,
		Title:          "IAM minimum permissions declared",
		Details:        fmt.Sprintf("%d S3 IAM actions declared for ingest.", len(in.IAMActions)),
		AuditorHint:    "Least-privilege review can be performed against documented action set.",
		Recommendation: "Compare this action list with deployed IAM policy statements.",
	}
}

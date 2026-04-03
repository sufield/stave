package securityaudit

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/outcome"
	"github.com/sufield/stave/internal/core/securityaudit"
)

var networkSpec = findingSpec{ //nolint:gosec // audit template, not a credential
	ID:       securityaudit.CheckRuntimeNetworkNone,
	Pillar:   securityaudit.PillarRuntime,
	Severity: policy.SeverityHigh,

	ErrStatus: outcome.Warn,
	ErrTitle:  "Runtime network policy inspection incomplete",
	ErrHint:   "Source-level network import inspection did not complete.",
	ErrReco:   "Run security-audit from repository root with source files available.",

	PassTitle:   "No banned runtime network imports",
	PassDetails: "Runtime import inspection found no banned network-capable imports.",
	PassHint:    "Supports offline runtime behavior expectations.",
	PassReco:    "Keep banned import tests enabled in CI.",

	FailStatus: outcome.Fail,
	FailTitle:  "Runtime network imports detected",
	FailHint:   "Runtime path includes banned network-capable imports.",
	FailReco:   "Remove banned imports or explicitly justify/allowlist the file-path mapping.",
}

func findingFromRuntimeNetwork(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	return buildFinding(networkSpec, err, in.Network.RuntimeNetworkOK,
		"", strings.Join(in.Network.RuntimeViolations, "; "))
}

var privilegeSpec = findingSpec{ //nolint:gosec // audit template, not a credential
	ID:       securityaudit.CheckPrivilegeNoSudo,
	Pillar:   securityaudit.PillarRuntime,
	Severity: policy.SeverityMedium,

	ErrStatus: outcome.Warn,
	ErrTitle:  "Privilege check inconclusive",
	ErrHint:   "Could not determine effective privilege level reliably.",
	ErrReco:   "Run under a standard non-root account.",

	PassTitle:   "No elevated privilege required",
	PassDetails: "Audit run executed without root/admin requirement.",
	PassHint:    "Supports least-privilege deployment posture.",
	PassReco:    "Keep execution profiles non-privileged in CI and local automation.",

	FailStatus:  outcome.Warn,
	FailTitle:   "Running with elevated privilege",
	FailDetails: "Command is running as root/administrator even though it is not required.",
	FailHint:    "Least-privilege principle recommends non-elevated execution.",
	FailReco:    "Run the command as a standard user account.",
}

func findingFromPrivilege(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	return buildFinding(privilegeSpec, err, !in.Operational.RunningAsPrivileged, "", "")
}

var iamSpec = findingSpec{ //nolint:gosec // audit template, not a credential
	ID:       securityaudit.CheckIAMS3MinPerms,
	Pillar:   securityaudit.PillarRuntime,
	Severity: policy.SeverityHigh,

	ErrStatus: outcome.Warn,
	ErrTitle:  "IAM minimum-permissions declaration unavailable",
	ErrHint:   "Unable to disclose required S3 permissions from source-of-truth manifest.",
	ErrReco:   "Regenerate IAM manifest and docs from the extractor mapping.",

	PassTitle: "IAM minimum permissions declared",
	PassHint:  "Least-privilege review can be performed against documented action set.",
	PassReco:  "Compare this action list with deployed IAM policy statements.",

	FailStatus:  outcome.Fail,
	FailTitle:   "IAM minimum permissions missing",
	FailDetails: "No required S3 IAM actions were declared.",
	FailHint:    "Permissions transparency requires explicit minimum-action list.",
	FailReco:    "Populate manifest_iam.go and regenerate docs/security/iam-minimum-s3-observation.md.",
}

func findingFromIAM(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	return buildFinding(iamSpec, err, len(in.IAMActions) > 0,
		fmt.Sprintf("%d S3 IAM actions declared for observation collection.", len(in.IAMActions)), "")
}

// findingFromOffline is complex (uses Request parameter) — kept explicit.
func findingFromOffline(in evidence.PolicyInspectionSnapshot, req Request, err error) securityaudit.Finding {
	if err != nil {
		return securityaudit.Finding{
			ID:             securityaudit.CheckOfflineEnforcement,
			Pillar:         securityaudit.PillarRuntime,
			Status:         outcome.Warn,
			Severity:       policy.SeverityHigh,
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
			Status:         outcome.Fail,
			Severity:       policy.SeverityHigh,
			Title:          "Offline enforcement failed",
			Details:        fmt.Sprintf("Proxy environment variables are set: %s", strings.Join(in.ProxyVarsSet, ", ")),
			AuditorHint:    "--require-offline was requested and policy checks found proxy settings.",
			Recommendation: "Unset proxy variables or run without --require-offline.",
		}
	}
	return securityaudit.Finding{
		ID:             securityaudit.CheckOfflineEnforcement,
		Pillar:         securityaudit.PillarRuntime,
		Status:         outcome.Pass,
		Severity:       policy.SeverityHigh,
		Title:          "Offline enforcement passed",
		Details:        "Proxy environment checks satisfy offline policy expectations.",
		AuditorHint:    "Offline mode remains deterministic unless explicitly opting into live checks.",
		Recommendation: "Use --require-offline in CI for strict enforcement.",
	}
}

var fsDisclosureSpec = findingSpec{ //nolint:gosec // not a credential — "Disclosure" triggers false positive
	ID:       securityaudit.CheckFSAccessDisclosure,
	Pillar:   securityaudit.PillarRuntime,
	Severity: policy.SeverityMedium,

	ErrStatus: outcome.Warn,
	ErrTitle:  "Filesystem disclosure incomplete",
	ErrHint:   "Read/write footprint declaration could not be generated.",
	ErrReco:   "Rerun security-audit with writable bundle directory.",

	PassTitle: "Filesystem access declared",
	PassHint:  "Bundle includes explicit read/write footprint for review.",
	PassReco:  "Review filesystem_access_declaration.json with local policy owners.",
}

func findingFromFSDisclosure(in evidence.PolicyInspectionSnapshot, err error) securityaudit.Finding {
	details := fmt.Sprintf("Declared %d read paths and %d write paths.", len(in.Filesystem.FilesystemReads), len(in.Filesystem.FilesystemWrites))
	return buildFinding(fsDisclosureSpec, err, true, details, "")
}

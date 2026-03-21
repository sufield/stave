package securityaudit

import (
	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

func buildFindings(ev evidence.Bundle, req Request) []securityaudit.Finding {
	findings := make([]securityaudit.Finding, 0, len(securityaudit.AllCheckIDs())+1)
	findings = append(findings, findingFromBuildInfo(ev.BuildInfo))
	findings = append(findings, findingFromSBOM(ev.SBOM, ev.SBOMErr))
	findings = append(findings, findingFromVuln(ev.Vuln, ev.VulnErr))
	findings = append(findings, findingFromBinaryHash(ev.Binary, ev.BinaryErr))
	findings = append(findings, findingFromSignature(ev.Binary, ev.BinaryErr))
	findings = append(findings, findingFromRuntimeNetwork(ev.Policy, ev.PolicyErr))
	findings = append(findings, findingFromOffline(ev.Policy, req, ev.PolicyErr))
	findings = append(findings, findingFromFSDisclosure(ev.Policy, ev.PolicyErr))
	findings = append(findings, findingFromPrivilege(ev.Policy, ev.PolicyErr))
	findings = append(findings, findingFromIAM(ev.Policy, ev.PolicyErr))
	findings = append(findings, findingFromCredentialStorage(ev.Policy, ev.PolicyErr))
	findings = append(findings, findingFromRedaction(ev.Policy, ev.PolicyErr))
	findings = append(findings, findingFromTelemetry(ev.Policy, ev.PolicyErr))
	findings = append(findings, findingFromPrivacyMode(ev.Policy, req, ev.PolicyErr))
	findings = append(findings, findingFromHardening(ev.Binary, ev.BinaryErr))
	findings = append(findings, findingFromAuditLogging(ev.Policy, ev.PolicyErr))
	findings = append(findings, findingFromCrosswalk(ev.Crosswalk, ev.CrosswalkErr))
	if len(ev.Crosswalk.MissingChecks) > 0 {
		findings = append(findings, findingFromCrosswalkMissing(ev.Crosswalk))
	}
	return findings
}

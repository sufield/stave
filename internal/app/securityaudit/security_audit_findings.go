package securityaudit

import (
	"github.com/sufield/stave/internal/domain/securityaudit"
)

func buildFindings(ev evidenceBundle, req SecurityAuditRequest) []securityaudit.Finding {
	findings := make([]securityaudit.Finding, 0, len(securityaudit.AllCheckIDs())+1)
	findings = append(findings, findingFromBuildInfo(ev.buildInfo))
	findings = append(findings, findingFromSBOM(ev.sbom, ev.sbomErr))
	findings = append(findings, findingFromVuln(ev.vuln, ev.vulnErr))
	findings = append(findings, findingFromBinaryHash(ev.binary, ev.binaryErr))
	findings = append(findings, findingFromSignature(ev.binary, ev.binaryErr))
	findings = append(findings, findingFromRuntimeNetwork(ev.policy, ev.policyErr))
	findings = append(findings, findingFromOffline(ev.policy, req, ev.policyErr))
	findings = append(findings, findingFromFSDisclosure(ev.policy, ev.policyErr))
	findings = append(findings, findingFromPrivilege(ev.policy, ev.policyErr))
	findings = append(findings, findingFromIAM(ev.policy, ev.policyErr))
	findings = append(findings, findingFromCredentialStorage(ev.policy, ev.policyErr))
	findings = append(findings, findingFromRedaction(ev.policy, ev.policyErr))
	findings = append(findings, findingFromTelemetry(ev.policy, ev.policyErr))
	findings = append(findings, findingFromPrivacyMode(ev.policy, req, ev.policyErr))
	findings = append(findings, findingFromHardening(ev.binary, ev.binaryErr))
	findings = append(findings, findingFromAuditLogging(ev.policy, ev.policyErr))
	findings = append(findings, findingFromCrosswalk(ev.crosswalk, ev.crosswalkErr))
	if len(ev.crosswalk.MissingChecks) > 0 {
		findings = append(findings, findingFromCrosswalkMissing(ev.crosswalk))
	}
	return findings
}

package securityaudit

import (
	"testing"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/internal/core/securityaudit"
)

func TestBuildFindings_AllPaths(t *testing.T) {
	ev := evidence.Bundle{
		BuildInfo: evidence.BuildInfoSnapshot{Available: true, GoVersion: "go1.26"},
		SBOM:      evidence.SBOMSnapshot{RawJSON: []byte(`{}`), FileName: "sbom.spdx.json", DependencyCount: 2},
		Vuln:      evidence.VulnerabilitySnapshot{Available: true, SourceUsed: "local"},
		Binary:    evidence.BinaryInspectionSnapshot{SHA256: "abc123", BinaryPath: "/bin/stave"},
		Policy: evidence.PolicyInspectionSnapshot{
			Network:    evidence.NetworkInspection{RuntimeNetworkOK: true},
			Credential: evidence.CredentialInspection{CredentialPolicyOK: true},
			Filesystem: evidence.FilesystemInspection{
				FilesystemReads:  []string{"/tmp"},
				FilesystemWrites: []string{"/out"},
			},
			Operational: evidence.OperationalInspection{
				RedactionPolicyOK:      true,
				TelemetryDeclaredNone:  true,
				AuditLoggingConfigured: true,
			},
			IAMActions: []string{"s3:GetObject"},
		},
		Crosswalk: evidence.CrosswalkSnapshot{},
	}
	req := Request{PrivacyEnabled: true}
	findings := buildFindings(ev, req)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	// Verify all findings have a non-empty ID
	for _, f := range findings {
		if f.ID == "" {
			t.Fatal("finding has empty ID")
		}
	}
}

func TestBuildFindings_WithCrosswalkMissing(t *testing.T) {
	ev := evidence.Bundle{
		BuildInfo: evidence.BuildInfoSnapshot{Available: false},
		Crosswalk: evidence.CrosswalkSnapshot{MissingChecks: []string{"SC.VULN"}},
	}
	findings := buildFindings(ev, Request{})
	// Should include crosswalk missing finding
	found := false
	for _, f := range findings {
		if f.ID == securityaudit.CheckControlMapMissing {
			found = true
		}
	}
	if !found {
		t.Fatal("expected CheckControlMapMissing finding")
	}
}

func TestAssembleReport_Basic(t *testing.T) {
	findings := []securityaudit.Finding{
		{
			ID:       securityaudit.CheckBuildInfoPresent,
			Pillar:   securityaudit.PillarSupplyChain,
			Status:   securityaudit.StatusPass,
			Severity: securityaudit.SeverityHigh,
		},
	}
	ev := evidence.Bundle{
		Crosswalk: evidence.CrosswalkSnapshot{
			ByCheck: map[string][]securityaudit.ControlRef{
				string(securityaudit.CheckBuildInfoPresent): {
					{Framework: "soc2", ControlID: "CC6.1"},
				},
			},
		},
	}
	req := NewRequest()
	artifacts := securityaudit.ArtifactManifest{}

	report := assembleReport(req, findings, ev, artifacts)
	if len(report.Findings) == 0 {
		t.Fatal("expected findings in report")
	}
}

func TestValidateRequest_BadSeverityFilter(t *testing.T) {
	req := NewRequest(WithSeverityFilter([]securityaudit.Severity{"bogus"}))
	if err := validateRequest(req); err == nil {
		t.Fatal("expected error for bad severity filter")
	}
}

func TestValidateRequest_BadFailOn(t *testing.T) {
	req := NewRequest(WithFailOn("bogus"))
	if err := validateRequest(req); err == nil {
		t.Fatal("expected error for bad fail-on")
	}
}

func TestValidateRequest_NoneFailOn(t *testing.T) {
	req := NewRequest(WithFailOn(securityaudit.SeverityNone))
	if err := validateRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

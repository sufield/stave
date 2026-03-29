package securityaudit

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/internal/core/securityaudit"
)

// ---------------------------------------------------------------------------
// findingSpec / buildFinding
// ---------------------------------------------------------------------------

func TestBuildFinding_ErrorPath(t *testing.T) {
	spec := findingSpec{
		ID:        securityaudit.CheckBuildInfoPresent,
		Pillar:    securityaudit.PillarSupplyChain,
		Severity:  securityaudit.SeverityHigh,
		ErrStatus: securityaudit.StatusWarn,
		ErrTitle:  "Build metadata unavailable",
		ErrHint:   "check hint",
		ErrReco:   "fix this",
	}
	f := buildFinding(spec, errForTest("boom"), false, "", "")
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("status = %v, want warn", f.Status)
	}
	if f.Title != "Build metadata unavailable" {
		t.Fatalf("title = %q", f.Title)
	}
	if f.Details != "boom" {
		t.Fatalf("details = %q", f.Details)
	}
}

func TestBuildFinding_PassPath(t *testing.T) {
	spec := findingSpec{
		ID:          securityaudit.CheckBuildInfoPresent,
		Pillar:      securityaudit.PillarSupplyChain,
		Severity:    securityaudit.SeverityHigh,
		PassTitle:   "Build metadata available",
		PassDetails: "default details",
		PassHint:    "hint",
		PassReco:    "reco",
	}
	f := buildFinding(spec, nil, true, "custom details", "")
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("status = %v, want pass", f.Status)
	}
	if f.Details != "custom details" {
		t.Fatalf("details = %q, want custom details", f.Details)
	}
}

func TestBuildFinding_PassPathDefaultDetails(t *testing.T) {
	spec := findingSpec{
		ID:          securityaudit.CheckBuildInfoPresent,
		Pillar:      securityaudit.PillarSupplyChain,
		Severity:    securityaudit.SeverityHigh,
		PassTitle:   "Build metadata available",
		PassDetails: "default details",
	}
	f := buildFinding(spec, nil, true, "", "")
	if f.Details != "default details" {
		t.Fatalf("details = %q, want default details", f.Details)
	}
}

func TestBuildFinding_FailPath(t *testing.T) {
	spec := findingSpec{
		ID:          securityaudit.CheckSBOMGenerated,
		Pillar:      securityaudit.PillarSupplyChain,
		Severity:    securityaudit.SeverityHigh,
		FailStatus:  securityaudit.StatusFail,
		FailTitle:   "SBOM generation failed",
		FailDetails: "default fail",
		FailHint:    "hint",
		FailReco:    "reco",
	}
	f := buildFinding(spec, nil, false, "", "custom fail")
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("status = %v, want fail", f.Status)
	}
	if f.Details != "custom fail" {
		t.Fatalf("details = %q, want custom fail", f.Details)
	}
}

func TestBuildFinding_FailPathDefaultDetails(t *testing.T) {
	spec := findingSpec{
		ID:          securityaudit.CheckSBOMGenerated,
		Pillar:      securityaudit.PillarSupplyChain,
		Severity:    securityaudit.SeverityHigh,
		FailStatus:  securityaudit.StatusFail,
		FailTitle:   "SBOM generation failed",
		FailDetails: "default fail",
	}
	f := buildFinding(spec, nil, false, "", "")
	if f.Details != "default fail" {
		t.Fatalf("details = %q, want default fail", f.Details)
	}
}

// ---------------------------------------------------------------------------
// Supply chain finding builders
// ---------------------------------------------------------------------------

func TestFindingFromBuildInfo(t *testing.T) {
	f := findingFromBuildInfo(evidence.BuildInfoSnapshot{Available: true, GoVersion: "go1.26"})
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("status = %v", f.Status)
	}
	f = findingFromBuildInfo(evidence.BuildInfoSnapshot{Available: false})
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("status = %v, want fail", f.Status)
	}
}

func TestFindingFromSBOM(t *testing.T) {
	f := findingFromSBOM(evidence.SBOMSnapshot{RawJSON: []byte(`{}`), FileName: "sbom.spdx.json", DependencyCount: 5}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("status = %v, want pass", f.Status)
	}
	f = findingFromSBOM(evidence.SBOMSnapshot{}, errForTest("fail"))
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("status = %v, want fail (error passed as fail, not error path)", f.Status)
	}
}

func TestFindingFromBinaryHash(t *testing.T) {
	f := findingFromBinaryHash(evidence.BinaryInspectionSnapshot{SHA256: "abc123", BinaryPath: "/usr/bin/stave"}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("status = %v, want pass", f.Status)
	}
	f = findingFromBinaryHash(evidence.BinaryInspectionSnapshot{SHA256: ""}, nil)
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("status = %v, want fail", f.Status)
	}
}

func TestFindingFromVuln(t *testing.T) {
	// Error
	f := findingFromVuln(evidence.VulnerabilitySnapshot{}, errForTest("scan failed"))
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("error path: status = %v, want warn", f.Status)
	}
	// Not available
	f = findingFromVuln(evidence.VulnerabilitySnapshot{Available: false, Details: "no evidence"}, nil)
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("unavailable path: status = %v, want warn", f.Status)
	}
	// Found vulns
	f = findingFromVuln(evidence.VulnerabilitySnapshot{Available: true, FindingCount: 3, SourceUsed: "local"}, nil)
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("found vulns: status = %v, want fail", f.Status)
	}
	if f.Severity != securityaudit.SeverityCritical {
		t.Fatalf("found vulns: severity = %v, want critical", f.Severity)
	}
	// Clean
	f = findingFromVuln(evidence.VulnerabilitySnapshot{Available: true, FindingCount: 0, SourceUsed: "local"}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("clean: status = %v, want pass", f.Status)
	}
}

func TestFindingFromSignature(t *testing.T) {
	// Error + attempt
	f := findingFromSignature(evidence.BinaryInspectionSnapshot{SignatureAttempt: true}, errForTest("verify failed"))
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("err+attempt: status = %v, want fail", f.Status)
	}
	// No attempt
	f = findingFromSignature(evidence.BinaryInspectionSnapshot{SignatureAttempt: false}, nil)
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("no attempt: status = %v, want warn", f.Status)
	}
	// Verified
	f = findingFromSignature(evidence.BinaryInspectionSnapshot{SignatureAttempt: true, SignatureVerified: true, SignatureDetail: "ok"}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("verified: status = %v, want pass", f.Status)
	}
	// Inconclusive
	f = findingFromSignature(evidence.BinaryInspectionSnapshot{SignatureAttempt: true, SignatureVerified: false, SignatureDetail: "inconclusive"}, nil)
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("inconclusive: status = %v, want warn", f.Status)
	}
}

// ---------------------------------------------------------------------------
// Runtime finding builders
// ---------------------------------------------------------------------------

func TestFindingFromRuntimeNetwork(t *testing.T) {
	f := findingFromRuntimeNetwork(evidence.PolicyInspectionSnapshot{
		Network: evidence.NetworkInspection{RuntimeNetworkOK: true},
	}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("ok: status = %v, want pass", f.Status)
	}
	f = findingFromRuntimeNetwork(evidence.PolicyInspectionSnapshot{
		Network: evidence.NetworkInspection{RuntimeNetworkOK: false, RuntimeViolations: []string{"net/http"}},
	}, nil)
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("violation: status = %v, want fail", f.Status)
	}
}

func TestFindingFromPrivilege(t *testing.T) {
	f := findingFromPrivilege(evidence.PolicyInspectionSnapshot{
		Operational: evidence.OperationalInspection{RunningAsPrivileged: false},
	}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("non-root: status = %v, want pass", f.Status)
	}
	f = findingFromPrivilege(evidence.PolicyInspectionSnapshot{
		Operational: evidence.OperationalInspection{RunningAsPrivileged: true},
	}, nil)
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("root: status = %v, want warn", f.Status)
	}
}

func TestFindingFromIAM(t *testing.T) {
	f := findingFromIAM(evidence.PolicyInspectionSnapshot{
		IAMActions: []string{"s3:GetObject", "s3:PutObject"},
	}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("with actions: status = %v, want pass", f.Status)
	}
	f = findingFromIAM(evidence.PolicyInspectionSnapshot{}, nil)
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("no actions: status = %v, want fail", f.Status)
	}
}

func TestFindingFromOffline(t *testing.T) {
	// Error
	f := findingFromOffline(evidence.PolicyInspectionSnapshot{}, Request{}, errForTest("fail"))
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("error: status = %v, want warn", f.Status)
	}
	// Require offline with proxy
	f = findingFromOffline(evidence.PolicyInspectionSnapshot{ProxyVarsSet: []string{"HTTPS_PROXY"}}, Request{RequireOffline: true}, nil)
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("proxy+offline: status = %v, want fail", f.Status)
	}
	// Pass
	f = findingFromOffline(evidence.PolicyInspectionSnapshot{}, Request{RequireOffline: true}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("pass: status = %v, want pass", f.Status)
	}
}

func TestFindingFromFSDisclosure(t *testing.T) {
	f := findingFromFSDisclosure(evidence.PolicyInspectionSnapshot{
		Filesystem: evidence.FilesystemInspection{
			FilesystemReads:  []string{"/tmp"},
			FilesystemWrites: []string{"/out"},
		},
	}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("status = %v, want pass", f.Status)
	}
	f = findingFromFSDisclosure(evidence.PolicyInspectionSnapshot{}, errForTest("fail"))
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("error: status = %v, want warn", f.Status)
	}
}

// ---------------------------------------------------------------------------
// Privacy finding builders
// ---------------------------------------------------------------------------

func TestFindingFromCredentialStorage(t *testing.T) {
	f := findingFromCredentialStorage(evidence.PolicyInspectionSnapshot{
		Credential: evidence.CredentialInspection{CredentialPolicyOK: true},
	}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("ok: status = %v, want pass", f.Status)
	}
	f = findingFromCredentialStorage(evidence.PolicyInspectionSnapshot{
		Credential: evidence.CredentialInspection{CredentialPolicyOK: false, CredentialViolations: []string{"AWS_SECRET"}},
	}, nil)
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("violation: status = %v, want fail", f.Status)
	}
}

func TestFindingFromRedaction(t *testing.T) {
	f := findingFromRedaction(evidence.PolicyInspectionSnapshot{
		Operational: evidence.OperationalInspection{RedactionPolicyOK: true},
	}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("ok: status = %v, want pass", f.Status)
	}
}

func TestFindingFromTelemetry(t *testing.T) {
	f := findingFromTelemetry(evidence.PolicyInspectionSnapshot{
		Operational: evidence.OperationalInspection{TelemetryDeclaredNone: true},
	}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("ok: status = %v, want pass", f.Status)
	}
}

func TestFindingFromPrivacyMode(t *testing.T) {
	// Error
	f := findingFromPrivacyMode(evidence.PolicyInspectionSnapshot{}, Request{}, errForTest("fail"))
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("error: status = %v, want warn", f.Status)
	}
	// Not enabled
	f = findingFromPrivacyMode(evidence.PolicyInspectionSnapshot{}, Request{PrivacyEnabled: false}, nil)
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("not enabled: status = %v, want warn", f.Status)
	}
	// Enabled and pass
	f = findingFromPrivacyMode(evidence.PolicyInspectionSnapshot{
		Operational: evidence.OperationalInspection{TelemetryDeclaredNone: true, RedactionPolicyOK: true},
		Credential:  evidence.CredentialInspection{CredentialPolicyOK: true},
	}, Request{PrivacyEnabled: true}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("pass: status = %v, want pass", f.Status)
	}
	// Enabled and fail
	f = findingFromPrivacyMode(evidence.PolicyInspectionSnapshot{
		Operational: evidence.OperationalInspection{TelemetryDeclaredNone: false},
	}, Request{PrivacyEnabled: true}, nil)
	if f.Status != securityaudit.StatusFail {
		t.Fatalf("fail: status = %v, want fail", f.Status)
	}
}

// ---------------------------------------------------------------------------
// Controls finding builders
// ---------------------------------------------------------------------------

func TestFindingFromHardening(t *testing.T) {
	f := findingFromHardening(evidence.BinaryInspectionSnapshot{HardeningLevel: securityaudit.StatusPass, HardeningDetail: "ok"}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("pass: status = %v", f.Status)
	}
	f = findingFromHardening(evidence.BinaryInspectionSnapshot{HardeningLevel: securityaudit.StatusWarn, HardeningDetail: "review"}, nil)
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("warn: status = %v", f.Status)
	}
	f = findingFromHardening(evidence.BinaryInspectionSnapshot{}, errForTest("fail"))
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("error: status = %v, want warn", f.Status)
	}
}

func TestFindingFromAuditLogging(t *testing.T) {
	f := findingFromAuditLogging(evidence.PolicyInspectionSnapshot{
		Operational: evidence.OperationalInspection{AuditLoggingConfigured: true},
	}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("ok: status = %v, want pass", f.Status)
	}
}

func TestFindingFromCrosswalk(t *testing.T) {
	// Pass
	f := findingFromCrosswalk(evidence.CrosswalkSnapshot{}, nil)
	if f.Status != securityaudit.StatusPass {
		t.Fatalf("pass: status = %v", f.Status)
	}
	// Missing
	f = findingFromCrosswalk(evidence.CrosswalkSnapshot{MissingChecks: []string{"SC.VULN"}}, nil)
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("missing: status = %v", f.Status)
	}
	// Error
	f = findingFromCrosswalk(evidence.CrosswalkSnapshot{}, errForTest("fail"))
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("error: status = %v, want warn", f.Status)
	}
}

func TestFindingFromCrosswalkMissing(t *testing.T) {
	f := findingFromCrosswalkMissing(evidence.CrosswalkSnapshot{MissingChecks: []string{"SC.VULN", "SC.SBOM"}})
	if f.Status != securityaudit.StatusWarn {
		t.Fatalf("status = %v, want warn", f.Status)
	}
	if f.ID != securityaudit.CheckControlMapMissing {
		t.Fatalf("id = %v", f.ID)
	}
}

// ---------------------------------------------------------------------------
// mapEvidenceRefs
// ---------------------------------------------------------------------------

func TestMapEvidenceRefs(t *testing.T) {
	tests := []struct {
		id      securityaudit.CheckID
		wantLen int
	}{
		{securityaudit.CheckBuildInfoPresent, 1},
		{securityaudit.CheckSBOMGenerated, 2},
		{securityaudit.CheckVulnResults, 1},
		{securityaudit.CheckBinarySHA256, 1},
		{securityaudit.CheckSignatureVerified, 2},
		{securityaudit.CheckRuntimeNetworkNone, 1},
		{securityaudit.CheckOfflineEnforcement, 1},
		{securityaudit.CheckFSAccessDisclosure, 1},
		{securityaudit.CheckControlMapping, 1},
		{securityaudit.CheckControlMapMissing, 1},
		{securityaudit.CheckPrivilegeNoSudo, 0},
	}
	for _, tt := range tests {
		refs := mapEvidenceRefs(tt.id)
		if len(refs) != tt.wantLen {
			t.Errorf("mapEvidenceRefs(%s) = %d refs, want %d", tt.id, len(refs), tt.wantLen)
		}
	}
}

// ---------------------------------------------------------------------------
// errorStringOrDefault
// ---------------------------------------------------------------------------

func TestErrorStringOrDefault(t *testing.T) {
	if got := errorStringOrDefault(nil, "fallback"); got != "fallback" {
		t.Fatalf("nil err: got %q, want 'fallback'", got)
	}
	if got := errorStringOrDefault(errForTest("hello"), "fallback"); got != "hello" {
		t.Fatalf("with err: got %q, want 'hello'", got)
	}
}

// ---------------------------------------------------------------------------
// Request / NewRequest / validateRequest
// ---------------------------------------------------------------------------

func TestNewRequestDefaults(t *testing.T) {
	req := NewRequest()
	if req.SBOMFormat != SBOMFormatSPDX {
		t.Fatalf("SBOMFormat = %v, want spdx", req.SBOMFormat)
	}
	if req.VulnSource != VulnSourceHybrid {
		t.Fatalf("VulnSource = %v, want hybrid", req.VulnSource)
	}
	if req.FailOn != securityaudit.SeverityHigh {
		t.Fatalf("FailOn = %v, want high", req.FailOn)
	}
	if req.StaveVersion != "unknown" {
		t.Fatalf("StaveVersion = %q", req.StaveVersion)
	}
}

func TestNewRequestWithOptions(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	req := NewRequest(
		WithNow(now),
		WithStaveVersion("v1.0.0"),
		WithCwd("/tmp"),
		WithBinaryPath("/usr/bin/stave"),
		WithOutDir("out"),
		WithSBOMFormat(SBOMFormatCycloneDX),
		WithVulnSource(VulnSourceLocal),
		WithLiveVulnCheck(true),
		WithReleaseBundleDir("/release"),
		WithPrivacy(true),
		WithFailOn(securityaudit.SeverityCritical),
		WithRequireOffline(true),
		WithSeverityFilter([]securityaudit.Severity{securityaudit.SeverityCritical}),
		WithComplianceFrameworks([]string{"soc2"}),
	)
	if req.Now != now {
		t.Fatalf("Now = %v", req.Now)
	}
	if req.StaveVersion != "v1.0.0" {
		t.Fatalf("StaveVersion = %q", req.StaveVersion)
	}
	if req.SBOMFormat != SBOMFormatCycloneDX {
		t.Fatalf("SBOMFormat = %v", req.SBOMFormat)
	}
	if !req.PrivacyEnabled {
		t.Fatal("PrivacyEnabled should be true")
	}
	if !req.RequireOffline {
		t.Fatal("RequireOffline should be true")
	}
}

func TestValidateRequest(t *testing.T) {
	req := NewRequest()
	if err := validateRequest(req); err != nil {
		t.Fatalf("valid request: %v", err)
	}

	bad := NewRequest(WithSBOMFormat("bogus"))
	if err := validateRequest(bad); err == nil {
		t.Fatal("expected error for bad SBOM format")
	}

	bad = NewRequest(WithVulnSource("bogus"))
	if err := validateRequest(bad); err == nil {
		t.Fatal("expected error for bad vuln source")
	}
}

// ---------------------------------------------------------------------------
// collectUniqueControls
// ---------------------------------------------------------------------------

func TestCollectUniqueControls(t *testing.T) {
	findings := []securityaudit.Finding{
		{ControlRefs: []securityaudit.ControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Rationale: "r1"},
			{Framework: "soc2", ControlID: "CC6.1", Rationale: "r1"}, // duplicate
		}},
		{ControlRefs: []securityaudit.ControlRef{
			{Framework: "soc2", ControlID: "CC7.1", Rationale: "r2"},
		}},
	}
	controls := collectUniqueControls(findings)
	if len(controls) != 2 {
		t.Fatalf("expected 2 unique controls, got %d", len(controls))
	}
}

// ---------------------------------------------------------------------------
// toParams
// ---------------------------------------------------------------------------

func TestToParams(t *testing.T) {
	req := NewRequest(
		WithCwd("/work"),
		WithBinaryPath("/bin/stave"),
		WithOutDir("out-dir"),
	)
	params := req.toParams()
	if params.Cwd != "/work" {
		t.Fatalf("Cwd = %q", params.Cwd)
	}
	if params.BinaryPath != "/bin/stave" {
		t.Fatalf("BinaryPath = %q", params.BinaryPath)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type testErr struct{ msg string }

func (e testErr) Error() string { return e.msg }

func errForTest(msg string) error { return testErr{msg} }

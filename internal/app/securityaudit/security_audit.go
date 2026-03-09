package securityaudit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/domain/securityaudit"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
)

// SecurityAuditRequest defines all inputs for a full enterprise audit run.
type SecurityAuditRequest struct {
	Now                  time.Time
	ToolVersion          string
	Cwd                  string
	BinaryPath           string
	OutDir               string
	SeverityFilter       []securityaudit.Severity
	SBOMFormat           string
	ComplianceFrameworks []string
	VulnSource           string
	LiveVulnCheck        bool
	ReleaseBundleDir     string
	PrivacyMode          bool
	FailOn               securityaudit.Severity
	RequireOffline       bool
}

// SecurityAuditRunner orchestrates security-audit evidence collection.
type SecurityAuditRunner struct {
	diagnostics defaultDiagnosticsService
	buildInfo   defaultBuildInfoProvider
	sbom        defaultSBOMGenerator
	vulns       defaultVulnEvidenceProvider
	binary      defaultBinaryInspector
	policy      defaultPolicyInspector
	crosswalk   defaultCrosswalkResolver
}

// NewSecurityAuditRunner wires default dependencies.
// The govulncheckRunner is injected from the adapter layer so that
// the app layer never imports os/exec directly.
// The signatureVerifier is optional — if nil, signature files are reported
// as found but not cryptographically verified.
func NewSecurityAuditRunner(govulncheckRunner GovulncheckRunner, signatureVerifier ports.Verifier) *SecurityAuditRunner {
	return &SecurityAuditRunner{
		diagnostics: defaultDiagnosticsService{},
		buildInfo:   defaultBuildInfoProvider{},
		sbom:        defaultSBOMGenerator{},
		vulns:       defaultVulnEvidenceProvider{runGovulncheck: govulncheckRunner},
		binary:      defaultBinaryInspector{signatureVerifier: signatureVerifier},
		policy:      defaultPolicyInspector{},
		crosswalk:   defaultCrosswalkResolver{},
	}
}

// Run executes the full security audit and returns the report + artifact bundle manifest.
func (r *SecurityAuditRunner) Run(
	ctx context.Context,
	req SecurityAuditRequest,
) (securityaudit.Report, securityaudit.ArtifactManifest, error) {
	req = normalizeSecurityAuditRequest(req)
	if err := validateSecurityAuditRequest(req); err != nil {
		return securityaudit.Report{}, securityaudit.ArtifactManifest{}, err
	}
	_, _ = r.diagnostics.Run(doctor.Context{
		Cwd:          req.Cwd,
		BinaryPath:   req.BinaryPath,
		StaveVersion: req.ToolVersion,
	})

	ev, err := r.collectEvidence(ctx, req)
	if err != nil {
		return securityaudit.Report{}, securityaudit.ArtifactManifest{}, err
	}

	findings := buildFindings(ev, req)
	artifacts := buildArtifactManifest(req, ev)
	report := assembleReport(req, findings, ev, artifacts)
	return report, artifacts, nil
}

func (r *SecurityAuditRunner) collectEvidence(ctx context.Context, req SecurityAuditRequest) (evidenceBundle, error) {
	buildInfo, err := r.buildInfo.Collect(req.Now)
	if err != nil {
		return evidenceBundle{}, fmt.Errorf("collect build info: %w", err)
	}
	sbom, sbomErr := r.sbom.Generate(buildInfo, req.SBOMFormat, req.Now)
	vuln, vulnErr := r.vulns.Resolve(ctx, req)
	binary, binaryErr := r.binary.Inspect(req, buildInfo)
	policy, policyErr := r.policy.Inspect(ctx, req)
	crosswalk, crosswalkErr := r.crosswalk.Resolve(ctx, req, securityaudit.AllCheckIDs())
	return evidenceBundle{
		buildInfo:    buildInfo,
		sbom:         sbom,
		sbomErr:      sbomErr,
		vuln:         vuln,
		vulnErr:      vulnErr,
		binary:       binary,
		binaryErr:    binaryErr,
		policy:       policy,
		policyErr:    policyErr,
		crosswalk:    crosswalk,
		crosswalkErr: crosswalkErr,
	}, nil
}

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

func buildArtifactManifest(req SecurityAuditRequest, ev evidenceBundle) securityaudit.ArtifactManifest {
	manifest := securityaudit.ArtifactManifest{
		SchemaVersion: string(kernel.SchemaSecurityAuditArtifacts),
		GeneratedAt:   req.Now.UTC().Format(time.RFC3339),
		BundleDir:     req.OutDir,
		Files:         make([]securityaudit.ArtifactEntry, 0, 10),
	}

	appendArtifact := func(path string, payload []byte) {
		if len(payload) == 0 || strings.TrimSpace(path) == "" {
			return
		}
		manifest.Files = append(manifest.Files, securityaudit.ArtifactEntry{
			Path:      filepath.Clean(path),
			SHA256:    string(platformcrypto.HashBytes(payload)),
			SizeBytes: int64(len(payload)),
			Content:   payload,
		})
	}

	appendArtifact(securityaudit.ArtifactBuildInfo, ev.buildInfo.RawJSON)
	appendArtifact(ev.sbom.FileName, ev.sbom.RawJSON)
	appendArtifact(securityaudit.ArtifactVulnReport, ev.vuln.RawJSON)
	appendArtifact(securityaudit.ArtifactBinaryChecksums, ev.binary.ChecksumJSON)
	if ev.binary.SignatureJSON != nil {
		appendArtifact(securityaudit.ArtifactSignatureVerify, ev.binary.SignatureJSON)
	}
	appendArtifact(securityaudit.ArtifactNetworkEgress, ev.policy.Network.NetworkDeclJSON)
	appendArtifact(securityaudit.ArtifactFilesystemAccess, ev.policy.Filesystem.FilesystemDeclJSON)
	appendArtifact(securityaudit.ArtifactControlCrosswalk, ev.crosswalk.ResolutionJSON)

	sort.Slice(manifest.Files, func(i, j int) bool {
		return manifest.Files[i].Path < manifest.Files[j].Path
	})
	return manifest
}

func assembleReport(req SecurityAuditRequest, findings []securityaudit.Finding, ev evidenceBundle, artifacts securityaudit.ArtifactManifest) securityaudit.Report {
	report := securityaudit.Report{
		SchemaVersion: string(kernel.SchemaSecurityAudit),
		GeneratedAt:   req.Now.UTC().Format(time.RFC3339),
		ToolVersion:   req.ToolVersion,
		Summary: securityaudit.Summary{
			BySeverity:        map[securityaudit.Severity]int{},
			FailOn:            req.FailOn,
			VulnSourceUsed:    ev.vuln.SourceUsed,
			EvidenceFreshness: ev.vuln.Freshness,
		},
		Findings: findings,
	}

	for i := range report.Findings {
		refs := ev.crosswalk.ByCheck[report.Findings[i].ID]
		report.Findings[i].ControlRefs = slices.Clone(refs)
	}

	report.EvidenceIndex = make([]securityaudit.EvidenceRef, 0, len(artifacts.Files))
	for _, file := range artifacts.Files {
		report.EvidenceIndex = append(report.EvidenceIndex, securityaudit.EvidenceRef{
			ID:     file.Path,
			Path:   file.Path,
			SHA256: file.SHA256,
		})
	}

	for i := range report.Findings {
		report.Findings[i].EvidenceRefs = mapEvidenceRefs(report.Findings[i].ID)
	}

	report.Normalize()
	report = report.FilterBySeverity(req.SeverityFilter)
	report.Controls = collectUniqueControls(report.Findings)
	report.Summary.FailOn = req.FailOn
	report.RecomputeSummary()
	report.Summary.VulnSourceUsed = ev.vuln.SourceUsed
	report.Summary.EvidenceFreshness = ev.vuln.Freshness
	report.Normalize()

	return report
}

func collectUniqueControls(findings []securityaudit.Finding) []securityaudit.ControlRef {
	set := map[string]securityaudit.ControlRef{}
	for _, finding := range findings {
		for _, ref := range finding.ControlRefs {
			key := ref.Framework + "|" + ref.ControlID + "|" + ref.Rationale
			set[key] = ref
		}
	}
	out := make([]securityaudit.ControlRef, 0, len(set))
	for _, ref := range set {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		if out[i].ControlID != out[j].ControlID {
			return out[i].ControlID < out[j].ControlID
		}
		return out[i].Rationale < out[j].Rationale
	})
	return out
}

func normalizeSecurityAuditRequest(req SecurityAuditRequest) SecurityAuditRequest {
	if req.Now.IsZero() {
		req.Now = time.Now().UTC()
	}
	if strings.TrimSpace(req.ToolVersion) == "" {
		req.ToolVersion = "unknown"
	}
	if strings.TrimSpace(req.Cwd) == "" {
		req.Cwd = "."
	}
	if strings.TrimSpace(req.SBOMFormat) == "" {
		req.SBOMFormat = "spdx"
	}
	req.SBOMFormat = strings.ToLower(strings.TrimSpace(req.SBOMFormat))
	if strings.TrimSpace(req.VulnSource) == "" {
		req.VulnSource = "hybrid"
	}
	req.VulnSource = strings.ToLower(strings.TrimSpace(req.VulnSource))
	if req.FailOn == "" {
		req.FailOn = securityaudit.SeverityHigh
	}
	if len(req.SeverityFilter) == 0 {
		req.SeverityFilter = []securityaudit.Severity{
			securityaudit.SeverityCritical,
			securityaudit.SeverityHigh,
		}
	}
	if strings.TrimSpace(req.BinaryPath) == "" {
		if exe, err := executablePath(); err == nil {
			req.BinaryPath = exe
		}
	}
	if strings.TrimSpace(req.OutDir) == "" {
		req.OutDir = fmt.Sprintf("security-audit-%s", req.Now.UTC().Format("20060102T150405Z"))
	}
	return req
}

func validateSecurityAuditRequest(req SecurityAuditRequest) error {
	if req.SBOMFormat != "spdx" && req.SBOMFormat != "cyclonedx" {
		return fmt.Errorf("invalid SBOM format %q (use spdx or cyclonedx)", req.SBOMFormat)
	}
	switch req.VulnSource {
	case "hybrid", "local", "ci":
	default:
		return fmt.Errorf("invalid vulnerability source %q (use hybrid, local, or ci)", req.VulnSource)
	}
	for _, sev := range req.SeverityFilter {
		if _, err := securityaudit.ParseSeverity(string(sev)); err != nil {
			return fmt.Errorf("invalid severity filter value %q: %w", sev, err)
		}
	}
	if req.FailOn != securityaudit.SeverityNone {
		if _, err := securityaudit.ParseSeverity(string(req.FailOn)); err != nil {
			return fmt.Errorf("invalid fail-on value %q: %w", req.FailOn, err)
		}
	}
	return nil
}

func executablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Abs(filepath.Clean(strings.TrimSpace(exe)))
}

package securityaudit

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/securityaudit"
)

// SecurityAuditRunner orchestrates security-audit evidence collection.
type SecurityAuditRunner struct {
	diagnostics defaultDiagnosticsService
	buildInfo   BuildInfoProvider
	sbom        SBOMGenerator
	vulns       VulnEvidenceProvider
	binary      BinaryInspector
	policy      PolicyInspector
	crosswalk   CrosswalkResolver
	hashBytes   func([]byte) kernel.Digest
}

// NewSecurityAuditRunner wires default dependencies.
// All platform and infrastructure operations are injected via RunnerDeps
// so the app layer never imports platform, adapter, or infrastructure packages.
func NewSecurityAuditRunner(deps RunnerDeps) *SecurityAuditRunner {
	return &SecurityAuditRunner{
		diagnostics: defaultDiagnosticsService{run: deps.RunDiagnostics},
		buildInfo:   defaultBuildInfoProvider{},
		sbom:        defaultSBOMGenerator{},
		vulns:       defaultVulnEvidenceProvider{runGovulncheck: deps.GovulncheckRunner, readFile: deps.ReadFile, statFile: deps.StatFile},
		binary:      defaultBinaryInspector{signatureVerifier: deps.SignatureVerifier, hashFile: deps.HashFile, readFile: deps.ReadFile, statFile: deps.StatFile},
		policy:      defaultPolicyInspector{readFile: deps.ReadFile, statFile: deps.StatFile, getenv: deps.Getenv, isPrivileged: deps.IsPrivileged, walkDir: deps.WalkDir},
		crosswalk:   defaultCrosswalkResolver{readFile: deps.ReadFile, resolve: deps.ResolveCrosswalk, statFile: deps.StatFile},
		hashBytes:   deps.HashBytes,
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
	if r.diagnostics.run != nil {
		r.diagnostics.run(req.Cwd, req.BinaryPath, req.ToolVersion)
	}

	ev, err := r.collectEvidence(ctx, req)
	if err != nil {
		return securityaudit.Report{}, securityaudit.ArtifactManifest{}, err
	}

	findings := buildFindings(ev, req)
	artifacts := r.buildArtifactManifest(req, ev)
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

package securityaudit

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

// Runner orchestrates security-audit evidence collection.
type Runner struct {
	collectors  evidence.Collectors
	diagnostics evidence.DefaultDiagnosticsService
	hashBytes   func([]byte) kernel.Digest
}

// NewRunner wires default dependencies.
// All platform and infrastructure operations are injected via RunnerDeps
// so the app layer never imports platform, adapter, or infrastructure packages.
func NewRunner(deps RunnerDeps) *Runner {
	return &Runner{
		collectors: evidence.NewCollectors(evidence.Deps{
			ReadFile:             deps.ReadFile,
			HashFile:             deps.HashFile,
			VulnerabilityScanner: deps.VulnerabilityScanner,
			SignatureVerifier:    deps.SignatureVerifier,
			StatFile:             deps.StatFile,
			Getenv:               deps.Getenv,
			IsPrivileged:         deps.IsPrivileged,
			WalkDir:              deps.WalkDir,
			ResolveCrosswalk:     deps.ResolveCrosswalk,
		}),
		diagnostics: evidence.DefaultDiagnosticsService{Run: deps.RunDiagnostics},
		hashBytes:   deps.HashBytes,
	}
}

// Run executes the full security audit and returns the report + artifact bundle manifest.
func (r *Runner) Run(
	ctx context.Context,
	req Request,
) (securityaudit.Report, securityaudit.ArtifactManifest, error) {
	req = normalizeRequest(req)
	if err := validateRequest(req); err != nil {
		return securityaudit.Report{}, securityaudit.ArtifactManifest{}, err
	}
	if r.diagnostics.Run != nil {
		r.diagnostics.Run(req.Cwd, req.BinaryPath, req.StaveVersion)
	}

	params := req.toParams()
	ev, err := r.collectEvidence(ctx, params)
	if err != nil {
		return securityaudit.Report{}, securityaudit.ArtifactManifest{}, err
	}

	findings := buildFindings(ev, req)
	artifacts := r.buildArtifactManifest(req, ev)
	report := assembleReport(req, findings, ev, artifacts)
	return report, artifacts, nil
}

func (r *Runner) collectEvidence(ctx context.Context, params evidence.Params) (evidence.Bundle, error) {
	buildInfo, err := r.collectors.BuildInfo.Collect(params.Now)
	if err != nil {
		return evidence.Bundle{}, fmt.Errorf("collect build info: %w", err)
	}
	sbom, sbomErr := r.collectors.SBOM.Generate(buildInfo, params.SBOMFormat, params.Now)
	vuln, vulnErr := r.collectors.Vuln.Resolve(ctx, params)
	binary, binaryErr := r.collectors.Binary.Inspect(params, buildInfo)
	policy, policyErr := r.collectors.Policy.Inspect(ctx, params)
	crosswalk, crosswalkErr := r.collectors.Crosswalk.Resolve(ctx, params, securityaudit.AllCheckIDs())
	return evidence.Bundle{
		BuildInfo:    buildInfo,
		SBOM:         sbom,
		SBOMErr:      sbomErr,
		Vuln:         vuln,
		VulnErr:      vulnErr,
		Binary:       binary,
		BinaryErr:    binaryErr,
		Policy:       policy,
		PolicyErr:    policyErr,
		Crosswalk:    crosswalk,
		CrosswalkErr: crosswalkErr,
	}, nil
}

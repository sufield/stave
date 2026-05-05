package apply

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	packs "github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/adapters/evaluation/shadow"
	"github.com/sufield/stave/internal/adapters/sirbridge"
	"github.com/sufield/stave/internal/adapters/telemetry"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/app/exemptlapse"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/pkg/stave/cliapi"
)

// executeEvaluation builds dependencies, runs the evaluation, and writes output.
// retErr is named so the deferred deps.Close() closure below can
// merge a close failure into the function's error result without
// shadowing it. The first return slot stays anonymous because every
// `return` in the body explicitly constructs the EvaluateResult.
func executeEvaluation(ctx context.Context, ec evalContext) (_ EvaluateResult, retErr error) {
	progress := ec.Runtime.BeginCountedProgress("apply controls against observations")
	defer progress.Done()

	// Create logic tracer if --trace flag or STAVE_TRACE env is set.
	var tracer *telemetry.LocalFileTracer
	tracePath := ec.Opts.TracePath
	if tracePath == "" && os.Getenv("STAVE_TRACE") != "" {
		tracePath = "audit_trace.json"
	}
	if tracePath != "" {
		tracer = telemetry.NewLocalFileTracer()
	}

	builder := NewBuilder(ec.Logger, ec.Opts, ec.Params, ec.IO)
	builder.NewFindingWriter = ec.NewFindingWriter
	builder.NewCtlRepo = ec.NewCtlRepo
	builder.NewStdinObsRepo = ec.NewStdinObsRepo
	builder.NewCELEvaluator = ec.NewCELEvaluator
	builder.NewChainLoader = ec.NewChainLoader
	builder.NewSLALoader = ec.NewSLALoader
	builder.ProjectConfig = ec.ProjectConfig
	builder.ProjectConfigPath = ec.ProjectConfigPath
	builder.OnObsProgress = progress.Update
	if tracer != nil {
		builder.Tracer = tracer
	}

	deps, err := builder.Build(ctx, ec.Plan)
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("build evaluation dependencies: %w", err)
	}
	// Capture deps.Close's error through retErr only when the
	// function is otherwise about to return cleanly. If a real
	// failure already populated retErr, that failure is the
	// load-bearing signal — overwriting it with a downstream
	// close error would obscure the actual root cause. Today
	// Close is a no-op and returns nil, but the merge contract
	// keeps the call site correct for any future Close
	// implementation that flushes trace files or finalizes a
	// registry.
	defer func() {
		if closeErr := deps.Close(); closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("close apply deps: %w", closeErr)
		}
	}()

	// Phase 2 cutover: route the evaluation core through pkg/stave/cliapi
	// so library and CLI share one orchestration path. The marshaler /
	// enricher / output pipeline below still come from deps so existing
	// CLI-specific concerns (sanitizer-aware enrichment, format-specific
	// marshaling, coverage posture) are preserved unchanged.
	//
	// stave.Config carries the same data deps.Config holds — exemption
	// rules, acknowledgment rules, SLA config, git metadata, project
	// config, and tracer all flow through stave's typed surface so the
	// resulting *evaluation.ComplianceReport is byte-identical to what
	// deps.Runner.PerformAssessment would have produced.
	staveCfg := buildStaveConfig(ec, deps)
	applyRes, err := cliapi.Apply(ctx, staveCfg)
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("execute evaluation: %w", err)
	}
	// Ensure the evaluation produced a usable outcome before
	// proceeding. cliapi.Apply must return a complete result on
	// success; IsIncomplete encapsulates the "all required fields
	// populated" contract on the type itself.
	// Shadow dark-launch hook. No-op unless STAVE_SHADOW_CMD is
	// set; when set, invokes the configured external solver
	// (Iter 3.1.4: typically the Python Z3 solver under
	// python/solver/) against the same FindingRequest that
	// produced the primary findings, logs a divergence summary
	// at slog.LevelDebug, and discards the secondary's output.
	// The user-visible report is unchanged regardless of shadow
	// state.
	if applyRes != nil && applyRes.ComplianceReport != nil {
		// FindingRequest carries the controls the assessor used.
		// Snapshots aren't surfaced on cliapi.ApplyResult today;
		// the secondary therefore receives an empty observation
		// grid and produces no SIR-derived findings — the
		// divergence log shows the primary's full count as
		// "missing" until cliapi exposes the loaded snapshots.
		// This is a known limitation of the dark-launch wiring,
		// not a solver bug; flagging it here so a future cliapi
		// extension closes the gap.
		shadowReq := evaluation.FindingRequest{
			Controls: applyRes.Controls,
			Now:      applyRes.ComplianceReport.Run.Now,
		}
		shadowBuilder := sir.NewBuilder(
			sir.WithRoleChainSource(sirbridge.NewAWSRoleChainSource()),
			sir.WithResourceFactGrouper(sirbridge.NewAWSS3FactGrouper()),
		)
		shadow.LogPrecomputedDivergence(ctx, ec.Logger, applyRes.ComplianceReport.Findings, shadowReq, shadowBuilder)
	}

	if applyRes.IsIncomplete() {
		return EvaluateResult{}, fmt.Errorf("execute evaluation: result is incomplete (response=%v)", applyRes)
	}
	result := *applyRes.ComplianceReport
	status := result.SecurityState

	// Export logic trace if enabled.
	if tracer != nil {
		lt := tracer.Finalize(ports.FinalizeArgs{StaveVersion: deps.Config.BuildVersion})
		if writeErr := telemetry.WriteTraceFile(lt, tracePath); writeErr != nil {
			slog.Warn("failed to write logic trace", "path", tracePath, "error", writeErr)
		}
	}

	// Owner annotation — resolve team ownership for each finding.
	if err := annotateOwners(&result, ec.Opts); err != nil {
		return EvaluateResult{}, err
	}

	// Reachability annotation — annotate findings with IAM blast radius.
	if reachErr := annotateReachability(&result, ec.Opts.ObservationsDir); reachErr != nil {
		return EvaluateResult{}, reachErr
	}

	// Skip the full output pipeline when --new-only or --new-since is
	// set. run_standard.go calls runNewOnlyOutput after this returns,
	// which writes a filtered output document. Running the full
	// pipeline here would produce a double-output stream — two JSON
	// documents on stdout — which breaks any consumer that expects
	// one document per invocation.
	if !ec.Opts.IsNewOnlyMode() {
		pipeline := &appeval.OutputPipeline{
			Marshaler: deps.Runner.ReportPublisher,
			Enricher:  deps.Runner.ContextEnricher,
			// applyRes.Controls is the workflow's loaded control set
			// from the cliapi.Apply path; deps.Runner.Controls() is
			// empty here because PerformAssessment isn't called on
			// this side of the dispatch.
			CoveragePosture: buildCoveragePosture(applyRes.Controls, ec.Logger),
			Logger:          ec.Logger,
		}
		if err := pipeline.Run(ctx, deps.Config.Output, &result); err != nil {
			return EvaluateResult{}, fmt.Errorf("run output pipeline: %w", err)
		}
	}

	evalResult := BuildEvaluateResult(status, deps.Config.PolicySource, deps.Config.ObservationSource)
	evalResult.RawFindings = result.Findings

	// Detect lapsed exemptions.
	evalResult.LapsedExemptions = exemptlapse.Detect(exemptlapse.Input{
		AcknowledgedFindings: result.AcknowledgedFindings,
		Now:                  deps.Config.Clock.Now(),
	})

	// Aggregation lives on ComplianceReport so the apply runner asks
	// the report whether any/critical breaches occurred instead of
	// reproducing the per-finding scan that used to live here.
	evalResult.HasSLABreach = result.HasAnySLABreach()
	evalResult.HasCriticalSLABreach = result.HasCriticalSLABreach()

	return evalResult, nil
}

// runStrictIntegrityCheck ensures internal pack integrity when --strict is set.
func runStrictIntegrityCheck(strict bool, stdout, stderr io.Writer) error {
	if !strict {
		return nil
	}

	rt := ui.NewRuntime(stdout, stderr)
	done := rt.BeginProgress("perform strict integrity checks")
	defer done()

	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return fmt.Errorf("load default pack registry: %w", err)
	}
	if err := reg.ValidateStrict(ctlbuiltin.EmbeddedFS()); err != nil {
		return ui.WithNextCommand(err, "stave packs list")
	}
	return nil
}

package apply

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/telemetry"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/app/exemptlapse"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/pkg/stave/cliapi"
)

// executeEvaluation builds dependencies, runs the evaluation, and writes output.
func executeEvaluation(ctx context.Context, ec evalContext) (EvaluateResult, error) {
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
	defer deps.Close()

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
	annotateReachability(&result, ec.Opts.ObservationsDir)

	// Skip the full output pipeline when --new-only or --new-since is
	// set. run_standard.go calls runNewOnlyOutput after this returns,
	// which writes a filtered output document. Running the full
	// pipeline here would produce a double-output stream — two JSON
	// documents on stdout — which breaks any consumer that expects
	// one document per invocation.
	if !ec.Opts.NewOnly && ec.Opts.NewSince == "" {
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

	// Scan findings for SLA breaches. The loop short-circuits only
	// when both HasSLABreach and HasCriticalSLABreach are set, since
	// once that pair is true no later finding can elevate either
	// flag. A bare `break` on the first breach (or first critical
	// breach) would leave HasCriticalSLABreach=false on the case
	// where the first SLA-breached finding is non-critical and a
	// later one IS critical.
	for i := range result.Findings {
		f := &result.Findings[i]
		if f.SLABreached {
			evalResult.HasSLABreach = true
		}
		if f.IsCriticalSLABreach() {
			evalResult.HasCriticalSLABreach = true
		}
		if evalResult.HasSLABreach && evalResult.HasCriticalSLABreach {
			break
		}
	}

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

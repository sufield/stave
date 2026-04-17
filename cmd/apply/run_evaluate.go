package apply

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/telemetry"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/app/exemptlapse"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
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

	result, status, err := deps.Runner.PerformAssessment(ctx, deps.Config)
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("execute evaluation: %w", err)
	}

	// Export logic trace if enabled.
	if tracer != nil {
		lt := tracer.Finalize("", deps.Config.BuildVersion, nil)
		if writeErr := telemetry.WriteTraceFile(lt, tracePath); writeErr != nil {
			slog.Warn("failed to write logic trace", "path", tracePath, "error", writeErr)
		}
	}

	// Owner annotation — resolve team ownership for each finding.
	annotateOwners(&result, ec.Opts)

	// Reachability annotation — annotate findings with IAM blast radius.
	annotateReachability(&result, ec.Opts.ObservationsDir)

	pipeline := &appeval.OutputPipeline{
		Marshaler: deps.Runner.ReportPublisher,
		Enricher:  deps.Runner.ContextEnricher,
		Logger:    ec.Logger,
	}
	if err := pipeline.Run(ctx, deps.Config.Output, &result); err != nil {
		return EvaluateResult{}, fmt.Errorf("run output pipeline: %w", err)
	}

	evalResult := BuildEvaluateResult(status, deps.Config.PolicySource, deps.Config.ObservationSource)
	evalResult.RawFindings = result.Findings

	// Detect lapsed exemptions.
	evalResult.LapsedExemptions = exemptlapse.Detect(exemptlapse.Input{
		AcknowledgedFindings: result.AcknowledgedFindings,
		Now:                  time.Now().UTC(),
	})

	// Scan findings for SLA breaches.
	for i := range result.Findings {
		f := &result.Findings[i]
		if f.SLABreached {
			evalResult.HasSLABreach = true
			if f.ControlSeverity.String() == "critical" || f.SLAEscalatedSeverity == "critical" {
				evalResult.HasCriticalSLABreach = true
				break // both flags set, no need to scan further
			}
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

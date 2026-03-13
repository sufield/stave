package diagnose

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	outtext "github.com/sufield/stave/internal/adapters/output/text"
	appdiagnose "github.com/sufield/stave/internal/app/diagnose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/trace"
)

type diagnoseOptions struct {
	ControlsDir     string
	ObservationsDir string
	PreviousOutput  string
	MaxUnsafe       string
	NowTime         string
	Format          string
	Quiet           bool
	Cases           []string
	SignalContains  string
	Template        string
	ControlID       string
	AssetID         string
}

func (o diagnoseOptions) normalizePaths(cmd *cobra.Command) (diagnoseOptions, *projctx.InferenceLog) {
	out := o
	out.ControlsDir = fsutil.CleanUserPath(out.ControlsDir)
	out.ObservationsDir = fsutil.CleanUserPath(out.ObservationsDir)
	out.PreviousOutput = fsutil.CleanUserPath(out.PreviousOutput)

	resolver, _ := projctx.NewResolver()
	engine := projctx.NewInferenceEngine(resolver)
	if !cmd.Flags().Changed("controls") {
		if inferred := engine.InferDir("controls", ""); inferred != "" {
			out.ControlsDir = inferred
		}
	}
	if !cmd.Flags().Changed("observations") {
		if inferred := engine.InferDir("observations", ""); inferred != "" {
			out.ObservationsDir = inferred
		}
	}

	return out, engine.Log
}

func (o diagnoseOptions) validateDirs(log *projctx.InferenceLog) error {
	if err := cmdutil.ValidateDirWithInference("--controls", o.ControlsDir, "controls", ui.ErrHintControlsNotAccessible, log); err != nil {
		return err
	}
	return cmdutil.ValidateDirWithInference("--observations", o.ObservationsDir, "observations", ui.ErrHintObservationsNotAccessible, log)
}

func (o diagnoseOptions) parseMaxUnsafe() (time.Duration, error) {
	return timeutil.ParseDurationFlag(o.MaxUnsafe, "--max-unsafe")
}

func (o diagnoseOptions) parseClock() (ports.Clock, error) {
	return compose.ResolveClock(o.NowTime)
}

type diagnoseExecution struct {
	cmd         *cobra.Command
	opts        diagnoseOptions
	diagnoseRun *appdiagnose.Run
	ctx         context.Context
	baseCfg     appdiagnose.Config
}

func (e diagnoseExecution) hasFindingDetailMode() bool {
	ctlID, resID := e.trimmedFindingIDs()
	return ctlID != "" || resID != ""
}

func (e diagnoseExecution) findingDetailRequest() diagnoseFindingDetailRequest {
	ctlID, resID := e.trimmedFindingIDs()
	return diagnoseFindingDetailRequest{
		cmd:         e.cmd,
		diagnoseRun: e.diagnoseRun,
		ctx:         e.ctx,
		baseCfg:     e.baseCfg,
		controlID:   ctlID,
		assetID:     resID,
		formatRaw:   e.opts.Format,
		quiet:       e.opts.Quiet,
	}
}

func (e diagnoseExecution) trimmedFindingIDs() (string, string) {
	return strings.TrimSpace(e.opts.ControlID), strings.TrimSpace(e.opts.AssetID)
}

type diagnoseFindingDetailRequest struct {
	cmd         *cobra.Command
	diagnoseRun *appdiagnose.Run
	ctx         context.Context
	baseCfg     appdiagnose.Config
	controlID   string
	assetID     string
	formatRaw   string
	quiet       bool
}

func validateFindingDetailArgs(controlID, assetID string) error {
	if controlID == "" {
		return fmt.Errorf("--control-id is required when --asset-id is set")
	}
	if assetID == "" {
		return fmt.Errorf("--asset-id is required when --control-id is set")
	}
	return nil
}

// runDiagnoseFindingDetail handles the single-finding deep-dive branch.
func runDiagnoseFindingDetail(req diagnoseFindingDetailRequest) error {
	if err := validateFindingDetailArgs(req.controlID, req.assetID); err != nil {
		return err
	}

	detail, err := req.diagnoseRun.ExecuteFindingDetail(req.ctx, appdiagnose.FindingDetailConfig{
		DiagnoseConfig: req.baseCfg,
		ControlID:      kernel.ControlID(req.controlID),
		AssetID:        asset.ID(req.assetID),
		TraceBuilder:   trace.NewFindingTraceBuilder(ctlyaml.YAMLPredicateParser),
		IDGen:          crypto.NewHasher(),
	})
	if err != nil {
		return err
	}

	format, fmtErr := compose.ResolveFormatValue(req.cmd, req.formatRaw)
	if fmtErr != nil {
		return fmtErr
	}

	out := compose.ResolveStdout(req.cmd.OutOrStdout(), req.quiet, format)
	if format.IsJSON() {
		return writeFindingDetailJSON(out, detail)
	}
	if err := outtext.WriteFindingDetail(out, detail); err != nil {
		return err
	}

	// Finding confirmed = violation exists, so exit code 3.
	return ui.ErrViolationsFound
}

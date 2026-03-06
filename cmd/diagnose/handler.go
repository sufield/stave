package diagnose

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	"github.com/sufield/stave/internal/adapters/output"
	appdiagnose "github.com/sufield/stave/internal/app/diagnose"
	supportapp "github.com/sufield/stave/internal/app/support"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/ports"
)

// RootCmd is set by the parent cmd package during init to provide
// access to the root command for tests that exercise the full command tree.
var RootCmd *cobra.Command

// GetRootCmd builds a minimal root command with diagnose subcommands attached.
// Used by package-level tests that exercise commands via root.Execute()
// without importing the parent cmd package (circular dependency).
func GetRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "stave",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.PersistentFlags().String("output", "text", "Output format")
	root.PersistentFlags().Bool("quiet", false, "Suppress output")
	root.PersistentFlags().CountP("verbose", "v", "Increase verbosity")
	root.PersistentFlags().Bool("force", false, "Allow overwrite")
	root.PersistentFlags().Bool("sanitize", false, "Sanitize identifiers")
	root.PersistentFlags().String("path-mode", "base", "Path rendering mode")
	root.PersistentFlags().String("log-file", "", "Log file path")

	root.AddCommand(DiagnoseCmd)
	root.AddCommand(ExplainCmd)

	return root
}

// runDiagnose executes the diagnose command.
func runDiagnose(cmd *cobra.Command, _ []string) error {
	execCtx, err := prepareDiagnoseExecution(cmd)
	if err != nil {
		return err
	}
	if execCtx.hasFindingDetailMode() {
		return runDiagnoseFindingDetail(execCtx.findingDetailRequest())
	}

	report, err := executeDiagnoseReport(execCtx)
	if err != nil {
		return err
	}
	return renderDiagnoseOutput(cmd, execCtx.opts, report)
}

func prepareDiagnoseExecution(cmd *cobra.Command) (diagnoseExecution, error) {
	opts := diagnoseOpts.normalizePaths(cmd)
	if err := opts.validateDirs(); err != nil {
		return diagnoseExecution{}, err
	}
	maxDuration, err := opts.parseMaxUnsafe()
	if err != nil {
		return diagnoseExecution{}, err
	}
	clock, err := opts.parseClock()
	if err != nil {
		return diagnoseExecution{}, err
	}
	diagnoseRun, err := newDiagnoseRun()
	if err != nil {
		return diagnoseExecution{}, err
	}
	return diagnoseExecution{
		cmd:         cmd,
		opts:        opts,
		diagnoseRun: diagnoseRun,
		ctx:         context.Background(),
		baseCfg:     buildDiagnoseConfig(opts, maxDuration, clock),
	}, nil
}

func executeDiagnoseReport(execCtx diagnoseExecution) (*diagnosis.Report, error) {
	report, err := supportapp.ExecuteDiagnoseReport(supportapp.DiagnoseReportRequest{
		Context: execCtx.ctx,
		Run:     execCtx.diagnoseRun,
		Config:  execCtx.baseCfg,
		Sanitize: func(r *diagnosis.Report) *diagnosis.Report {
			return output.SanitizeReport(cmdutil.GetSanitizer(execCtx.cmd), r)
		},
	})
	if err != nil {
		return nil, err
	}
	return filterDiagnosisReport(report, execCtx.opts.Cases, execCtx.opts.SignalContains), nil
}

func newDiagnoseRun() (*appdiagnose.Run, error) {
	obsLoader, err := cmdutil.NewObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	ctlLoader, err := cmdutil.NewControlRepository()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	evalLoader := evaljson.NewLoader()
	return appdiagnose.NewRun(obsLoader, ctlLoader, evalLoader, evalLoader), nil
}

func buildDiagnoseConfig(opts diagnoseOptions, maxDuration time.Duration, clock ports.Clock) appdiagnose.Config {
	cfg := appdiagnose.Config{
		ControlsDir:     opts.ControlsDir,
		ObservationsDir: opts.ObservationsDir,
		MaxUnsafe:       maxDuration,
		Clock:           clock,
		PredicateParser: ctlyaml.YAMLPredicateParser,
	}
	if opts.PreviousOutput == "-" {
		cfg.OutputReader = os.Stdin
	} else {
		cfg.OutputFile = opts.PreviousOutput
	}
	return cfg
}

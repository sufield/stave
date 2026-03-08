package validate

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// validateOpts is the mutable option set used by package-level helper tests.
var validateOpts = defaultOptions()

type options struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       string
	NowTime         string
	Format          string
	StrictMode      bool
	FixHints        bool
	QuietMode       bool
	InFile          string
	SchemaVersion   string
	Kind            string
	Template        string
}

func defaultOptions() *options {
	return &options{
		ControlsDir:     "controls/s3",
		ObservationsDir: "observations",
		MaxUnsafe:       cmdutil.ResolveMaxUnsafeDefault(),
		Format:          "text",
		QuietMode:       cmdutil.ResolveQuietDefault(),
	}
}

func (o *options) BindFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory (inferred from project root if omitted)")
	flags.StringVarP(&o.ObservationsDir, "observations", "o", o.ObservationsDir, "Path to observation snapshots directory (inferred from project root if omitted)")
	flags.StringVar(&o.MaxUnsafe, "max-unsafe", o.MaxUnsafe, cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	flags.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
	flags.StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
	flags.BoolVar(&o.StrictMode, "strict", false, "Treat warnings as errors (exit 2)")
	flags.BoolVar(&o.FixHints, "fix-hints", false, "Print command-level remediation hints after validation issues")
	flags.BoolVar(&o.QuietMode, "quiet", o.QuietMode, cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))
	flags.StringVar(&o.InFile, "in", "", "Path to single input file (use - for stdin). Detection: leading '{'/'[' => observation JSON; otherwise control YAML")
	flags.StringVar(&o.SchemaVersion, "schema-version", "", "Contract schema version for --kind mode (defaults by kind)")
	flags.StringVar(&o.Kind, "kind", "", "Contract kind for --in mode: control|observation|finding")
	flags.StringVar(&o.Template, "template", "", "Template string for custom output formatting (supports {{.Field}}, {{range}}, {{json}})")
}

func prepareValidateCommand(cmd *cobra.Command, opts *options) (ui.OutputFormat, error) {
	if err := cmdutil.EnsureContextSelectionValid(); err != nil {
		return "", err
	}

	format, err := ui.ParseOutputFormat(opts.Format)
	if err != nil {
		return "", err
	}

	if err := prepareValidatePaths(cmd, opts); err != nil {
		return "", err
	}

	_, cfgPath, _ := cmdutil.FindProjectConfigWithPath()
	gitMeta := cmdutil.CollectGitAudit(cmdutil.RootForContextName(), []string{opts.ControlsDir, cfgPath})
	if !opts.QuietMode {
		cmdutil.WarnIfGitDirty(cmd, gitMeta, "validate")
	}
	logVerboseContext(cmd, opts)

	return format, nil
}

func prepareValidatePaths(cmd *cobra.Command, opts *options) error {
	normalizeValidatePaths(cmd, opts)
	return validateValidateDirs(opts)
}

// normalizeValidatePaths cleans user-supplied paths, trims string fields,
// and applies project-root inference for controls and observations dirs.
func normalizeValidatePaths(cmd *cobra.Command, opts *options) {
	opts.ControlsDir = fsutil.CleanUserPath(opts.ControlsDir)
	opts.ObservationsDir = fsutil.CleanUserPath(opts.ObservationsDir)
	opts.InFile = fsutil.CleanUserPath(opts.InFile)
	opts.Kind = strings.TrimSpace(opts.Kind)
	opts.SchemaVersion = strings.TrimSpace(opts.SchemaVersion)
	cmdutil.ResetInferAttempts()

	opts.ControlsDir = cmdutil.InferControlsDir(cmd, opts.ControlsDir)
	opts.ObservationsDir = cmdutil.InferObservationsDir(cmd, opts.ObservationsDir)
}

// validateValidateDirs checks that controls and observations directories
// exist and are accessible. Skipped when --in is set (single file mode).
func validateValidateDirs(opts *options) error {
	if opts.InFile != "" {
		return nil
	}
	if err := validateDirWithInference("--controls", opts.ControlsDir, "controls", ui.ErrHintControlsNotAccessible); err != nil {
		return err
	}
	return validateDirWithInference("--observations", opts.ObservationsDir, "observations", ui.ErrHintObservationsNotAccessible)
}

// logVerboseContext prints context details to stderr when verbose mode is enabled.
func logVerboseContext(cmd *cobra.Command, opts *options) {
	verbosity := 0
	if cmd != nil {
		verbosity, _ = cmd.Root().PersistentFlags().GetCount("verbose")
	}
	if verbosity == 0 || opts.QuietMode || cmdutil.QuietEnabled(cmd) {
		return
	}
	sc, _ := cmdutil.ResolveSelectedGlobalContext()
	ctxName := sc.Name
	if !sc.Active || strings.TrimSpace(ctxName) == "" {
		ctxName = "none"
	}
	_, cfgPath, _ := cmdutil.FindProjectConfigWithPath()
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "context=%s project_config=%s controls=%s observations=%s\n", ctxName, cmdutil.EmptyDash(cfgPath), opts.ControlsDir, opts.ObservationsDir)
}

func validateDirWithInference(flag, path, inferKey string, hint error) error {
	if err := cmdutil.ValidateDir(flag, path, hint); err != nil {
		if detail := cmdutil.ExplainInferenceFailure(inferKey); detail != "" {
			return fmt.Errorf("%w\n%s", err, detail)
		}
		return err
	}
	return nil
}

type validateParams struct {
	maxUnsafe *time.Duration
	nowTime   time.Time
	issues    []diag.Issue
}

func parseValidateParams(opts *options) validateParams {
	var params validateParams

	maxDuration, err := timeutil.ParseDuration(opts.MaxUnsafe)
	if err != nil {
		params.issues = append(params.issues, diag.New("INVALID_MAX_UNSAFE").
			Error().
			Action("Use format like 168h, 7d, or 1d12h").
			Command("stave validate --max-unsafe 168h").
			With("value", opts.MaxUnsafe).
			WithSensitive("error", err.Error()).
			Build())
	} else {
		params.maxUnsafe = &maxDuration
	}

	if opts.NowTime != "" {
		t, parseErr := time.Parse(time.RFC3339, opts.NowTime)
		if parseErr != nil {
			params.issues = append(params.issues, diag.New("INVALID_NOW_TIME").
				Error().
				Action("Use RFC3339 format").
				Command("stave validate --now 2026-01-15T00:00:00Z").
				With("value", opts.NowTime).
				WithSensitive("error", parseErr.Error()).
				Build())
		} else {
			params.nowTime = t
		}
	}

	return params
}

func ensureValidateModeFlags(opts *options) error {
	if opts.Kind != "" {
		return fmt.Errorf("--kind requires --in <file|->")
	}
	return nil
}

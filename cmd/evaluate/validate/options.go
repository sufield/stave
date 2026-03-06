package validate

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// parsedValidateFormat holds the parsed output format for the validate command.
var parsedValidateFormat ui.OutputFormat

// validateOpts is the mutable option set used by package-level helper tests.
var validateOpts = defaultOptions()

// validateIsJSONOutput returns true if JSON output is requested via --format flag.
func validateIsJSONOutput() bool {
	return parsedValidateFormat.IsJSON()
}

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
	flags.StringVar(&o.Template, "template", "", "Go text/template string for custom output formatting")
}

func prepareValidateCommand(cmd *cobra.Command, opts *options) error {
	if err := cmdutil.EnsureContextSelectionValid(); err != nil {
		return err
	}

	format, err := ui.ParseOutputFormat(opts.Format)
	if err != nil {
		return err
	}
	parsedValidateFormat = format

	if err := prepareValidatePaths(cmd, opts); err != nil {
		return err
	}
	return nil
}

func prepareValidatePaths(cmd *cobra.Command, opts *options) error {
	opts.ControlsDir = fsutil.CleanUserPath(opts.ControlsDir)
	opts.ObservationsDir = fsutil.CleanUserPath(opts.ObservationsDir)
	opts.InFile = fsutil.CleanUserPath(opts.InFile)
	opts.Kind = strings.TrimSpace(opts.Kind)
	opts.SchemaVersion = strings.TrimSpace(opts.SchemaVersion)
	cmdutil.ResetInferAttempts()

	opts.ControlsDir = cmdutil.InferControlsDir(cmd, opts.ControlsDir)
	opts.ObservationsDir = cmdutil.InferObservationsDir(cmd, opts.ObservationsDir)

	_, cfgPath, _ := cmdutil.FindProjectConfigWithPath()
	gitMeta := cmdutil.CollectGitAudit(cmdutil.RootForContextName(), []string{opts.ControlsDir, cfgPath})
	warnIfGitDirty(opts, gitMeta, "validate")

	verbosity := 0
	if cmd != nil {
		verbosity, _ = cmd.Root().PersistentFlags().GetCount("verbose")
	}
	if verbosity > 0 && !opts.QuietMode && !cmdutil.QuietEnabled(cmd) {
		sc, _ := cmdutil.ResolveSelectedGlobalContext()
		ctxName := sc.Name
		if !sc.Active || strings.TrimSpace(ctxName) == "" {
			ctxName = "none"
		}
		_, cfgPath, _ := cmdutil.FindProjectConfigWithPath()
		_, _ = fmt.Fprintf(os.Stderr, "context=%s project_config=%s controls=%s observations=%s\n", ctxName, cmdutil.EmptyDash(cfgPath), opts.ControlsDir, opts.ObservationsDir)
	}

	if opts.InFile == "" {
		if err := validateDirExists("--controls", opts.ControlsDir, "controls", ui.ErrHintControlsNotAccessible); err != nil {
			return err
		}
		if err := validateDirExists("--observations", opts.ObservationsDir, "observations", ui.ErrHintObservationsNotAccessible); err != nil {
			return err
		}
	}

	return nil
}

func validateDirExists(flag, path, inferKey string, hint error) error {
	fi, err := os.Stat(path)
	if err != nil {
		baseErr := ui.DirectoryAccessError(flag, path, err, hint)
		if detail := cmdutil.ExplainInferenceFailure(inferKey); detail != "" {
			return fmt.Errorf("%w\n%s", baseErr, detail)
		}
		return baseErr
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s must be a directory: %s", flag, path)
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

// warnIfGitDirty prints a warning if git is dirty and quiet mode is not enabled.
func warnIfGitDirty(opts *options, git *evaluation.GitInfo, label string) {
	if git == nil || !git.Dirty {
		return
	}
	if opts.QuietMode {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "WARN: Uncommitted changes detected in %s inputs (%s). This run may not reflect committed state.\n", label, strings.Join(git.DirtyList, ", "))
}

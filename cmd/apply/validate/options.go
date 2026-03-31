package validate

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// resolveConfigDefaults fills flag values from project config when the user
// did not set them explicitly on the command line.
func (o *options) resolveConfigDefaults(cmd *cobra.Command) {
	eval := cmdctx.EvaluatorFromCmd(cmd)
	if !cmd.Flags().Changed("max-unsafe") {
		o.MaxUnsafeDuration = eval.MaxUnsafeDuration()
	}
}

type options struct {
	// Paths
	Controls     string
	Observations string
	InputPath    string // --in

	// Configuration
	MaxUnsafeDuration string
	NowTime           string
	Strict            bool

	// Metadata Overrides
	Kind          string
	SchemaVersion string

	// Output/UI
	Format   string
	Template string
	FixHints bool
}

func (o *options) hintCtx() hintContext {
	return hintContext{ControlsDir: o.Controls, ObservationsDir: o.Observations}
}

// newOptions initializes defaults with zero values for config-derived fields.
// Call resolveConfigDefaults after flag parsing to fill in project-config defaults.
func newOptions() *options {
	return &options{
		Controls:     "controls",
		Observations: "observations",
		Format:       "text",
	}
}

func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.Controls, "controls", "i", o.Controls, "Path to control definitions (inferred if omitted)")
	f.StringVarP(&o.Observations, "observations", "o", o.Observations, "Path to observation snapshots (inferred if omitted)")
	f.StringVar(&o.MaxUnsafeDuration, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339) for deterministic output")
	f.StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
	f.BoolVar(&o.Strict, "strict", false, "Treat warnings as errors (exit 2)")
	f.BoolVar(&o.FixHints, "fix-hints", false, "Print remediation hints after issues")
	f.StringVar(&o.InputPath, "in", "", "Single input file or '-' for stdin")
	f.StringVar(&o.SchemaVersion, "schema-version", "", "Contract schema version override")
	f.StringVar(&o.Kind, "kind", "", "Contract kind: control|observation|finding")
	f.StringVar(&o.Template, "template", "", "Custom output template")
}

// Prepare resolves config defaults, normalizes paths, and validates flag
// combinations. This is the single "option lifecycle" entry point called
// from PreRunE.
func (o *options) Prepare(cmd *cobra.Command) error {
	o.resolveConfigDefaults(cmd)
	return o.normalizeAndValidate(
		cmd.Flags().Changed("controls"),
		cmd.Flags().Changed("observations"),
	)
}

// normalizeAndValidate cleans user input, applies project-root inference,
// and validates flag combinations.
func (o *options) normalizeAndValidate(controlsChanged, obsChanged bool) error {
	o.InputPath = fsutil.CleanUserPath(o.InputPath)
	o.Kind = strings.TrimSpace(o.Kind)
	o.SchemaVersion = strings.TrimSpace(o.SchemaVersion)

	if o.Kind != "" && o.InputPath == "" {
		return &ui.UserError{Err: fmt.Errorf("flag --kind requires --in <file>")}
	}

	singleFileMode := o.InputPath != ""

	ec, err := compose.PrepareEvaluationContext(compose.EvalContextRequest{
		ControlsDir:                o.Controls,
		ObservationsDir:            o.Observations,
		ControlsChanged:            controlsChanged,
		ObsChanged:                 obsChanged,
		SkipPathInference:          singleFileMode,
		SkipControlsValidation:     singleFileMode,
		SkipObservationsValidation: singleFileMode,
		SkipMaxUnsafe:              true,
		SkipClock:                  true,
		SkipFormat:                 true,
	})
	if err != nil {
		return err
	}
	o.Controls = ec.ControlsDir
	o.Observations = ec.ObservationsDir

	// Validate context resolution (fail-fast if context state is broken).
	if ec.Resolver != nil {
		if _, resolveErr := ec.Resolver.ResolveSelected(); resolveErr != nil {
			return resolveErr
		}
	}

	return nil
}

// auditGitStatus checks for uncommitted changes in control/config files
// and emits a warning to stderr if the working tree is dirty.
func (o *options) auditGitStatus(cmd *cobra.Command) error {
	gf := cliflags.GetGlobalFlags(cmd)
	resolver, err := projctx.NewResolver()
	if err != nil {
		return fmt.Errorf("resolve project context: %w", err)
	}

	_, cfgPath, cfgErr := projconfig.FindProjectConfigWithPath("")
	if cfgErr != nil {
		return fmt.Errorf("load project config: %w", cfgErr)
	}

	root := resolver.ProjectRoot()
	gitMeta := compose.AuditGitStatus(root, []string{o.Controls, cfgPath})
	compose.WarnGitDirty(cmd.ErrOrStderr(), gitMeta, "validate", gf.Quiet)
	return nil
}

// logEnvironment emits debug-level context information for troubleshooting.
func (o *options) logEnvironment() {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return
	}
	_, cfgPath, _ := projconfig.FindProjectConfigWithPath("")

	ctxName := "none"
	if sc, scErr := resolver.ResolveSelected(); scErr == nil && sc.Active && strings.TrimSpace(sc.Name) != "" {
		ctxName = sc.Name
	}
	slog.Debug("validate environment",
		"context", ctxName,
		"config", compose.EmptyDash(cfgPath),
		"controls", o.Controls,
		"observations", o.Observations)
}

// validateParams holds the fully parsed domain types.
type validateParams struct {
	maxUnsafe *time.Duration
	nowTime   time.Time
	issues    []diag.Issue
}

// parseParams converts raw strings from options into structured domain values.
func (o *options) parseParams() validateParams {
	var p validateParams

	dur, err := kernel.ParseDuration(o.MaxUnsafeDuration)
	if err != nil {
		p.issues = append(p.issues, diag.New(diag.CodeInvalidMaxUnsafe).
			Error().
			Action("Use format like 168h, 7d, or 1d12h").
			Command("stave validate --max-unsafe 168h").
			With("value", o.MaxUnsafeDuration).
			WithSensitive("error", err.Error()).
			Build())
	} else {
		p.maxUnsafe = &dur
	}

	if o.NowTime != "" {
		t, parseErr := cliflags.ParseRFC3339(o.NowTime, "--now")
		if parseErr != nil {
			p.issues = append(p.issues, diag.New(diag.CodeInvalidNowTime).
				Error().
				Action("Use RFC3339 format").
				Command("stave validate --now 2026-01-15T00:00:00Z").
				With("value", o.NowTime).
				WithSensitive("error", parseErr.Error()).
				Build())
		} else {
			p.nowTime = t
		}
	}

	return p
}

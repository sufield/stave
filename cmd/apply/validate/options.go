package validate

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/dircheck"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/diag"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
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
	f.StringVar(&o.MaxUnsafeDuration, "max-unsafe", "", cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
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
	if err := o.normalize(
		cmd.Flags().Changed("controls"),
		cmd.Flags().Changed("observations"),
	); err != nil {
		return err
	}
	return o.validate()
}

// normalize cleans user input and applies project-root inference.
// controlsChanged/obsChanged indicate whether the user explicitly set those flags.
func (o *options) normalize(controlsChanged, obsChanged bool) error {
	o.Controls = fsutil.CleanUserPath(o.Controls)
	o.Observations = fsutil.CleanUserPath(o.Observations)
	o.InputPath = fsutil.CleanUserPath(o.InputPath)
	o.Kind = strings.TrimSpace(o.Kind)
	o.SchemaVersion = strings.TrimSpace(o.SchemaVersion)

	// Apply inference if we are not in single-file mode
	if o.InputPath == "" {
		resolver, err := projctx.NewResolver()
		if err != nil {
			return fmt.Errorf("resolve project context: %w", err)
		}
		engine := projctx.NewInferenceEngine(resolver)
		if !controlsChanged {
			if inferred := engine.InferDir("controls", ""); inferred != "" {
				o.Controls = inferred
			}
		}
		if !obsChanged {
			if inferred := engine.InferDir("observations", ""); inferred != "" {
				o.Observations = inferred
			}
		}
	}
	return nil
}

// validate performs logical checks on flag combinations.
func (o *options) validate() error {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return err
	}
	if _, err = resolver.ResolveSelected(); err != nil {
		return err
	}

	if o.Kind != "" && o.InputPath == "" {
		return fmt.Errorf("flag --kind requires --in <file>")
	}

	// Ensure directories exist if in project mode
	if o.InputPath == "" {
		if err := dircheck.ValidateFlagDir("--controls", o.Controls, "", ui.ErrHintControlsNotAccessible, nil); err != nil {
			return err
		}
		if err := dircheck.ValidateFlagDir("--observations", o.Observations, "", ui.ErrHintObservationsNotAccessible, nil); err != nil {
			return err
		}
	}

	return nil
}

// prepareAndLogEnvironment handles Git audits and verbose context logging.
func (o *options) prepareAndLogEnvironment(cmd *cobra.Command) error {
	gf := cmdutil.GetGlobalFlags(cmd)
	resolver, resolverErr := projctx.NewResolver()
	if resolverErr != nil {
		return fmt.Errorf("resolve project context: %w", resolverErr)
	}

	_, cfgPath, err := projconfig.FindProjectConfigWithPath("")
	if err != nil {
		return fmt.Errorf("load project config: %w", err)
	}
	root := resolver.ProjectRoot()
	gitMeta := compose.AuditGitStatus(root, []string{o.Controls, cfgPath})
	compose.WarnGitDirty(cmd.ErrOrStderr(), gitMeta, "validate", gf.Quiet)

	ctxName := "none"
	if resolver != nil {
		if sc, err := resolver.ResolveSelected(); err == nil && sc.Active && strings.TrimSpace(sc.Name) != "" {
			ctxName = sc.Name
		}
	}
	slog.Debug("validate environment",
		"context", ctxName,
		"config", compose.EmptyDash(cfgPath),
		"controls", o.Controls,
		"observations", o.Observations)
	return nil
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
		t, parseErr := cmdutil.ParseRFC3339(o.NowTime, "--now")
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

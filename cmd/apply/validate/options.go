package validate

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/diag"
)

type options struct {
	// Paths
	Controls     string
	Observations string
	InputPath    string // --in

	// Configuration
	MaxUnsafe string
	NowTime   string
	Strict    bool

	// Metadata Overrides
	Kind          string
	SchemaVersion string

	// Output/UI
	Format   string
	Template string
	FixHints bool
	Quiet    bool
}

// newOptions initializes defaults from project configuration.
func newOptions() *options {
	return &options{
		Controls:     "controls/s3",
		Observations: "observations",
		MaxUnsafe:    projconfig.Global().MaxUnsafe(),
		Format:       "text",
		Quiet:        projconfig.Global().Quiet(),
	}
}

func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.Controls, "controls", "i", o.Controls, "Path to control definitions (inferred if omitted)")
	f.StringVarP(&o.Observations, "observations", "o", o.Observations, "Path to observation snapshots (inferred if omitted)")
	f.StringVar(&o.MaxUnsafe, "max-unsafe", o.MaxUnsafe, cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339) for deterministic output")
	f.StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
	f.BoolVar(&o.Strict, "strict", false, "Treat warnings as errors (exit 2)")
	f.BoolVar(&o.FixHints, "fix-hints", false, "Print remediation hints after issues")
	f.BoolVar(&o.Quiet, "quiet", o.Quiet, cmdutil.WithDynamicDefaultHelp("Suppress output"))
	f.StringVar(&o.InputPath, "in", "", "Single input file or '-' for stdin")
	f.StringVar(&o.SchemaVersion, "schema-version", "", "Contract schema version override")
	f.StringVar(&o.Kind, "kind", "", "Contract kind: control|observation|finding")
	f.StringVar(&o.Template, "template", "", "Custom output template")
}

// normalize cleans user input and applies project-root inference.
func (o *options) normalize(cmd *cobra.Command) error {
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
		if !cmd.Flags().Changed("controls") {
			if inferred := engine.InferDir("controls", ""); inferred != "" {
				o.Controls = inferred
			}
		}
		if !cmd.Flags().Changed("observations") {
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
		if err := cmdutil.ValidateFlagDir("--controls", o.Controls, "", ui.ErrHintControlsNotAccessible, nil); err != nil {
			return err
		}
		if err := cmdutil.ValidateFlagDir("--observations", o.Observations, "", ui.ErrHintObservationsNotAccessible, nil); err != nil {
			return err
		}
	}

	return nil
}

// prepareEnvironment handles Git audits and verbose context logging.
func (o *options) prepareEnvironment(cmd *cobra.Command) error {
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
	compose.WarnGitDirty(cmd.ErrOrStderr(), gitMeta, "validate", o.Quiet || gf.Quiet)

	verbosity := 0
	if cmd != nil {
		verbosity, _ = cmd.Root().PersistentFlags().GetCount("verbose")
	}
	if verbosity > 0 && !o.Quiet && !gf.Quiet {
		ctxName := "none"
		if resolver != nil {
			if sc, err := resolver.ResolveSelected(); err == nil && sc.Active && strings.TrimSpace(sc.Name) != "" {
				ctxName = sc.Name
			}
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "context=%s config=%s controls=%s observations=%s\n",
			ctxName, compose.EmptyDash(cfgPath), o.Controls, o.Observations)
	}
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

	dur, err := timeutil.ParseDuration(o.MaxUnsafe)
	if err != nil {
		p.issues = append(p.issues, diag.New(diag.CodeInvalidMaxUnsafe).
			Error().
			Action("Use format like 168h, 7d, or 1d12h").
			Command("stave validate --max-unsafe 168h").
			With("value", o.MaxUnsafe).
			WithSensitive("error", err.Error()).
			Build())
	} else {
		p.maxUnsafe = &dur
	}

	if o.NowTime != "" {
		t, parseErr := timeutil.ParseRFC3339(o.NowTime, "--now")
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

package validate

import (
	"errors"
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
	appvalidation "github.com/sufield/stave/internal/app/validation"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// resolveConfigDefaults fills flag values from project config when the user
// did not set them explicitly on the command line.
func (o *options) resolveConfigDefaults(cmd *cobra.Command) {
	eval := cmdctx.ResolverFromCmd(cmd)
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

	// Staleness
	AssertRecent string

	// useBuiltinControls is set when --controls is absent and no controls
	// directory exists: validate against the embedded catalog.
	useBuiltinControls bool
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
	f.StringVar(&o.AssertRecent, "assert-recent", "", "Fail if no snapshot newer than this duration (e.g. 48h)")
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

// BuildRequest constructs the appropriate ContentValidator request
// for these options. When Kind is unset the input is auto-detected;
// when set it must normalise to a recognised schemas.Kind alias.
// Replaces the package-level buildValidationRequest function so the
// Kind/SchemaVersion/Strict triple lives on the type that owns the
// fields, and runValidateSingleFile drops the inline branching.
func (o *options) BuildRequest(data []byte) (appvalidation.ContentValidator, error) {
	if o.Kind == "" {
		return appvalidation.AutoRequest{Data: data}, nil
	}
	normalizedKind, err := normalizeKind(o.Kind)
	if err != nil {
		return nil, err
	}
	return appvalidation.ExplicitRequest{
		Data:          data,
		Kind:          normalizedKind,
		SchemaVersion: o.SchemaVersion,
		Strict:        o.Strict,
	}, nil
}

// normalizeAndValidate cleans user input, applies project-root inference,
// and validates flag combinations.
func (o *options) normalizeAndValidate(controlsChanged, obsChanged bool) error {
	o.InputPath = fsutil.CleanUserPath(o.InputPath)
	o.Kind = strings.TrimSpace(o.Kind)
	o.SchemaVersion = strings.TrimSpace(o.SchemaVersion)

	if o.Kind != "" && o.InputPath == "" {
		return &ui.UserError{Err: errors.New("flag --kind requires --in <file>")}
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
		AllowBuiltinFallback:       !singleFileMode,
	})
	if err != nil {
		return fmt.Errorf("prepare evaluation context: %w", err)
	}
	o.Controls = ec.ControlsDir
	o.Observations = ec.ObservationsDir
	o.useBuiltinControls = ec.UseBuiltinControls

	// Validate context resolution (fail-fast if context state is broken).
	if ec.Resolver != nil {
		if _, resolveErr := ec.Resolver.ResolveSelected(); resolveErr != nil {
			return fmt.Errorf("resolve project context: %w", resolveErr)
		}
	}

	return nil
}

// logEnvironment emits debug-level context information for troubleshooting.
func (o *options) logEnvironment() {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return
	}
	_, cfgPath, cfgErr := projconfig.FindProjectConfigWithPath("")
	if cfgErr != nil {
		slog.Debug("unexpected error finding project config", "error", cfgErr)
	}

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
	issues    []diag.Finding
}

// parseParams converts raw strings from options into structured domain values.
func (o *options) parseParams() validateParams {
	var p validateParams

	dur, issue := compose.ResolveDurationDiag(o.MaxUnsafeDuration)
	if issue != nil {
		p.issues = append(p.issues, *issue)
	} else {
		p.maxUnsafe = dur
	}

	if o.NowTime != "" {
		t, issue := compose.ResolveNowDiag(o.NowTime)
		if issue != nil {
			p.issues = append(p.issues, *issue)
		} else {
			p.nowTime = t
		}
	}

	return p
}

package validate

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// Input is the per-run payload for the validate command. All cobra-owned
// values (io, format, global flags) are resolved at the RunE boundary so
// runValidate and its helpers stay off the cobra import graph and the
// command imports only pkg/stave, cmd/cmdutil, and the exempt CLI helpers.
type Input struct {
	Stdin    io.Reader
	Out      io.Writer // already quiet/format-resolved via compose.ResolveStdout
	Stderr   io.Writer
	Format   string
	Quiet    bool
	Sanitize bool
	Rt       *ui.Runtime
	Opts     *options
}

// runValidate is the primary entry point invoked from RunE.
func runValidate(ctx context.Context, in Input) error {
	in.Opts.logEnvironment()
	in.Rt.Quiet = in.Quiet

	if in.Opts.InputPath != "" {
		return runValidateSingleFile(in)
	}
	return runValidateProject(ctx, in)
}

// runValidateProject validates the controls/observations project through the
// pkg/stave facade and applies the result (output, staleness, exit, hint).
func runValidateProject(ctx context.Context, in Input) error {
	enabledPacks, packLoadErr := discoverEnabledPacks()

	done := in.Rt.BeginProgress("validate artifacts")
	res, err := stave.ValidateProject(ctx, stave.ValidateProjectRequest{
		ControlsDir:     in.Opts.Controls,
		ObservationsDir: in.Opts.Observations,
		MaxUnsafe:       in.Opts.MaxUnsafeDuration,
		Now:             in.Opts.NowTime,
		Sanitize:        in.Sanitize,
		Strict:          in.Opts.Strict,
		FixHints:        in.Opts.FixHints,
		Format:          in.Format,
		Template:        in.Opts.Template,
		AssertRecent:    in.Opts.AssertRecent,
	}, enabledPacks, packLoadErr, ui.SeverityLabel, ui.ExecuteTemplate)
	done()

	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
	}

	if _, werr := in.Out.Write(res.Output); werr != nil {
		return fmt.Errorf("write validation output: %w", werr)
	}

	// Staleness (--assert-recent) trips after the report prints, mapping to
	// exit 2 via UserError — matching the command's pre-facade behavior.
	if res.StaleMessage != "" {
		return &ui.UserError{Err: errors.New(res.StaleMessage)}
	}

	if res.ExitErr == nil && !in.Quiet {
		ui.WriteHint(in.Stderr, fmt.Sprintf(
			"stave apply --controls %s --observations %s",
			in.Opts.Controls, in.Opts.Observations,
		))
	}
	return res.ExitErr
}

// runValidateSingleFile validates a single input document (the --in path).
func runValidateSingleFile(in Input) error {
	data, source, err := ui.ReadInput(in.Stdin, in.Opts.InputPath)
	if err != nil {
		return fmt.Errorf("read input %q: %w", source, err)
	}

	kind := ""
	if in.Opts.Kind != "" {
		canonical, kerr := normalizeKind(in.Opts.Kind)
		if kerr != nil {
			return kerr
		}
		kind = canonical
	}

	res, err := stave.ValidateContent(
		data, kind, in.Opts.SchemaVersion, in.Opts.Strict,
		in.Format, in.Opts.Template, in.Opts.FixHints,
		in.Opts.Controls, in.Opts.Observations,
		ui.SeverityLabel, ui.ExecuteTemplate,
	)
	if err != nil {
		return fmt.Errorf("validation failed for %q: %w", source, err)
	}

	if _, werr := in.Out.Write(res.Output); werr != nil {
		return fmt.Errorf("write validation output: %w", werr)
	}
	return res.ExitErr //nolint:wrapcheck // facade exit-code sentinel; preserve mapping.
}

// discoverEnabledPacks reads the project's enabled control packs from
// stave.yaml (a command-layer concern). It returns the pack names and, when
// the config could not be read, the load error string — both passed to the
// validate facade which turns them into pack diagnostics.
func discoverEnabledPacks() ([]string, string) {
	cfg, ok, err := projconfig.FindProjectConfig()
	if err != nil {
		return nil, err.Error()
	}
	if !ok {
		return nil, ""
	}
	return cfg.EnabledControlPacks, ""
}

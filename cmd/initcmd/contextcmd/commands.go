// Package contextcmd implements the stave config context subcommands for
// creating, listing, selecting, showing, and deleting named project contexts.
package contextcmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	contexts "github.com/sufield/stave/internal/config"
	"github.com/sufield/stave/internal/platform/metadata"
)

// NewContextCmd constructs the context command group with its subcommands.
func NewContextCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "context",
		Short: "Named project context commands",
		Long: `Context manages named project pointers. Context only affects default path
resolution and never changes evaluation semantics.` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(newContextListCmd())
	cmd.AddCommand(newContextCreateCmd())
	cmd.AddCommand(newContextUseCmd())
	cmd.AddCommand(newContextShowCmd())
	cmd.AddCommand(newContextDeleteCmd())

	return cmd
}

func newContextListCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available contexts",
		Long: `List all named contexts stored in the user configuration.

Exit Codes:
  0    Success
  2    Input error
  4    Internal error`,
		Example: `  stave config context list
  stave config context list --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, err := compose.ResolveFormatValue(format)
			if err != nil {
				return fmt.Errorf("resolve output format: %w", err)
			}
			return runContextList(ListInput{Stdout: cmd.OutOrStdout(), Format: resolved})
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	return cmd
}

func newContextCreateCmd() *cobra.Command {
	var dir, configFile, controls, observations string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create or update a named context",
		Long: `Create a named context that stores default paths for a project.
Contexts are saved in the user configuration and selected with
'config context use'. They affect default path resolution only —
evaluation semantics are never changed.

Exit Codes:
  0    Context created or updated
  2    Input error (invalid directory or name)
  4    Internal error`,
		Example: `  stave config context create myproject --dir /path/to/project
  stave config context create myproject --dir . --controls controls/s3`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContextCreate(CreateInput{
				Stdout:          cmd.OutOrStdout(),
				Name:            args[0],
				Dir:             dir,
				ConfigFile:      configFile,
				ControlsDir:     controls,
				ObservationsDir: observations,
			})
		},
	}
	cmd.Flags().StringVarP(&dir, "dir", "d", ".", "Project root directory for this context")
	cmd.Flags().StringVar(&configFile, "config", "stave.yaml", "Project config path (absolute or relative to --dir)")
	cmd.Flags().StringVar(&controls, "controls", "", "Default controls directory for this context")
	cmd.Flags().StringVar(&observations, "observations", "", "Default observations directory for this context")
	return cmd
}

func newContextUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Set active context",
		Long: `Set the active context. Subsequent commands use this context's default
paths unless overridden by flags. Override with STAVE_CONTEXT env var.

Exit Codes:
  0    Context activated
  2    Input error (unknown context name)
  4    Internal error`,
		Example:       `  stave config context use myproject`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContextUse(UseInput{Stdout: cmd.OutOrStdout(), Name: args[0]})
		},
	}
}

func newContextShowCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show selected context",
		Long: `Show the currently active context and its configured paths.
Reports how the context was selected (active vs STAVE_CONTEXT env var).

Exit Codes:
  0    Success
  2    No context selected
  4    Internal error`,
		Example: `  stave config context show
  stave config context show --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, err := compose.ResolveFormatValue(format)
			if err != nil {
				return fmt.Errorf("resolve output format: %w", err)
			}
			return runContextShow(ShowInput{Stdout: cmd.OutOrStdout(), Format: resolved})
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	return cmd
}

func newContextDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a context",
		Long: `Delete a named context from the user configuration. If the deleted
context was active, no context will be selected until you run
'config context use' again.

Exit Codes:
  0    Context deleted
  2    Input error (unknown context name)
  4    Internal error`,
		Example:       `  stave config context delete myproject`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContextDelete(DeleteInput{Stdout: cmd.OutOrStdout(), Name: args[0]})
		},
	}
}

// --- Per-command Input structs ---

// ListInput is the payload for runContextList, assembled in RunE.
type ListInput struct {
	Stdout io.Writer
	Format appcontracts.OutputFormat
}

// CreateInput is the payload for runContextCreate, assembled in RunE.
type CreateInput struct {
	Stdout          io.Writer
	Name            string
	Dir             string
	ConfigFile      string
	ControlsDir     string
	ObservationsDir string
}

// UseInput is the payload for runContextUse, assembled in RunE.
type UseInput struct {
	Stdout io.Writer
	Name   string
}

// ShowInput is the payload for runContextShow, assembled in RunE.
type ShowInput struct {
	Stdout io.Writer
	Format appcontracts.OutputFormat
}

// DeleteInput is the payload for runContextDelete, assembled in RunE.
type DeleteInput struct {
	Stdout io.Writer
	Name   string
}

// --- Bridge Functions (no cobra) ---

func runContextList(in ListInput) error {
	st, _, err := contexts.Load()
	if err != nil {
		return fmt.Errorf("load context store: %w", err)
	}
	runner := &Runner{Stdout: in.Stdout}
	return runner.List(st, in.Format)
}

func runContextCreate(in CreateInput) error {
	rootAbs, err := filepath.Abs(strings.TrimSpace(in.Dir))
	if err != nil {
		return fmt.Errorf("resolve --dir: %w", err)
	}
	fi, statErr := os.Stat(rootAbs)
	if statErr != nil || !fi.IsDir() {
		return &ui.UserError{Err: fmt.Errorf("--dir must point to an existing directory: %s", rootAbs)}
	}

	st, _, err := contexts.Load()
	if err != nil {
		return fmt.Errorf("load context store: %w", err)
	}

	c := contexts.Context{ProjectRoot: rootAbs}
	c.ProjectConfig = strings.TrimSpace(in.ConfigFile)
	c.Defaults.ControlsDir = strings.TrimSpace(in.ControlsDir)
	c.Defaults.ObservationsDir = strings.TrimSpace(in.ObservationsDir)

	runner := &Runner{Stdout: in.Stdout}
	return runner.Create(st, in.Name, c)
}

func runContextUse(in UseInput) error {
	st, _, err := contexts.Load()
	if err != nil {
		return fmt.Errorf("load context store: %w", err)
	}
	runner := &Runner{Stdout: in.Stdout}
	return runner.Use(st, in.Name)
}

func runContextShow(in ShowInput) error {
	st, path, err := contexts.Load()
	if err != nil {
		return fmt.Errorf("load context store: %w", err)
	}
	name, ctx, ok, resolveErr := st.ResolveSelected()
	if resolveErr != nil {
		return fmt.Errorf("resolve selected context: %w", resolveErr)
	}
	if !ok || ctx == nil {
		return &ui.UserError{Err: errors.New("no context selected; use `stave context create <name> --dir <path>` then `stave context use <name>`")}
	}

	selectedBy := "active"
	if strings.TrimSpace(os.Getenv("STAVE_CONTEXT")) != "" {
		selectedBy = "env:STAVE_CONTEXT"
	}

	runner := &Runner{Stdout: in.Stdout}
	return runner.Show(in.Format, ShowResult{
		StoreFile:     path,
		SelectedBy:    selectedBy,
		Name:          name,
		ProjectRoot:   ctx.CanonicalProjectRoot(),
		ProjectConfig: ctx.CanonicalProjectConfig(),
		ControlsDir:   ctx.EffectiveControlsDir(),
		ObserveDir:    ctx.EffectiveObservationsDir(),
	})
}

func runContextDelete(in DeleteInput) error {
	st, _, err := contexts.Load()
	if err != nil {
		return fmt.Errorf("load context store: %w", err)
	}
	runner := &Runner{Stdout: in.Stdout}
	return runner.Delete(st, in.Name)
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

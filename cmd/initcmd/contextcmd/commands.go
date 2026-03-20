package contextcmd

import (
	"fmt"

	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	contexts "github.com/sufield/stave/internal/config"
	"github.com/sufield/stave/internal/metadata"
)

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
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runContextList(cmd, format)
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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContextCreate(cmd, args, dir, configFile, controls, observations)
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
		Args:  cobra.ExactArgs(1),
		RunE:  runContextUse,
	}
}

func newContextShowCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show selected context",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runContextShow(cmd, format)
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	return cmd
}

func newContextDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a context",
		Args:  cobra.ExactArgs(1),
		RunE:  runContextDelete,
	}
}

// --- Bridge Functions ---

func runContextList(cmd *cobra.Command, rawFormat string) error {
	st, _, err := contexts.Load()
	if err != nil {
		return err
	}
	format, fmtErr := compose.ResolveFormatValue(cmd, rawFormat)
	if fmtErr != nil {
		return fmtErr
	}
	runner := &Runner{Stdout: cmd.OutOrStdout()}
	return runner.List(cmd.Context(), st, format)
}

func runContextCreate(cmd *cobra.Command, args []string, dir, configFile, controls, observations string) error {
	rootAbs, err := filepath.Abs(strings.TrimSpace(dir))
	if err != nil {
		return fmt.Errorf("resolve --dir: %w", err)
	}
	fi, statErr := os.Stat(rootAbs)
	if statErr != nil || !fi.IsDir() {
		return &ui.UserError{Err: fmt.Errorf("--dir must point to an existing directory: %s", rootAbs)}
	}

	st, _, err := contexts.Load()
	if err != nil {
		return err
	}

	c := contexts.Context{ProjectRoot: rootAbs}
	c.ProjectConfig = strings.TrimSpace(configFile)
	c.Defaults.ControlsDir = strings.TrimSpace(controls)
	c.Defaults.ObservationsDir = strings.TrimSpace(observations)

	runner := &Runner{Stdout: cmd.OutOrStdout()}
	return runner.Create(cmd.Context(), st, args[0], c)
}

func runContextUse(cmd *cobra.Command, args []string) error {
	st, _, err := contexts.Load()
	if err != nil {
		return err
	}
	runner := &Runner{Stdout: cmd.OutOrStdout()}
	return runner.Use(cmd.Context(), st, args[0])
}

func runContextShow(cmd *cobra.Command, rawFormat string) error {
	st, path, err := contexts.Load()
	if err != nil {
		return err
	}
	name, ctx, ok, resolveErr := st.ResolveSelected()
	if resolveErr != nil {
		return resolveErr
	}
	if !ok || ctx == nil {
		return &ui.UserError{Err: fmt.Errorf("no context selected; use `stave context create <name> --dir <path>` then `stave context use <name>`")}
	}

	selectedBy := "active"
	if strings.TrimSpace(os.Getenv("STAVE_CONTEXT")) != "" {
		selectedBy = "env:STAVE_CONTEXT"
	}

	format, fmtErr := compose.ResolveFormatValue(cmd, rawFormat)
	if fmtErr != nil {
		return fmtErr
	}

	runner := &Runner{Stdout: cmd.OutOrStdout()}
	return runner.Show(cmd.Context(), format, ShowResult{
		StoreFile:     path,
		SelectedBy:    selectedBy,
		Name:          name,
		ProjectRoot:   strings.TrimSpace(ctx.ProjectRoot),
		ProjectConfig: strings.TrimSpace(ctx.ProjectConfig),
		ControlsDir:   strings.TrimSpace(ctx.Defaults.ControlsDir),
		ObserveDir:    strings.TrimSpace(ctx.Defaults.ObservationsDir),
	})
}

func runContextDelete(cmd *cobra.Command, args []string) error {
	st, _, err := contexts.Load()
	if err != nil {
		return err
	}
	runner := &Runner{Stdout: cmd.OutOrStdout()}
	return runner.Delete(cmd.Context(), st, args[0])
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

package contextcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	contexts "github.com/sufield/stave/internal/config"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// --- Domain Models ---

// ListItem represents a single context entry for list output.
type ListItem struct {
	Name          string `json:"name"`
	ProjectRoot   string `json:"project_root"`
	ProjectConfig string `json:"project_config,omitempty"`
	ControlsDir   string `json:"controls_dir,omitempty"`
	ObserveDir    string `json:"observations_dir,omitempty"`
	Active        bool   `json:"active"`
}

// ShowResult represents the resolved active context for show output.
type ShowResult struct {
	StoreFile     string `json:"store_file"`
	SelectedBy    string `json:"selected_by"`
	Name          string `json:"name"`
	ProjectRoot   string `json:"project_root"`
	ProjectConfig string `json:"project_config,omitempty"`
	ControlsDir   string `json:"controls_dir,omitempty"`
	ObserveDir    string `json:"observations_dir,omitempty"`
}

// --- Runner ---

// Runner orchestrates the management of named project contexts.
type Runner struct {
	Stdout io.Writer
	Stderr io.Writer
}

// List retrieves all contexts from the store and renders them.
func (r *Runner) List(_ context.Context, st *contexts.Store, format ui.OutputFormat) error {
	names := st.Names()
	active := strings.TrimSpace(st.Active)

	items := make([]ListItem, 0, len(names))
	for _, name := range names {
		c := st.Contexts[name]
		items = append(items, ListItem{
			Name:          name,
			ProjectRoot:   strings.TrimSpace(c.ProjectRoot),
			ProjectConfig: strings.TrimSpace(c.ProjectConfig),
			ControlsDir:   strings.TrimSpace(c.Defaults.ControlsDir),
			ObserveDir:    strings.TrimSpace(c.Defaults.ObservationsDir),
			Active:        name == active,
		})
	}

	if format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, items)
	}

	if len(items) == 0 {
		_, err := fmt.Fprintln(r.Stdout, "No contexts configured.")
		return err
	}
	for _, item := range items {
		suffix := ""
		if item.Active {
			suffix = " (active)"
		}
		fmt.Fprintf(r.Stdout, "%s%s\n", item.Name, suffix)
		fmt.Fprintf(r.Stdout, "  root: %s\n", item.ProjectRoot)
		fmt.Fprintf(r.Stdout, "  config: %s\n", emptyDash(item.ProjectConfig))
		fmt.Fprintf(r.Stdout, "  controls: %s\n", emptyDash(item.ControlsDir))
		fmt.Fprintf(r.Stdout, "  observations: %s\n", emptyDash(item.ObserveDir))
	}
	return nil
}

// Create adds or updates a named context in the store.
func (r *Runner) Create(_ context.Context, st *contexts.Store, name string, c contexts.Context) error {
	name = contexts.NormalizeName(name)
	if name == "" {
		return &ui.UserError{Err: fmt.Errorf("context name cannot be empty")}
	}

	st.Contexts[name] = c
	if strings.TrimSpace(st.Active) == "" {
		st.Active = name
	}

	if err := st.Save(); err != nil {
		return fmt.Errorf("failed to save context store: %w", err)
	}

	fmt.Fprintf(r.Stdout, "Context saved: %s\n", name)
	return nil
}

// Use sets a context as the active default in the store.
func (r *Runner) Use(_ context.Context, st *contexts.Store, name string) error {
	name = contexts.NormalizeName(name)
	if _, ok := st.Contexts[name]; !ok {
		return &ui.UserError{Err: fmt.Errorf("context %q not found (available: %s)", name, strings.Join(st.Names(), ", "))}
	}

	st.Active = name
	if err := st.Save(); err != nil {
		return fmt.Errorf("failed to update active context: %w", err)
	}

	fmt.Fprintf(r.Stdout, "Active context: %s\n", name)
	return nil
}

// Show renders the currently selected context.
func (r *Runner) Show(_ context.Context, format ui.OutputFormat, res ShowResult) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}

	_, err := fmt.Fprintf(r.Stdout, "Context: %s (%s)\nStore: %s\nProject root: %s\nConfig: %s\nControls default: %s\nObservations default: %s\n",
		res.Name,
		res.SelectedBy,
		res.StoreFile,
		res.ProjectRoot,
		emptyDash(res.ProjectConfig),
		emptyDash(res.ControlsDir),
		emptyDash(res.ObserveDir),
	)
	return err
}

// Delete removes a context from the store.
func (r *Runner) Delete(_ context.Context, st *contexts.Store, name string) error {
	name = contexts.NormalizeName(name)
	if _, ok := st.Contexts[name]; !ok {
		return &ui.UserError{Err: fmt.Errorf("context %q not found", name)}
	}

	delete(st.Contexts, name)
	if strings.TrimSpace(st.Active) == name {
		st.Active = ""
	}

	if err := st.Save(); err != nil {
		return fmt.Errorf("failed to persist context deletion: %w", err)
	}

	fmt.Fprintf(r.Stdout, "Deleted context: %s\n", name)
	return nil
}

// --- CLI Bridge ---

// NewContextCmd constructs the context command tree.
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

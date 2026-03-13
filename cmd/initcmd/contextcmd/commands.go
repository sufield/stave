package contextcmd

import (
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

// NewContextCmd constructs the context command tree with closure-scoped flags.
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

type contextListItem struct {
	Name          string `json:"name"`
	ProjectRoot   string `json:"project_root"`
	ProjectConfig string `json:"project_config,omitempty"`
	ControlsDir   string `json:"controls_dir,omitempty"`
	ObserveDir    string `json:"observations_dir,omitempty"`
	Active        bool   `json:"active"`
}

type contextShowOutput struct {
	StoreFile     string `json:"store_file"`
	SelectedBy    string `json:"selected_by"`
	Name          string `json:"name"`
	ProjectRoot   string `json:"project_root"`
	ProjectConfig string `json:"project_config,omitempty"`
	ControlsDir   string `json:"controls_dir,omitempty"`
	ObserveDir    string `json:"observations_dir,omitempty"`
}

func runContextList(cmd *cobra.Command, rawFormat string) error {
	st, _, err := contexts.Load()
	if err != nil {
		return err
	}
	items := contextListItemsFromState(st)
	format, err := compose.ResolveFormatValue(cmd, rawFormat)
	if err != nil {
		return err
	}
	return writeContextListOutput(cmd.OutOrStdout(), items, format)
}

func contextListItemsFromState(st *contexts.Store) []contextListItem {
	names := st.Names()
	items := make([]contextListItem, 0, len(names))
	active := strings.TrimSpace(st.Active)
	for _, name := range names {
		ctx := st.Contexts[name]
		items = append(items, contextListItem{
			Name:          name,
			ProjectRoot:   strings.TrimSpace(ctx.ProjectRoot),
			ProjectConfig: strings.TrimSpace(ctx.ProjectConfig),
			ControlsDir:   strings.TrimSpace(ctx.Defaults.ControlsDir),
			ObserveDir:    strings.TrimSpace(ctx.Defaults.ObservationsDir),
			Active:        name == active,
		})
	}
	return items
}

func writeContextListOutput(w io.Writer, items []contextListItem, format ui.OutputFormat) error {
	if format.IsJSON() {
		return writeContextListJSON(w, items)
	}
	return writeContextListText(w, items)
}

func writeContextListJSON(w io.Writer, items []contextListItem) error {
	return jsonutil.WriteIndented(w, items)
}

func writeContextListText(w io.Writer, items []contextListItem) error {
	if len(items) == 0 {
		_, err := fmt.Fprintln(w, "No contexts configured.")
		return err
	}
	for _, item := range items {
		if err := writeContextListItem(w, item); err != nil {
			return err
		}
	}
	return nil
}

func writeContextListItem(w io.Writer, item contextListItem) error {
	activeMark := ""
	if item.Active {
		activeMark = " (active)"
	}
	lines := []string{
		fmt.Sprintf("%s%s", item.Name, activeMark),
		fmt.Sprintf("  root: %s", item.ProjectRoot),
		fmt.Sprintf("  config: %s", emptyDash(item.ProjectConfig)),
		fmt.Sprintf("  controls: %s", emptyDash(item.ControlsDir)),
		fmt.Sprintf("  observations: %s", emptyDash(item.ObserveDir)),
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func runContextCreate(cmd *cobra.Command, args []string, dir, configFile, controls, observations string) error {
	name := contexts.NormalizeName(args[0])
	if name == "" {
		return &ui.InputError{Err: fmt.Errorf("context name cannot be empty")}
	}
	rootAbs, err := filepath.Abs(strings.TrimSpace(dir))
	if err != nil {
		return fmt.Errorf("resolve --dir: %w", err)
	}
	fi, err := os.Stat(rootAbs)
	if err != nil || !fi.IsDir() {
		return &ui.InputError{Err: fmt.Errorf("--dir must point to an existing directory: %s", rootAbs)}
	}

	st, _, err := contexts.Load()
	if err != nil {
		return err
	}
	ctx := contexts.Context{ProjectRoot: rootAbs}
	ctx.ProjectConfig = strings.TrimSpace(configFile)
	ctx.Defaults.ControlsDir = strings.TrimSpace(controls)
	ctx.Defaults.ObservationsDir = strings.TrimSpace(observations)

	st.Contexts[name] = ctx
	if strings.TrimSpace(st.Active) == "" {
		st.Active = name
	}
	err = st.Save()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Context saved: %s\n", name)
	return err
}

func runContextUse(cmd *cobra.Command, args []string) error {
	name := contexts.NormalizeName(args[0])
	st, _, err := contexts.Load()
	if err != nil {
		return err
	}
	if _, ok := st.Contexts[name]; !ok {
		return &ui.InputError{Err: fmt.Errorf("context %q not found (available: %s)", name, strings.Join(st.Names(), ", "))}
	}
	st.Active = name
	err = st.Save()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Active context: %s\n", name)
	return err
}

func runContextShow(cmd *cobra.Command, rawFormat string) error {
	st, path, err := contexts.Load()
	if err != nil {
		return err
	}
	name, ctx, ok, err := st.ResolveSelected()
	if err != nil {
		return err
	}
	if !ok || ctx == nil {
		return &ui.InputError{Err: fmt.Errorf("no context selected; use `stave context create <name> --dir <path>` then `stave context use <name>`")}
	}
	selectedBy := "active"
	if strings.TrimSpace(os.Getenv("STAVE_CONTEXT")) != "" {
		selectedBy = "env:STAVE_CONTEXT"
	}
	out := contextShowOutput{
		StoreFile:     path,
		SelectedBy:    selectedBy,
		Name:          name,
		ProjectRoot:   strings.TrimSpace(ctx.ProjectRoot),
		ProjectConfig: strings.TrimSpace(ctx.ProjectConfig),
		ControlsDir:   strings.TrimSpace(ctx.Defaults.ControlsDir),
		ObserveDir:    strings.TrimSpace(ctx.Defaults.ObservationsDir),
	}

	format, err := compose.ResolveFormatValue(cmd, rawFormat)
	if err != nil {
		return err
	}
	if format.IsJSON() {
		return jsonutil.WriteIndented(cmd.OutOrStdout(), out)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Context: %s (%s)\nStore: %s\nProject root: %s\nConfig: %s\nControls default: %s\nObservations default: %s\n",
		out.Name,
		out.SelectedBy,
		out.StoreFile,
		out.ProjectRoot,
		emptyDash(out.ProjectConfig),
		emptyDash(out.ControlsDir),
		emptyDash(out.ObserveDir),
	)
	return err
}

func runContextDelete(cmd *cobra.Command, args []string) error {
	name := contexts.NormalizeName(args[0])
	st, _, err := contexts.Load()
	if err != nil {
		return err
	}
	if _, ok := st.Contexts[name]; !ok {
		return &ui.InputError{Err: fmt.Errorf("context %q not found", name)}
	}
	delete(st.Contexts, name)
	if strings.TrimSpace(st.Active) == name {
		st.Active = ""
	}
	err = st.Save()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted context: %s\n", name)
	return err
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

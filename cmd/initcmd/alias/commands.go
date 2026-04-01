package alias

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// --- Domain Types ---

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// CommandFinder checks if an alias name collides with an existing built-in command.
type CommandFinder interface {
	Exists(name string) bool
}

// Entry represents a single command alias.
type Entry struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

// --- Runner ---

// Runner orchestrates the management of command aliases in user configuration.
type Runner struct {
	Resolver *projconfig.Resolver
	Finder   CommandFinder
	Stdout   io.Writer
	Stderr   io.Writer
}

// Set creates or updates an alias in the user's global config.
func (r *Runner) Set(ctx context.Context, name, command string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if !namePattern.MatchString(name) {
		return fmt.Errorf("invalid alias name %q: must match [a-zA-Z0-9_-]+", name)
	}

	if r.Finder != nil && r.Finder.Exists(name) {
		return fmt.Errorf("alias %q collides with an existing built-in command", name)
	}

	command = strings.TrimSpace(command)
	if command == "" {
		return fmt.Errorf("alias command cannot be empty")
	}

	cfg, path, err := r.Resolver.LoadUserConfig()
	if err != nil {
		return err
	}
	if cfg.Aliases == nil {
		cfg.Aliases = map[string]string{}
	}
	cfg.Aliases[name] = command

	if err := r.Resolver.WriteUserConfig(cfg, path); err != nil {
		return fmt.Errorf("persisting alias: %w", err)
	}

	fmt.Fprintf(r.Stderr, "Alias set: %s -> %s\n", name, command)
	return nil
}

// List retrieves all defined aliases and outputs them in the requested format.
func (r *Runner) List(ctx context.Context, format appcontracts.OutputFormat) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cfg, _, err := r.Resolver.LoadUserConfig()
	if err != nil {
		return err
	}

	var entries []Entry
	for k, v := range cfg.Aliases {
		entries = append(entries, Entry{Name: k, Command: v})
	}
	slices.SortFunc(entries, func(a, b Entry) int {
		return strings.Compare(a.Name, b.Name)
	})

	if format.IsJSON() {
		if entries == nil {
			entries = []Entry{}
		}
		return jsonutil.WriteIndented(r.Stdout, entries)
	}

	if len(entries) == 0 {
		fmt.Fprintln(r.Stdout, "No aliases defined.")
		return nil
	}
	for _, e := range entries {
		fmt.Fprintf(r.Stdout, "%s -> %s\n", e.Name, e.Command)
	}
	return nil
}

// Delete removes an existing alias from the user's config.
func (r *Runner) Delete(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cfg, path, err := r.Resolver.LoadUserConfig()
	if err != nil {
		return err
	}

	if _, ok := cfg.Aliases[name]; !ok {
		return fmt.Errorf("alias %q not found", name)
	}

	delete(cfg.Aliases, name)
	if len(cfg.Aliases) == 0 {
		cfg.Aliases = nil
	}

	if err := r.Resolver.WriteUserConfig(cfg, path); err != nil {
		return fmt.Errorf("persisting alias deletion: %w", err)
	}

	fmt.Fprintf(r.Stderr, "Alias deleted: %s\n", name)
	return nil
}

// --- CLI Bridge ---

// cobraFinder implements CommandFinder by checking the command tree.
type cobraFinder struct {
	root *cobra.Command
}

func (f *cobraFinder) Exists(name string) bool {
	if f.root == nil {
		return false
	}
	found, _, err := f.root.Find([]string{name})
	return err == nil && found != nil && found != f.root
}

// NewCmd constructs the alias command tree.
func NewCmd(rootCmd *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alias",
		Short: "Manage command aliases",
		Long:  "Create, list, and delete command aliases stored in user config." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	cmd.AddCommand(newSetCmd(rootCmd))
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newDeleteCmd())

	return cmd
}

func newSetCmd(rootCmd *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "set <name> <command>",
		Short: "Create or update an alias",
		Long: `Set creates or updates a command alias.

Alias names must match [a-zA-Z0-9_-]+ and must not collide with
existing command names.

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave alias set ev "apply --controls controls/s3 --now 2026-01-11T00:00:00Z"`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := projconfig.NewResolver()
			if err != nil {
				return fmt.Errorf("resolve project context: %w", err)
			}
			runner := &Runner{
				Resolver: res,
				Finder:   &cobraFinder{root: rootCmd},
				Stderr:   cmd.ErrOrStderr(),
			}
			return runner.Set(cmd.Context(), args[0], args[1])
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func newListCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all aliases",
		Long: `List all defined aliases from user config.

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave alias list --format json`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := projconfig.NewResolver()
			if err != nil {
				return fmt.Errorf("resolve project context: %w", err)
			}
			runner := &Runner{
				Resolver: res,
				Stdout:   cmd.OutOrStdout(),
			}
			fmtValue, fmtErr := compose.ResolveFormatValue(cmd, format)
			if fmtErr != nil {
				return fmtErr
			}
			return runner.List(cmd.Context(), fmtValue)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))

	return cmd
}

func newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete an alias",
		Long: `Delete removes an alias from user config.

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave alias delete ev`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := projconfig.NewResolver()
			if err != nil {
				return fmt.Errorf("resolve project context: %w", err)
			}
			runner := &Runner{
				Resolver: res,
				Stderr:   cmd.ErrOrStderr(),
			}
			return runner.Delete(cmd.Context(), args[0])
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

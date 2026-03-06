package alias

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

var aliasFormat string

var aliasNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// rootCmd is set by the wiring layer via SetRootCmd after root command creation.
// It is used only for alias collision detection.
var rootCmd *cobra.Command

// SetRootCmd injects the root command for alias collision detection.
func SetRootCmd(cmd *cobra.Command) {
	rootCmd = cmd
}

var AliasCmd = &cobra.Command{
	Use:   "alias",
	Short: "Manage command aliases",
	Long:  "Create, list, and delete command aliases stored in user config." + metadata.OfflineHelpSuffix,
	Args:  cobra.NoArgs,
}

var AliasSetCmd = &cobra.Command{
	Use:   "set <name> <command>",
	Short: "Create or update an alias",
	Long: `Set creates or updates a command alias.

Alias names must match [a-zA-Z0-9_-]+ and must not collide with
existing command names.

Examples:
  stave alias set ap "apply --controls controls/s3 --observations examples/observations --max-unsafe 24h"
  stave alias set q "apply --quiet"` + metadata.OfflineHelpSuffix,
	Args:          cobra.ExactArgs(2),
	RunE:          runAliasSet,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var AliasListCmd = &cobra.Command{
	Use:           "list",
	Short:         "List all aliases",
	Long:          "List all defined aliases from user config." + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          runAliasList,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var AliasDeleteCmd = &cobra.Command{
	Use:           "delete <name>",
	Short:         "Delete an alias",
	Long:          "Delete removes an alias from user config." + metadata.OfflineHelpSuffix,
	Args:          cobra.ExactArgs(1),
	RunE:          runAliasDelete,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	AliasListCmd.Flags().StringVarP(&aliasFormat, "format", "f", "text", "Output format: text or json")
	_ = AliasListCmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	AliasCmd.AddCommand(AliasSetCmd)
	AliasCmd.AddCommand(AliasListCmd)
	AliasCmd.AddCommand(AliasDeleteCmd)
}

func runAliasSet(_ *cobra.Command, args []string) error {
	name := args[0]
	command := args[1]

	if !aliasNamePattern.MatchString(name) {
		return fmt.Errorf("invalid alias name %q: must match [a-zA-Z0-9_-]+", name)
	}

	// Check for collision with existing commands
	if rootCmd != nil {
		if cmd, _, err := rootCmd.Find([]string{name}); err == nil && cmd != nil && cmd != rootCmd {
			return fmt.Errorf("alias %q collides with existing command %q", name, cmd.Use)
		}
	}

	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("alias command cannot be empty")
	}

	cfg, path := cmdutil.LoadUserConfigFull()
	if cfg.Aliases == nil {
		cfg.Aliases = map[string]string{}
	}
	cfg.Aliases[name] = command

	if err := cmdutil.WriteUserConfigFull(cfg, path); err != nil {
		return fmt.Errorf("write alias: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Alias set: %s -> %s\n", name, command)
	return nil
}

type aliasEntry struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

func runAliasList(cmd *cobra.Command, _ []string) error {
	aliases := cmdutil.LoadUserAliases()

	formatRaw := strings.TrimSpace(aliasFormat)
	if !cmd.Flags().Changed("format") && cmdutil.IsJSONMode(cmd) {
		formatRaw = "json"
	}
	format, err := ui.ParseOutputFormat(strings.ToLower(formatRaw))
	if err != nil {
		return err
	}

	names := make([]string, 0, len(aliases))
	for name := range aliases {
		names = append(names, name)
	}
	sort.Strings(names)

	if format.IsJSON() {
		entries := make([]aliasEntry, 0, len(names))
		for _, name := range names {
			entries = append(entries, aliasEntry{Name: name, Command: aliases[name]})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	if len(names) == 0 {
		fmt.Fprintln(os.Stdout, "No aliases defined.")
		return nil
	}
	for _, name := range names {
		fmt.Fprintf(os.Stdout, "%s -> %s\n", name, aliases[name])
	}
	return nil
}

func runAliasDelete(_ *cobra.Command, args []string) error {
	name := args[0]

	cfg, path := cmdutil.LoadUserConfigFull()
	if cfg.Aliases == nil || cfg.Aliases[name] == "" {
		return fmt.Errorf("alias %q not found", name)
	}

	delete(cfg.Aliases, name)
	if len(cfg.Aliases) == 0 {
		cfg.Aliases = nil
	}

	if err := cmdutil.WriteUserConfigFull(cfg, path); err != nil {
		return fmt.Errorf("write alias: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Alias deleted: %s\n", name)
	return nil
}

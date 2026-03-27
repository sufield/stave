package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestCligCompliance verifies that all Stave commands follow CLIG.dev
// guidelines: help quality, flag conventions, exit code documentation,
// and output format support.
func TestCligCompliance(t *testing.T) {
	root := getRootCmd()

	// Walk the full command tree (including nested subcommands).
	var commands []*cobra.Command
	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		commands = append(commands, cmd)
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	for _, child := range root.Commands() {
		walk(child)
	}

	for _, cmd := range commands {
		name := cmd.CommandPath()

		// Skip group headers (no Run function) and built-in helpers.
		if cmd.RunE == nil && cmd.Run == nil && !cmd.HasSubCommands() {
			continue
		}
		// Skip pure group parents that only exist to hold subcommands.
		if (cmd.RunE == nil && cmd.Run == nil) && cmd.HasSubCommands() {
			continue
		}

		t.Run(name, func(t *testing.T) {
			t.Run("has_long_description", func(t *testing.T) {
				if strings.TrimSpace(cmd.Long) == "" {
					t.Errorf("%s: missing Long description (CLIG: every command needs a detailed help)", name)
				}
			})

			t.Run("long_starts_with_verb", func(t *testing.T) {
				long := strings.TrimSpace(cmd.Long)
				if long == "" {
					t.Skip("no Long description")
				}
				// First word should be capitalized (verb phrase).
				first := strings.SplitN(long, " ", 2)[0]
				if first != "" && first[0] >= 'a' && first[0] <= 'z' {
					t.Errorf("%s: Long description should start with a capitalized verb, got %q", name, first)
				}
			})

			t.Run("documents_exit_codes", func(t *testing.T) {
				// Only leaf commands that execute logic need exit code docs.
				if cmd.RunE == nil && cmd.Run == nil {
					t.Skip("group command")
				}
				long := strings.TrimSpace(cmd.Long)
				if long == "" {
					t.Skip("no Long description")
				}
				if !strings.Contains(strings.ToLower(long), "exit") {
					t.Errorf("%s: Long description should document exit codes", name)
				}
			})

			t.Run("has_examples", func(t *testing.T) {
				if cmd.RunE == nil && cmd.Run == nil {
					t.Skip("group command")
				}
				if strings.TrimSpace(cmd.Example) == "" {
					t.Errorf("%s: missing Example (CLIG: show realistic usage)", name)
				}
			})

			t.Run("silence_usage_set", func(t *testing.T) {
				// Commands should not dump usage on every error.
				if cmd.RunE == nil {
					t.Skip("no RunE")
				}
				if !cmd.SilenceUsage {
					t.Errorf("%s: SilenceUsage should be true (errors should not print usage)", name)
				}
			})

			t.Run("silence_errors_set", func(t *testing.T) {
				if cmd.RunE == nil {
					t.Skip("no RunE")
				}
				if !cmd.SilenceErrors {
					t.Errorf("%s: SilenceErrors should be true (errors rendered by executor)", name)
				}
			})

			t.Run("format_flag_if_data_command", func(t *testing.T) {
				if !isDataCommand(cmd) {
					t.Skip("not a data command")
				}
				f := cmd.Flags().Lookup("format")
				if f == nil {
					f = cmd.InheritedFlags().Lookup("format")
				}
				if f == nil {
					t.Errorf("%s: data-producing command lacks --format flag", name)
				}
			})
		})
	}
}

// TestCligGlobalFlags verifies root-level flags required by CLIG.dev.
func TestCligGlobalFlags(t *testing.T) {
	root := getRootCmd()

	// help and version are managed by Cobra itself (not in PersistentFlags).
	if !root.Flags().HasFlags() && root.PersistentFlags().Lookup("help") == nil {
		// Cobra always registers --help; this is a sanity check.
		t.Error("root command missing --help (Cobra should register this)")
	}
	if root.Version == "" {
		t.Error("root command has empty Version (CLIG: --version must print version)")
	}

	requiredGlobals := []struct {
		name string
		why  string
	}{
		{"quiet", "CLIG: --quiet suppresses non-essential output"},
		{"verbose", "CLIG: -v enables verbose/debug output"},
		{"no-color", "CLIG: --no-color disables ANSI output"},
	}

	for _, rf := range requiredGlobals {
		t.Run(rf.name, func(t *testing.T) {
			f := root.PersistentFlags().Lookup(rf.name)
			if f == nil {
				f = root.Flags().Lookup(rf.name)
			}
			if f == nil {
				t.Errorf("root command missing --%s flag (%s)", rf.name, rf.why)
			}
		})
	}
}

// isDataCommand returns true for commands that produce multi-format output
// (text + JSON or text + JSON + SARIF). These should have --format.
// JSON-only inspection commands are excluded — they always output JSON by
// design and don't need a format switch.
func isDataCommand(cmd *cobra.Command) bool {
	multiFormatCommands := map[string]bool{
		"stave apply":             true,
		"stave diagnose":          true,
		"stave validate":          true,
		"stave report":            true,
		"stave doctor":            true,
		"stave security-audit":    true,
		"stave ci gate":           true,
		"stave snapshot diff":     true,
		"stave snapshot quality":  true,
		"stave snapshot upcoming": true,
		"stave snapshot hygiene":  true,
		"stave controls list":     true,
	}
	return multiFormatCommands[cmd.CommandPath()]
}

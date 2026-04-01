package env

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	staveenv "github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// --- Domain Types ---

// ListConfig defines the parameters for the environment variable listing.
type ListConfig struct {
	Format appcontracts.OutputFormat
	Stdout io.Writer
}

// Entry represents the structured output for an environment variable.
type Entry struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Category     string `json:"category"`
	Value        string `json:"value"`
	IsSet        bool   `json:"is_set"`
	DefaultValue string `json:"default_value,omitempty"`
}

// listEnvVars retrieves all supported STAVE_* variables and renders them.
func listEnvVars(cfg ListConfig) error {
	vars := staveenv.All()
	entries := make([]Entry, len(vars))
	for i, v := range vars {
		val := v.Value()
		isSet := val != ""
		if !isSet {
			val = v.DefaultValue
		}
		entries[i] = Entry{
			Name:         v.Name,
			Description:  v.Description,
			Category:     v.Category,
			Value:        val,
			IsSet:        isSet || v.DefaultValue != "",
			DefaultValue: v.DefaultValue,
		}
	}

	if cfg.Format.IsJSON() {
		return jsonutil.WriteIndented(cfg.Stdout, entries)
	}
	return renderEnvText(cfg.Stdout, entries)
}

func renderEnvText(w io.Writer, entries []Entry) error {
	fmt.Fprintln(w, "STAVE_* Environment Variables")
	fmt.Fprintln(w, "-----------------------------")

	categories := []struct {
		label string
		key   string
	}{
		{"Configuration", "config"},
		{"Debug", "debug"},
	}

	for _, cat := range categories {
		fmt.Fprintf(w, "\n%s:\n", cat.label)

		tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		for _, e := range entries {
			if e.Category != cat.key {
				continue
			}
			display := e.Value
			if !e.IsSet {
				display = "(not set)"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", e.Name, e.Description, display)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// --- CLI Bridge ---

// NewEnvCmd constructs the env command tree.
func NewEnvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Manage environment variables",
		Long: `Env groups commands for discovering STAVE_* environment variables
supported by Stave.

Examples:
  stave env list
  stave env list --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(newEnvListCmd())
	return cmd
}

func newEnvListCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List supported STAVE_* environment variables",
		Long: `List prints every supported STAVE_* environment variable with its
description, category, and current value.

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave config env list`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmtValue, err := compose.ResolveFormatValue(cmd, format)
			if err != nil {
				return err
			}
			return listEnvVars(ListConfig{
				Format: fmtValue,
				Stdout: cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	return cmd
}

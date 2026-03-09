package env

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/envvar"
	"github.com/sufield/stave/internal/metadata"
)

// NewEnvCmd constructs the env command tree with closure-scoped flags.
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

Examples:
  stave env list
  stave env list --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnvList(cmd, format)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}

type envListEntry struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Category     string `json:"category"`
	Value        string `json:"value"`
	DefaultValue string `json:"default_value,omitempty"`
}

func runEnvList(cmd *cobra.Command, rawFormat string) error {
	vars := envvar.All()

	format, err := cmdutil.ResolveFormatValue(cmd, rawFormat)
	if err != nil {
		return err
	}

	if format.IsJSON() {
		return writeEnvListJSON(cmd, vars)
	}
	return writeEnvListText(cmd, vars)
}

func writeEnvListJSON(cmd *cobra.Command, vars []envvar.Entry) error {
	entries := make([]envListEntry, len(vars))
	for i, v := range vars {
		entries[i] = envListEntry{
			Name:         v.Name,
			Description:  v.Description,
			Category:     v.Category,
			Value:        v.Value(),
			DefaultValue: v.DefaultValue,
		}
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func writeEnvListText(cmd *cobra.Command, vars []envvar.Entry) error {
	w := cmd.OutOrStdout()
	if err := writeEnvListHeader(w); err != nil {
		return err
	}
	nameWidth, descWidth := envColumnWidths(vars)

	categories := []struct {
		label string
		key   string
	}{
		{"Configuration", "config"},
		{"Debug", "debug"},
	}

	for _, category := range categories {
		if err := writeEnvListCategory(w, vars, category.label, category.key, nameWidth, descWidth); err != nil {
			return err
		}
	}
	return nil
}

func writeEnvListHeader(w io.Writer) error {
	if _, err := fmt.Fprintln(w, "STAVE_* Environment Variables"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "-----------------------------")
	return err
}

func envColumnWidths(vars []envvar.Entry) (int, int) {
	nameWidth := 0
	descWidth := 0
	for _, variable := range vars {
		if len(variable.Name) > nameWidth {
			nameWidth = len(variable.Name)
		}
		if len(variable.Description) > descWidth {
			descWidth = len(variable.Description)
		}
	}
	return nameWidth, descWidth
}

func writeEnvListCategory(w io.Writer, vars []envvar.Entry, label, key string, nameWidth, descWidth int) error {
	if _, err := fmt.Fprintf(w, "\n%s:\n", label); err != nil {
		return err
	}
	for _, variable := range vars {
		if variable.Category != key {
			continue
		}
		if err := writeEnvListVariable(w, variable, nameWidth, descWidth); err != nil {
			return err
		}
	}
	return nil
}

func writeEnvListVariable(w io.Writer, variable envvar.Entry, nameWidth, descWidth int) error {
	value := variable.Value()
	if value == "" {
		value = "(not set)"
	}
	_, err := fmt.Fprintf(w, "  %-*s  %-*s  %s\n", nameWidth, variable.Name, descWidth, variable.Description, value)
	return err
}

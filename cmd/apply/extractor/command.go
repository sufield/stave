package extractor

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

var (
	// ExtractorCmd is the extractor parent command.
	ExtractorCmd *cobra.Command
	// ExtractorNewCmd is the extractor new subcommand.
	ExtractorNewCmd *cobra.Command
)

type options struct {
	Name string
	Dir  string
}

func defaultOptions() *options {
	return &options{Dir: "."}
}

func (o *options) BindFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&o.Name, "name", "", "Extractor name (required; used for directory and file naming)")
	flags.StringVar(&o.Dir, "dir", o.Dir, "Parent directory where the extractor scaffold is created")
	_ = cmd.MarkFlagRequired("name")
}

func (o *options) normalize() {
	o.Dir = fsutil.CleanUserPath(o.Dir)
	o.Name = strings.TrimSpace(o.Name)
}

func (o *options) validate() error {
	if strings.TrimSpace(o.Name) == "" {
		return fmt.Errorf("--name cannot be empty")
	}
	if strings.ContainsAny(o.Name, `/\`) || o.Name != filepath.Base(o.Name) || o.Name == ".." || o.Name == "." {
		return fmt.Errorf("--name must be a plain identifier, not a path (got %q)", o.Name)
	}
	return nil
}

func init() {
	ExtractorCmd = NewCmd(ui.NewRuntime(nil, nil))
}

// NewCmd builds the extractor command tree.
func NewCmd(rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		rt = ui.NewRuntime(nil, nil)
	}

	opts := defaultOptions()
	newCmd := newExtractorNewCmd(rt, opts)

	cmd := &cobra.Command{
		Use:   "extractor",
		Short: "Extractor development commands",
		Long:  "Grouped commands for developing custom extractors." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newCmd)

	ExtractorNewCmd = newCmd
	return cmd
}

func newExtractorNewCmd(rt *ui.Runtime, opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Scaffold a new custom extractor project",
		Long: `New creates a starter directory layout for building a custom Stave extractor,
including a README, metadata file, starter Go transform, test, and Makefile.

Examples:
  stave extractor new --name my-extractor
  stave extractor new --name aws-rds --dir ./extractors
  stave extractor new --name my-extractor --force` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScaffold(cmd, rt, opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}

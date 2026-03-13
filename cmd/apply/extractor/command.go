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

type options struct {
	Name string
	Dir  string
}

// NewCmd builds the extractor command tree.
func NewCmd(rt *ui.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extractor",
		Short: "Extractor development commands",
		Long:  "Grouped commands for developing custom extractors." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	cmd.AddCommand(newExtractorNewCmd(rt))

	return cmd
}

func newExtractorNewCmd(rt *ui.Runtime) *cobra.Command {
	opts := &options{
		Dir: ".",
	}

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
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			opts.normalize()
			return opts.validate()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if rt == nil {
				rt = ui.DefaultRuntime()
			}
			return runScaffold(cmd, rt, opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.bindFlags(cmd)

	return cmd
}

func (o *options) bindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.Name, "name", "", "Extractor name (required; used for directory and file naming)")
	f.StringVar(&o.Dir, "dir", o.Dir, "Parent directory where the extractor scaffold is created")
	_ = cmd.MarkFlagRequired("name")
}

func (o *options) normalize() {
	o.Dir = fsutil.CleanUserPath(o.Dir)
	o.Name = strings.TrimSpace(o.Name)
}

func (o *options) validate() error {
	if o.Name == "" {
		return fmt.Errorf("flag --name is required")
	}

	base := filepath.Base(o.Name)
	if strings.ContainsAny(o.Name, `/\`) || o.Name != base || o.Name == ".." || o.Name == "." {
		return fmt.Errorf("invalid name %q: must be a plain identifier, not a path", o.Name)
	}
	return nil
}

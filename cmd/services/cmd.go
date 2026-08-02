// Package services implements `stave services` — queries against the
// service registry (data/services.yaml). Subcommands: list, inspect,
// coverage. Hidden command (internal tooling).
package services

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	RegistryPath string
	ControlsDir  string
	Format       string
	Status       string
	Category     string
	HasControls  bool
	NoControls   bool
}

// NewCmd constructs the `services` command.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "services",
		Short:  "Query the AWS service registry",
		Hidden: true,
		Long: `Services queries the service registry (data/services.yaml) to show
which AWS services Stave is aware of, their coverage status, and
control density.

The registry is the source of truth for Stave's AWS service
universe. Control counts are derived at runtime by joining against
the control catalog.

Subcommands:
  list       List all services with status and control counts
  inspect    Full detail for one service
  coverage   Aggregate coverage report by category

Inputs:
  --registry     Path to services.yaml (default: data/services.yaml)
  --controls     Control catalog directory (default: controls)

Exit codes:
  0   Success
  2   Invalid input
  4   Internal error
`,
		Example: `  stave services list
  stave services list --status=active --has-controls
  stave services inspect iam
  stave services coverage`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newInspectCmd())
	cmd.AddCommand(newCoverageCmd())
	return cmd
}

func newListCmd() *cobra.Command {
	opts := &options{
		RegistryPath: "data/services.yaml",
		ControlsDir:  "",
		Format:       "text",
	}
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all services in the registry",
		Long: `List shows every service in the registry with its status, category,
and live control count (joined from the control catalog).

Inputs:
  --status S       Filter by status: active | known_not_covered | out_of_scope | retired | preview
  --category C     Filter by category (e.g., compute, identity)
  --has-controls   Only services with at least one control
  --no-controls    Only services with zero controls (gap finder)
  --format F       text (default) | json
  --registry       Path to services.yaml (default: data/services.yaml)
  --controls DIR   Control catalog directory (default: controls)

Exit codes:
  0   Success
  4   Internal error
`,
		Example: `  stave services list
  stave services list --status=active
  stave services list --category=compute --format json
  stave services list --no-controls`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.Format != "json" && opts.Format != "text" && opts.Format != "" {
				return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
			}
			out, err := stave.RenderServicesList(cmd.Context(), stave.ServicesListOptions{
				RegistryPath: opts.RegistryPath,
				ControlsDir:  opts.ControlsDir,
				Format:       opts.Format,
				Status:       opts.Status,
				Category:     opts.Category,
				HasControls:  opts.HasControls,
				NoControls:   opts.NoControls,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVar(&opts.RegistryPath, "registry", "data/services.yaml", "path to services.yaml")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "control catalog directory (default: embedded catalog)")
	cmd.Flags().StringVar(&opts.Status, "status", "", "filter by status")
	cmd.Flags().StringVar(&opts.Category, "category", "", "filter by category")
	cmd.Flags().BoolVar(&opts.HasControls, "has-controls", false, "only services with controls")
	cmd.Flags().BoolVar(&opts.NoControls, "no-controls", false, "only services with zero controls")
	return cmd
}

func newInspectCmd() *cobra.Command {
	opts := &options{
		RegistryPath: "data/services.yaml",
		ControlsDir:  "",
		Format:       "text",
	}
	cmd := &cobra.Command{
		Use:   "inspect <service-id>",
		Short: "Inspect a single service",
		Long: `Inspect shows full detail for one service: metadata, notes, and
all controls that belong to it (joined from the catalog).

Inputs:
  <service-id>     Service ID (positional, required)
  --format F       text (default) | json
  --registry       Path to services.yaml (default: data/services.yaml)
  --controls DIR   Control catalog directory (default: controls)

Exit codes:
  0   Success
  2   Invalid input (service not found)
  4   Internal error
`,
		Example: `  stave services inspect iam
  stave services inspect s3 --format json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Format != "json" && opts.Format != "text" && opts.Format != "" {
				return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
			}
			out, err := stave.RenderServicesInspect(cmd.Context(), stave.ServicesInspectOptions{
				ServiceID:    args[0],
				RegistryPath: opts.RegistryPath,
				ControlsDir:  opts.ControlsDir,
				Format:       opts.Format,
			})
			if err != nil {
				if errors.Is(err, stave.ErrInvalidInput) {
					return &ui.UserError{Err: err}
				}
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVar(&opts.RegistryPath, "registry", "data/services.yaml", "path to services.yaml")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "control catalog directory (default: embedded catalog)")
	return cmd
}

func newCoverageCmd() *cobra.Command {
	opts := &options{
		RegistryPath: "data/services.yaml",
		ControlsDir:  "",
		Format:       "text",
	}
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Aggregate service coverage report",
		Long: `Coverage shows an aggregate view of how the service registry
maps to the control catalog: total services by status, control
density by category, and gap identification.

Inputs:
  --category C     Single-category drill-down
  --format F       text (default) | json
  --registry       Path to services.yaml (default: data/services.yaml)
  --controls DIR   Control catalog directory (default: controls)

Exit codes:
  0   Success
  4   Internal error
`,
		Example: `  stave services coverage
  stave services coverage --format json
  stave services coverage --category=compute`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.Format != "json" && opts.Format != "text" && opts.Format != "" {
				return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
			}
			out, err := stave.RenderServicesCoverage(cmd.Context(), stave.ServicesCoverageOptions{
				RegistryPath: opts.RegistryPath,
				ControlsDir:  opts.ControlsDir,
				Format:       opts.Format,
				Category:     opts.Category,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVar(&opts.RegistryPath, "registry", "data/services.yaml", "path to services.yaml")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "control catalog directory (default: embedded catalog)")
	cmd.Flags().StringVar(&opts.Category, "category", "", "filter to one category")
	return cmd
}

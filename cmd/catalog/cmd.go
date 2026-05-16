// Package catalog implements `stave capabilities catalog` — the
// user-facing catalog view that groups controls + chains +
// operational features by service and renders a browse-friendly
// listing. Paired with `stave search` for query-by-intent.
package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcaps "github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// Deps holds the catalog-loading factories.
type Deps struct {
	NewCtlRepo     compose.CtlRepoFactory
	NewChainLoader compose.ChainLoaderFactory
}

type options struct {
	Service     string
	Category    string
	KindFilter  string
	Format      string
	ControlsDir string
	ChainsDir   string
}

// NewCmd constructs the `catalog` subcommand of `capabilities`.
func NewCmd(deps Deps) *cobra.Command {
	opts := &options{
		Format:      "text",
		ControlsDir: "controls",
		ChainsDir:   "chains",
	}
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Print the user-facing capability catalog",
		Long: `Catalog emits the grouped view of what Stave can check: control
groups by (service, category), compound chains, and operational
features (readiness, gaps, drift, validate, export-sir). Pair with
` + "`stave search <query>`" + ` to look up by intent.

Use --service to filter to one service (s3, iam, lambda, …) or
--category to filter within a service. --kind narrows to one of
control_group | chain | operational.

Inputs:
  --service SVC    Filter to one service (e.g. s3)
  --category CAT   Filter to one category within --service (e.g. public)
  --kind K         control_group | chain | operational
  --format F       text (default) | json
  --controls DIR   Control catalog directory (default: controls)
  --chains DIR     Chain catalog directory (default: chains)

Exit codes:
  0   Success
  2   Invalid input
  4   Internal error
`,
		Example: `  stave capabilities catalog
  stave capabilities catalog --service s3
  stave capabilities catalog --kind chain
  stave capabilities catalog --format json | jq '.capabilities | length'`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), opts, deps)
		},
	}
	cmd.Flags().StringVar(&opts.Service, "service", "", "filter to one service")
	cmd.Flags().StringVar(&opts.Category, "category", "", "filter to one category (requires --service)")
	cmd.Flags().StringVar(&opts.KindFilter, "kind", "", "filter to one kind: control_group | chain | operational")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "control catalog directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chain catalog directory")
	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options, deps Deps) error {
	switch opts.Format {
	case "text", "json":
	default:
		return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
	}
	switch opts.KindFilter {
	case "", "control_group", "chain", "operational":
	default:
		return &ui.UserError{Err: fmt.Errorf("--kind must be control_group | chain | operational (got %q)", opts.KindFilter)}
	}

	controls, err := compose.LoadControlsFrom(ctx, deps.NewCtlRepo, opts.ControlsDir)
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}
	chains, err := compose.LoadChainDefinitions(ctx, deps.NewChainLoader, opts.ChainsDir)
	if err != nil {
		var notFound interface{ NotFound() bool }
		if !errors.As(err, &notFound) || !notFound.NotFound() {
			return fmt.Errorf("load chains: %w", err)
		}
		chains = nil
	}
	catalog := appcaps.Build(controls, chains)
	catalog = filter(catalog, opts)

	if opts.Format == "json" {
		return jsonutil.WriteIndented(w, struct {
			TotalCapabilities int                  `json:"total_capabilities"`
			Capabilities      []appcaps.Capability `json:"capabilities"`
		}{
			TotalCapabilities: len(catalog),
			Capabilities:      catalog,
		})
	}
	return renderText(w, catalog)
}

func filter(in []appcaps.Capability, opts *options) []appcaps.Capability {
	out := make([]appcaps.Capability, 0, len(in))
	for _, c := range in {
		if opts.KindFilter != "" && c.Kind != opts.KindFilter {
			continue
		}
		if opts.Service != "" && c.Service != opts.Service {
			continue
		}
		if opts.Category != "" && c.Category != opts.Category {
			continue
		}
		out = append(out, c)
	}
	return out
}

func renderText(w io.Writer, catalog []appcaps.Capability) error {
	type bucketKey struct {
		kind, service string
	}
	buckets := map[bucketKey][]appcaps.Capability{}
	for _, c := range catalog {
		k := bucketKey{c.Kind, c.Service}
		buckets[k] = append(buckets[k], c)
	}
	// Stable order: by kind, then service
	keys := make([]bucketKey, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return kindOrder(keys[i].kind) < kindOrder(keys[j].kind)
		}
		return keys[i].service < keys[j].service
	})

	fmt.Fprintln(w, "Stave Capabilities")
	fmt.Fprintln(w, strings.Repeat("=", 18))
	fmt.Fprintln(w)

	totalControls, totalChains, totalOps := 0, 0, 0
	for _, k := range keys {
		caps := buckets[k]
		sort.Slice(caps, func(i, j int) bool { return caps[i].Title < caps[j].Title })

		header := headerFor(k.kind, k.service, caps)
		fmt.Fprintln(w, header)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, c := range caps {
			switch c.Kind {
			case "control_group":
				totalControls += len(c.ControlIDs)
				fmt.Fprintf(tw, "  %s\t[%s]\t%d controls\n",
					c.Title, strings.ToUpper(c.Severity), len(c.ControlIDs))
			case "chain":
				totalChains++
				fmt.Fprintf(tw, "  %s\t[chain]\t%s\n",
					c.Title, c.Description)
			case "operational":
				totalOps++
				fmt.Fprintf(tw, "  %s\t-\t%s\n", c.Title, firstSentence(c.Description))
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Totals: %d control entries across groups, %d compound chains, %d operational features\n",
		totalControls, totalChains, totalOps)
	fmt.Fprintln(w, `Use 'stave search "<intent>"' to find specific capabilities.`)
	return nil
}

func headerFor(kind, service string, caps []appcaps.Capability) string {
	switch kind {
	case "control_group":
		ctlCount := 0
		for _, c := range caps {
			ctlCount += len(c.ControlIDs)
		}
		return fmt.Sprintf("%s — %d capabilities, %d controls",
			strings.ToUpper(service), len(caps), ctlCount)
	case "chain":
		return fmt.Sprintf("Compound chains (%d)", len(caps))
	case "operational":
		return fmt.Sprintf("Operational features (%d)", len(caps))
	}
	return strings.ToUpper(service)
}

func firstSentence(s string) string {
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[:i+1]
	}
	return s
}

func kindOrder(k string) int {
	switch k {
	case "control_group":
		return 0
	case "chain":
		return 1
	case "operational":
		return 2
	}
	return 3
}

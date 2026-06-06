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
	policy "github.com/sufield/stave/internal/core/controldef"
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
	NoPager     bool
	Severity    string
	Leaf        bool
}

// NewCmd constructs the `catalog` subcommand of `capabilities`.
func NewCmd(deps Deps) *cobra.Command {
	opts := &options{
		Format:      "auto",
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

Output is paged through $PAGER (then 'less -R', then 'more') when stdout is a
terminal, and written plain and unpaged when stdout is a pipe, a redirect, or
CI — so '... | grep' and '... > file' are unaffected. JSON is never paged.
Use --no-pager to force plain output on a terminal.

Drill-down mirrors 'man <topic>':
  catalog                 summary: one line per service
  catalog <SERVICE>       that service's capabilities, one line each
  catalog <SERVICE> --leaf  the leaf controls (individual control IDs)
  catalog --severity CRITICAL  only the matching leaf controls, any level

--severity matches an EXACT level and lists control-group controls only;
chains and operational features carry no severity and are excluded (stated in
the output, not silently dropped). --leaf is the leaf drill-down: --controls/-i
is already the catalog directory, so the leaf toggle is a distinct flag.

Inputs:
  --service SVC    Filter to one service (e.g. s3); also accepted positionally
  --category CAT   Filter to one category within --service (e.g. public)
  --kind K         control_group | chain | operational
  --severity SEV   critical | high | medium | low | info (leaf controls)
  --leaf           Drill to individual leaf controls
  --format F       auto (default; paged on a TTY) | text | wide | json
  --no-pager       Never page, even on a terminal
  --controls DIR   Control catalog directory (default: controls)
  --chains DIR     Chain catalog directory (default: chains)

Exit codes:
  0   Success
  2   Invalid input
  4   Internal error
`,
		Example: `  stave capabilities catalog
  stave capabilities catalog s3
  stave capabilities catalog --service s3
  stave capabilities catalog --kind chain
  stave capabilities catalog --format json | jq '.capabilities | length'`,
		// Wrap the arg-count check in a UserError so a surplus positional
		// (e.g. `catalog s3 iam`) exits 2 (invalid input), not 4 (internal):
		// cobra's raw "accepts at most 1 arg(s)" error isn't unknown-command-
		// shaped, so without this it falls through ExitCode() to ExitInternal.
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.MaximumNArgs(1)(cmd, args); err != nil {
				return &ui.UserError{Err: err}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Positional SERVICE is accepted as an alias for --service so the
			// drill-down reads like `man <topic>`. An explicit --service wins.
			if len(args) == 1 && opts.Service == "" {
				opts.Service = args[0]
			}
			return run(cmd.Context(), cmd.OutOrStdout(), opts, deps)
		},
	}
	cmd.Flags().StringVar(&opts.Service, "service", "", "filter to one service")
	cmd.Flags().StringVar(&opts.Category, "category", "", "filter to one category (requires --service)")
	cmd.Flags().StringVar(&opts.KindFilter, "kind", "", "filter to one kind: control_group | chain | operational")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "auto", "output format: auto | text | wide | json")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "control catalog directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chain catalog directory")
	cmd.Flags().BoolVar(&opts.NoPager, "no-pager", false, "never page output, even on a terminal")
	cmd.Flags().StringVar(&opts.Severity, "severity", "", "show only leaf controls of this severity: critical | high | medium | low | info")
	cmd.Flags().BoolVar(&opts.Leaf, "leaf", false, "drill to leaf controls (the individual control IDs); pairs with a service")
	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options, deps Deps) error {
	renderer, rendErr := NewRenderer(opts.Format)
	if rendErr != nil {
		return &ui.UserError{Err: rendErr}
	}
	switch opts.KindFilter {
	case "", "control_group", "chain", "operational":
	default:
		return &ui.UserError{Err: fmt.Errorf("--kind must be control_group | chain | operational (got %q)", opts.KindFilter)}
	}
	if opts.Severity != "" {
		if sev, perr := policy.ParseSeverity(opts.Severity); perr != nil || !sev.IsValid() {
			return &ui.UserError{Err: fmt.Errorf("--severity must be critical | high | medium | low | info (got %q)", opts.Severity)}
		}
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

	mode := resolveView(opts)
	var leafs []appcaps.LeafControl
	if mode == viewLeaf {
		leafs = appcaps.LeafControls(controls, opts.Service, opts.Category, opts.Severity)
	}

	// Page human output on a TTY; never page JSON (keeps JSON-to-pipe clean)
	// and never when --no-pager is set or stdout is not a terminal. NewPager
	// returns w unchanged with a no-op close in the unpaged cases, so piped
	// and redirected output is byte-for-byte identical to before.
	pageable := opts.Format != "json" && !opts.NoPager
	pw, closePager := ui.NewPager(ctx, w, pageable)
	renderErr := renderer.Render(pw, catalogReport{
		TotalCapabilities: len(catalog),
		Capabilities:      catalog,
		summary:           appcaps.CatalogSummary(controls, chains),
		services:          appcaps.ServiceRollup(controls),
		leafs:             leafs,
		mode:              mode,
		serviceArg:        opts.Service,
		categoryArg:       opts.Category,
		sevFilter:         opts.Severity,
	})
	closeErr := closePager()
	if renderErr != nil {
		return fmt.Errorf("render catalog: %w", renderErr)
	}
	if closeErr != nil {
		return closeErr // already wrapped ("wait for pager: …") by NewPager's closer
	}
	return nil
}

// resolveView maps the flags to a human-view mode. JSON ignores this. Default
// is the summary view; --kind chain|operational lists that kind; a service or
// category filter (or --kind control_group) drills into control-group
// capabilities one line each.
func resolveView(opts *options) viewMode {
	switch {
	case opts.Leaf || opts.Severity != "":
		// --severity collapses to matching leaf controls; --leaf drills to them.
		return viewLeaf
	case opts.KindFilter == "chain" || opts.KindFilter == "operational":
		return viewKind
	case opts.Service != "" || opts.Category != "" || opts.KindFilter == "control_group":
		return viewService
	default:
		return viewSummary
	}
}

func filter(in []appcaps.Capability, opts *options) []appcaps.Capability {
	out := make([]appcaps.Capability, 0, len(in))
	for i := range in {
		c := &in[i]
		if opts.KindFilter != "" && c.Kind != opts.KindFilter {
			continue
		}
		// Case-insensitive: the summary table prints service/category names
		// uppercase, so a user drills with what they see (e.g. `catalog S3`).
		if opts.Service != "" && !strings.EqualFold(c.Service, opts.Service) {
			continue
		}
		if opts.Category != "" && !strings.EqualFold(c.Category, opts.Category) {
			continue
		}
		out = append(out, *c)
	}
	return out
}

// renderView dispatches the human-readable output by mode. Summary-first by
// default (one line per service); --service / --category drill into one
// service's capabilities; --kind chain|operational lists that kind.
func renderView(w io.Writer, r catalogReport) error {
	switch r.mode {
	case viewService:
		return renderServiceView(w, r)
	case viewKind:
		return renderKindView(w, r)
	case viewLeaf:
		return renderLeafView(w, r)
	default:
		return renderSummaryView(w, r)
	}
}

// renderSummaryView is the default: a header with catalog-wide counts and a
// control-group-scoped severity histogram, then one line per service. ~40 lines
// for the whole surface instead of the old per-control dump.
func renderSummaryView(w io.Writer, r catalogReport) error {
	s := r.summary
	fmt.Fprintf(w, "Stave: %d controls · %d services · %d chains · %d operational\n",
		s.Controls, s.Services, s.Chains, s.Operational)
	fmt.Fprintf(w, "Severity (control groups only; %d chains, %d operational not rated): %s\n\n",
		s.Chains, s.Operational, severityHistogram(s))

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	header := "SERVICE\tCAPS\tCONTROLS\tMAX SEVERITY"
	if r.wide {
		header += "\tSEVERITIES"
	}
	fmt.Fprintln(tw, header)
	for i := range r.services {
		row := &r.services[i]
		line := fmt.Sprintf("%s\t%d\t%d\t%s",
			strings.ToUpper(row.Service), row.Caps, row.Controls,
			strings.ToUpper(row.MaxSev.String()))
		if r.wide {
			line += "\t" + sevBreakdown(row.Sev)
		}
		fmt.Fprintln(tw, line)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush catalog table: %w", err)
	}
	fmt.Fprintln(w, "\nDrill in:  stave capabilities catalog <SERVICE>")
	fmt.Fprintln(w, `Search:    stave search "<intent>"`)
	return nil
}

// sevBreakdown renders a compact per-severity tally (highest-first, non-zero
// only) for the wide view, e.g. "crit:2 high:3 med:1". controldef.Severity.
func sevBreakdown(m map[policy.Severity]int) string {
	order := []policy.Severity{
		policy.SeverityCritical, policy.SeverityHigh, policy.SeverityMedium,
		policy.SeverityLow, policy.SeverityInfo,
	}
	short := map[policy.Severity]string{
		policy.SeverityCritical: "crit", policy.SeverityHigh: "high",
		policy.SeverityMedium: "med", policy.SeverityLow: "low", policy.SeverityInfo: "info",
	}
	parts := make([]string, 0, len(order))
	for _, s := range order {
		if n := m[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", short[s], n))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

// severityHistogram renders the control-group severity counts highest-first,
// omitting empty buckets. Operates strictly on controldef.Severity — the counts
// come from CatalogSummary, which never touches pkg/stave.Severity.
func severityHistogram(s appcaps.Summary) string {
	order := []policy.Severity{
		policy.SeverityCritical, policy.SeverityHigh, policy.SeverityMedium,
		policy.SeverityLow, policy.SeverityInfo,
	}
	parts := make([]string, 0, len(order))
	for _, sev := range order {
		if n := s.SeverityHist[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToUpper(sev.String())))
		}
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, " · ")
}

// renderServiceView lists the capabilities of the drilled-in service(s), one
// line each: title, severity, control count.
func renderServiceView(w io.Writer, r catalogReport) error {
	caps := controlGroups(r.Capabilities)
	if r.serviceArg != "" {
		fmt.Fprintf(w, "%s capabilities (%d)\n\n", strings.ToUpper(r.serviceArg), len(caps))
	} else {
		fmt.Fprintf(w, "Control-group capabilities (%d)\n\n", len(caps))
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	header := "CAPABILITY\tSEVERITY\tCONTROLS"
	if r.wide {
		header += "\tCATEGORY\tASSET TYPES"
	}
	fmt.Fprintln(tw, header)
	for i := range caps {
		c := &caps[i]
		line := fmt.Sprintf("%s\t%s\t%d", c.Title, strings.ToUpper(c.Severity), len(c.ControlIDs))
		if r.wide {
			line += "\t" + dash(c.Category) + "\t" + dash(strings.Join(c.AssetTypes, ","))
		}
		fmt.Fprintln(tw, line)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush catalog table: %w", err)
	}
	return nil
}

// renderLeafView lists individual leaf controls (control IDs) for the --leaf /
// --severity drill-down. A --severity filter lists control-group controls only;
// the note makes the exclusion of un-rated chains/operational explicit rather
// than silent.
func renderLeafView(w io.Writer, r catalogReport) error {
	scope := "all services"
	if r.serviceArg != "" {
		scope = strings.ToUpper(r.serviceArg)
		if r.categoryArg != "" {
			scope += "/" + r.categoryArg
		}
	} else if r.categoryArg != "" {
		scope = "category " + r.categoryArg
	}
	if r.sevFilter != "" {
		fmt.Fprintf(w, "Leaf controls — %s, severity %s (%d)\n", scope, strings.ToUpper(r.sevFilter), len(r.leafs))
		fmt.Fprintln(w, "Note: --severity lists control-group controls only; chains and operational features are not severity-rated and are excluded.")
	} else {
		fmt.Fprintf(w, "Leaf controls — %s (%d)\n", scope, len(r.leafs))
	}
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	header := "CONTROL ID\tSEVERITY\tNAME"
	if r.wide {
		header += "\tCATEGORY"
	}
	fmt.Fprintln(tw, header)
	for i := range r.leafs {
		lc := &r.leafs[i]
		line := fmt.Sprintf("%s\t%s\t%s", lc.ID, strings.ToUpper(lc.Severity.String()), dash(lc.Name))
		if r.wide {
			line += "\t" + dash(lc.Category)
		}
		fmt.Fprintln(tw, line)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush catalog table: %w", err)
	}
	return nil
}

// dash renders an empty string as "-" so columns stay aligned and obviously
// empty rather than blank.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// renderKindView lists a single kind (chains or operational), one line each.
func renderKindView(w io.Writer, r catalogReport) error {
	fmt.Fprintf(w, "%d capabilities\n", len(r.Capabilities))
	// Chains and operational features are not service-scoped, so a --service /
	// --category filter excludes all of them. Say so explicitly rather than
	// returning a bare "0 capabilities" — same honesty stance as --severity.
	if r.serviceArg != "" || r.categoryArg != "" {
		fmt.Fprintln(w, "Note: chains and operational features are not service-scoped; --service/--category do not narrow this kind.")
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for i := range r.Capabilities {
		c := &r.Capabilities[i]
		var line string
		switch c.Kind {
		case "chain":
			line = fmt.Sprintf("%s\t[chain]\t%s", c.Title, c.Description)
		case "operational":
			line = fmt.Sprintf("%s\t-\t%s", c.Title, firstSentence(c.Description))
		default:
			line = fmt.Sprintf("%s\t[%s]\t%d controls", c.Title, strings.ToUpper(c.Severity), len(c.ControlIDs))
		}
		if r.wide && c.ExampleCmd != "" {
			line += "\t" + c.ExampleCmd
		}
		fmt.Fprintln(tw, line)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush catalog table: %w", err)
	}
	return nil
}

// controlGroups returns the control_group capabilities, sorted by service then
// title, for the drill-down listing.
func controlGroups(in []appcaps.Capability) []appcaps.Capability {
	out := make([]appcaps.Capability, 0, len(in))
	for i := range in {
		if in[i].Kind == "control_group" {
			out = append(out, in[i])
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func firstSentence(s string) string {
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[:i+1]
	}
	return s
}

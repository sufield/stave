package stave

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	appcaps "github.com/sufield/stave/internal/app/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// CatalogOptions parameterizes [RenderCatalog]. Empty ControlsDir/ChainsDir
// default at the CLI to "controls"/"chains". Format is "json", "wide", or
// "text"/"auto"/"" (the human view). Service/Category/KindFilter/Severity/
// Leaf select the drill-down view.
type CatalogOptions struct {
	Service     string
	Category    string
	KindFilter  string
	Format      string
	ControlsDir string
	ChainsDir   string
	Severity    string
	Taxonomy    string
	Leaf        bool
	Verbose     bool
	Family      string
}

// catalogReport is the JSON-shape contract for `stave capabilities
// catalog`. TotalCapabilities is derived from len(Capabilities); both
// fields are present so JSON consumers don't recompute it.
type catalogReport struct {
	TotalCapabilities int                  `json:"total_capabilities"`
	Capabilities      []appcaps.Capability `json:"capabilities"`

	// View state for the human (text/wide) renderers only. UNEXPORTED so
	// encoding/json never emits them — the JSON contract stays exactly
	// {total_capabilities, capabilities}.
	summary     appcaps.Summary
	services    []appcaps.ServiceRow
	leafs       []appcaps.LeafControl
	mode        catalogViewMode
	serviceArg  string
	categoryArg string
	sevFilter   string
	wide        bool
	verbose     bool
	family      string
}

// catalogViewMode selects the human-readable view. JSON is unaffected.
type catalogViewMode int

const (
	catalogViewSummary catalogViewMode = iota // header + one line per service
	catalogViewService                        // one service's capabilities
	catalogViewKind                           // a single --kind listing
	catalogViewLeaf                           // leaf controls (--leaf / --severity)
)

// RenderCatalog loads the control + chain catalogs, builds the grouped
// capability view, applies the service/category/kind/severity filters and
// drill-down mode, and renders the result as JSON, the human table, or its
// wide variant. Invalid --kind/--severity values wrap [ErrInvalidInput]
// (exit 2); loader failures stay plain (exit 4). It is the library entry
// point behind `stave capabilities catalog`.
func RenderCatalog(ctx context.Context, opts CatalogOptions) ([]byte, error) {
	if opts.Family != "" && opts.KindFilter == "" {
		opts.KindFilter = "chain"
	}
	switch opts.KindFilter {
	case "", "control_group", "chain", "operational":
	default:
		return nil, fmt.Errorf("--kind must be control_group | chain | operational (got %q): %w", opts.KindFilter, ErrInvalidInput)
	}
	if opts.Severity != "" {
		if sev, perr := policy.ParseSeverity(opts.Severity); perr != nil || !sev.IsValid() {
			return nil, fmt.Errorf("--severity must be critical | high | medium | low | info (got %q): %w", opts.Severity, ErrInvalidInput)
		}
	}

	controls, err := loadControlsFromDir(ctx, opts.ControlsDir)
	if err != nil {
		return nil, err
	}
	chains, err := loadChainsOptional(opts.ChainsDir)
	if err != nil {
		return nil, err
	}

	catalog := appcaps.Build(controls, chains)
	catalog = catalogFilter(catalog, opts)

	mode := catalogResolveView(opts)
	var leafs []appcaps.LeafControl
	if mode == catalogViewLeaf {
		leafs = appcaps.LeafControls(controls, opts.Service, opts.Category, opts.Severity, opts.Taxonomy)
	}

	report := catalogReport{
		TotalCapabilities: len(catalog),
		Capabilities:      catalog,
		summary:           appcaps.CatalogSummary(controls, chains),
		services:          appcaps.ServiceRollup(controls),
		leafs:             leafs,
		mode:              mode,
		serviceArg:        opts.Service,
		categoryArg:       opts.Category,
		sevFilter:         opts.Severity,
		verbose:           opts.Verbose,
		family:            opts.Family,
	}

	var buf bytes.Buffer
	switch opts.Format {
	case "json":
		if err := jsonutil.WriteIndented(&buf, report); err != nil {
			return nil, fmt.Errorf("render catalog: %w", err)
		}
	case "wide":
		report.wide = true
		if err := renderCatalogView(&buf, report); err != nil {
			return nil, fmt.Errorf("render catalog: %w", err)
		}
	default: // text, auto, ""
		if err := renderCatalogView(&buf, report); err != nil {
			return nil, fmt.Errorf("render catalog: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// catalogResolveView maps the flags to a human-view mode.
func catalogResolveView(opts CatalogOptions) catalogViewMode {
	switch {
	case opts.Leaf || opts.Severity != "" || opts.Taxonomy != "":
		return catalogViewLeaf
	case opts.KindFilter == "chain" || opts.KindFilter == "operational":
		return catalogViewKind
	case opts.Service != "" || opts.Category != "" || opts.KindFilter == "control_group":
		return catalogViewService
	default:
		return catalogViewSummary
	}
}

func catalogFilter(in []appcaps.Capability, opts CatalogOptions) []appcaps.Capability {
	out := make([]appcaps.Capability, 0, len(in))
	for i := range in {
		c := &in[i]
		if opts.KindFilter != "" && c.Kind != opts.KindFilter {
			continue
		}
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

// renderCatalogView dispatches the human-readable output by mode.
func renderCatalogView(w io.Writer, r catalogReport) error {
	switch r.mode {
	case catalogViewService:
		return renderCatalogServiceView(w, r)
	case catalogViewKind:
		return renderCatalogKindView(w, r)
	case catalogViewLeaf:
		return renderCatalogLeafView(w, r)
	default:
		return renderCatalogSummaryView(w, r)
	}
}

func renderCatalogSummaryView(w io.Writer, r catalogReport) error {
	s := r.summary
	fmt.Fprintf(w, "Stave: %d controls · %d services · %d chains · %d operational\n",
		s.Controls, s.Services, s.Chains, s.Operational)
	fmt.Fprintf(w, "Severity (control groups only; %d chains, %d operational not rated): %s\n\n",
		s.Chains, s.Operational, catalogSeverityHistogram(s))

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
			line += "\t" + catalogSevBreakdown(row.Sev)
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

// catalogSeverityOrder is the fixed highest-first severity ordering shared by
// the catalog severity renderers. Package-level so the literal is not
// re-allocated on every render call.
var catalogSeverityOrder = []policy.Severity{
	policy.SeverityCritical, policy.SeverityHigh, policy.SeverityMedium,
	policy.SeverityLow, policy.SeverityInfo,
}

// catalogSevShort maps severities to their compact wide-view labels.
var catalogSevShort = map[policy.Severity]string{
	policy.SeverityCritical: "crit", policy.SeverityHigh: "high",
	policy.SeverityMedium: "med", policy.SeverityLow: "low", policy.SeverityInfo: "info",
}

// catalogSevBreakdown renders a compact per-severity tally (highest-first,
// non-zero only) for the wide view, e.g. "crit:2 high:3 med:1".
func catalogSevBreakdown(m map[policy.Severity]int) string {
	parts := make([]string, 0, len(catalogSeverityOrder))
	for _, s := range catalogSeverityOrder {
		if n := m[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", catalogSevShort[s], n))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

// catalogSeverityHistogram renders the control-group severity counts
// highest-first, omitting empty buckets.
func catalogSeverityHistogram(s appcaps.Summary) string {
	parts := make([]string, 0, len(catalogSeverityOrder))
	for _, sev := range catalogSeverityOrder {
		if n := s.SeverityHist[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToUpper(sev.String())))
		}
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, " · ")
}

func renderCatalogServiceView(w io.Writer, r catalogReport) error {
	caps := catalogControlGroups(r.Capabilities)
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
			line += "\t" + catalogDash(c.Category) + "\t" + catalogDash(strings.Join(c.AssetTypes, ","))
		}
		fmt.Fprintln(tw, line)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush catalog table: %w", err)
	}
	return nil
}

func renderCatalogLeafView(w io.Writer, r catalogReport) error {
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
		line := fmt.Sprintf("%s\t%s\t%s", lc.ID, strings.ToUpper(lc.Severity.String()), catalogDash(lc.Name))
		if r.wide {
			line += "\t" + catalogDash(lc.Category)
		}
		fmt.Fprintln(tw, line)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush catalog table: %w", err)
	}
	return nil
}

// catalogDash renders an empty string as "-" so columns stay aligned.
func catalogDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func renderCatalogKindView(w io.Writer, r catalogReport) error {
	chains := catalogChains(r.Capabilities)
	if len(chains) > 0 && !hasNonChains(r.Capabilities) {
		return renderCatalogChainView(w, r, chains)
	}
	fmt.Fprintf(w, "%d capabilities\n", len(r.Capabilities))
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
			line = fmt.Sprintf("%s\t-\t%s", c.Title, catalogFirstSentence(c.Description))
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

func hasNonChains(caps []appcaps.Capability) bool {
	for i := range caps {
		if caps[i].Kind != "chain" {
			return true
		}
	}
	return false
}

func catalogChains(caps []appcaps.Capability) []appcaps.Capability {
	out := make([]appcaps.Capability, 0, len(caps))
	for i := range caps {
		if caps[i].Kind == "chain" {
			out = append(out, caps[i])
		}
	}
	return out
}

type chainFamily struct {
	name   string
	chains []appcaps.Capability
}

func chainFamilyKey(c *appcaps.Capability) string {
	if len(c.ChainIDs) == 0 {
		return "other"
	}
	id := c.ChainIDs[0]
	first, _, ok := strings.Cut(id, "_")
	if !ok {
		return id
	}
	return first
}

func groupChainsByFamily(chains []appcaps.Capability) []chainFamily {
	idx := map[string]int{}
	var families []chainFamily
	for i := range chains {
		key := chainFamilyKey(&chains[i])
		if fi, ok := idx[key]; ok {
			families[fi].chains = append(families[fi].chains, chains[i])
		} else {
			idx[key] = len(families)
			families = append(families, chainFamily{
				name:   humaniseChainFamily(key),
				chains: []appcaps.Capability{chains[i]},
			})
		}
	}
	slices.SortFunc(families, func(a, b chainFamily) int {
		return cmp.Compare(a.name, b.name)
	})
	for i := range families {
		slices.SortFunc(families[i].chains, func(a, b appcaps.Capability) int {
			sa := chainSevRank(a.Severity)
			sb := chainSevRank(b.Severity)
			if sa != sb {
				return cmp.Compare(sb, sa) // descending severity
			}
			return cmp.Compare(a.Title, b.Title)
		})
	}
	return families
}

func humaniseChainFamily(key string) string {
	if key == "" {
		return "Other"
	}
	var b strings.Builder
	b.Grow(len(key))
	capitalizeNext := true
	for i := 0; i < len(key); i++ {
		ch := key[i]
		if ch == '_' {
			b.WriteByte(' ')
			capitalizeNext = true
		} else if capitalizeNext {
			if ch >= 'a' && ch <= 'z' {
				b.WriteByte(ch - 'a' + 'A')
			} else {
				b.WriteByte(ch)
			}
			capitalizeNext = false
		} else {
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func chainSevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func chainSevTag(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "CRIT"
	case "high":
		return "HIGH"
	case "medium":
		return "MED "
	case "low":
		return "LOW "
	default:
		return "    "
	}
}

func truncateDescription(s string, limit int) string {
	flat := strings.Join(strings.Fields(s), " ")
	if len(flat) <= limit {
		return flat
	}
	return flat[:limit-1] + "…"
}

func renderCatalogChainView(w io.Writer, r catalogReport, chains []appcaps.Capability) error {
	families := groupChainsByFamily(chains)
	if r.family != "" {
		filtered := families[:0]
		for i := range families {
			key := strings.ToLower(families[i].name)
			query := strings.ToLower(r.family)
			if key == query || strings.HasPrefix(key, query) {
				filtered = append(filtered, families[i])
			}
		}
		families = filtered
	}

	total := 0
	sevCounts := map[string]int{}
	for i := range families {
		for j := range families[i].chains {
			total++
			sev := strings.ToLower(families[i].chains[j].Severity)
			if sev != "" {
				sevCounts[sev]++
			}
		}
	}

	fmt.Fprintf(w, "CHAINS BY FAMILY%*sTOTAL: %d\n\n", 39, " ", total)

	for i := range families {
		fam := &families[i]
		header := fmt.Sprintf("── %s (%d) ", fam.name, len(fam.chains))
		pad := max(65-len(header), 3)
		fmt.Fprintf(w, "%s%s\n", header, strings.Repeat("─", pad))

		for j := range fam.chains {
			c := &fam.chains[j]
			tag := chainSevTag(c.Severity)
			desc := c.Description
			if !r.verbose {
				desc = truncateDescription(desc, 45)
			}
			fmt.Fprintf(w, "  %s  %-34s  %s\n", tag, c.Title, desc)
		}
		fmt.Fprintln(w)
	}

	var footer strings.Builder
	fmt.Fprintf(&footer, "%d chains", total)
	parts := make([]string, 0, 4)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := sevCounts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(&footer, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w, footer.String())
	if !r.verbose {
		fmt.Fprintln(w, "Use --verbose for full descriptions")
	}
	return nil
}

// catalogControlGroups returns the control_group capabilities, sorted by
// service then title.
func catalogControlGroups(in []appcaps.Capability) []appcaps.Capability {
	out := make([]appcaps.Capability, 0, len(in))
	for i := range in {
		if in[i].Kind == "control_group" {
			out = append(out, in[i])
		}
	}
	slices.SortFunc(out, func(a, b appcaps.Capability) int {
		return cmp.Or(
			cmp.Compare(a.Service, b.Service),
			cmp.Compare(a.Title, b.Title),
		)
	})
	return out
}

func catalogFirstSentence(s string) string {
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[:i+1]
	}
	return s
}

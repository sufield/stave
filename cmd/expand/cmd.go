// Package expand implements the `stave expand` command, which surfaces
// every control sharing a structural defect archetype with a given finding
// (or with a directly-specified archetype). The command is read-only:
// it loads the control catalog and groups it by archetype.
package expand

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/controls/archetype"
	"github.com/sufield/stave/internal/app/expand"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

type options struct {
	Archetype   string
	Finding     string
	List        bool
	Format      string
	Snapshots   string
	ControlsDir string
}

// NewCmd constructs the expand command.
func NewCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "expand",
		Short: "Show every control sharing a structural defect archetype",
		Long: `Expand a finding or archetype into the family of controls that
detect the same class of structural defect across services.

When a single finding fires, its archetype identifies every other place
the same defect can manifest in your infrastructure. Use --finding to
pivot from a specific control, --archetype to start from a known class,
or --list to see all archetypes.

Inputs:
  --archetype <id>     Archetype ID (e.g., ghost-reference)
  --finding <id>       Control ID to look up the archetype from
  --list               List all archetypes with control counts
  --format text|json   Output format (default: text)
  --snapshots <dir>    Path to observations dir (optional; enables
                       snapshot coverage section)
  --controls <dir>     Control definitions directory (default: controls)

Outputs:
  stdout: archetype summary, controls grouped by service, optional
          snapshot coverage and recommended commands.
  stderr: errors only.

Exit codes:
  0   success
  2   input error (missing flags, unknown archetype/finding)
  4   internal error (control loader failure)
  130 SIGINT
`,
		Example: `  # List all archetypes with control counts
  stave expand --list

  # Expand an archetype into its control family
  stave expand --archetype ghost-reference

  # Pivot from a known finding to its sibling controls
  stave expand --finding CTL.ROUTE53.DANGLING.S3.001

  # JSON output for tooling
  stave expand --archetype ghost-reference --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runExpand(cmd.Context(), cmd.OutOrStdout(), opts, newCtlRepo)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.Archetype, "archetype", "", "archetype ID to expand (e.g., ghost-reference)")
	flags.StringVar(&opts.Finding, "finding", "", "control ID to expand from (e.g., CTL.ROUTE53.DANGLING.S3.001)")
	flags.BoolVar(&opts.List, "list", false, "list all archetypes with control counts")
	flags.StringVarP(&opts.Format, "format", "f", "text", "output format: text or json")
	flags.StringVar(&opts.Snapshots, "snapshots", "", "observations directory for snapshot coverage check")
	flags.StringVarP(&opts.ControlsDir, cliflags.FlagControls, "i", "controls", "control definitions directory")

	cmd.MarkFlagsMutuallyExclusive("archetype", "finding", "list")

	return cmd
}

func runExpand(ctx context.Context, w io.Writer, opts *options, newCtlRepo compose.CtlRepoFactory) error {
	if opts.Archetype == "" && opts.Finding == "" && !opts.List {
		return inputErrorf("one of --archetype, --finding, or --list is required")
	}
	if opts.Format != "text" && opts.Format != "json" {
		return inputErrorf("--format must be text or json (got %q)", opts.Format)
	}

	controls, err := compose.LoadControlsFrom(ctx, newCtlRepo, opts.ControlsDir)
	if err != nil {
		return internalErrorf("load controls: %w", err)
	}

	if opts.List {
		return renderList(w, opts.Format, controls)
	}

	archID := opts.Archetype
	var finding *policy.ControlDefinition
	if opts.Finding != "" {
		ctlID := kernel.ControlID(opts.Finding)
		for i := range controls {
			if controls[i].ID == ctlID {
				finding = &controls[i]
				break
			}
		}
		if finding == nil {
			return inputErrorf("control %q not found in %s", opts.Finding, opts.ControlsDir)
		}
		if finding.Archetype.IsEmpty() {
			return inputErrorf("control %q has no archetype field", opts.Finding)
		}
		archID = finding.Archetype.String()
	}

	arch, ok := archetype.Lookup(archID)
	if !ok {
		return inputErrorf("unknown archetype %q (use --list to see catalog)", archID)
	}

	matched := expand.FilterByArchetype(controls, archID)
	snap := expand.ScanSnapshots(opts.Snapshots, arch.Services)

	switch opts.Format {
	case "json":
		return renderJSON(w, arch, matched, snap, finding)
	default:
		return renderText(w, arch, matched, snap, finding)
	}
}

// renderText writes the human-readable form of a single-archetype expand.
func renderText(w io.Writer, arch archetype.Archetype, matched []policy.ControlDefinition, snap *expand.SnapshotStatus, finding *policy.ControlDefinition) error {
	if finding != nil {
		fmt.Fprintf(w, "Finding: %s\n", finding.ID)
		if finding.Name != "" {
			fmt.Fprintf(w, "  %s\n\n", finding.Name)
		} else {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "This is an instance of the %s archetype.\n\n", arch.Name)
	}

	fmt.Fprintf(w, "Archetype: %s\n\n", arch.Name)
	fmt.Fprintln(w, wrapParagraph(arch.Description, 70))
	fmt.Fprintln(w)
	fmt.Fprintln(w, wrapParagraph(arch.Guidance, 70))
	fmt.Fprintln(w)

	if len(matched) == 0 {
		fmt.Fprintln(w, "Controls in this archetype: (none yet — no controls have been")
		fmt.Fprintln(w, "tagged with this archetype in the loaded catalog).")
	} else {
		fmt.Fprintln(w, "Controls in this archetype:")
		fmt.Fprintln(w)
		groups := groupByService(matched)
		for _, svc := range sortedKeys(groups) {
			ctls := groups[svc]
			fmt.Fprintf(w, "  %s (%d control%s)\n", svc, len(ctls), plural(len(ctls)))
			for i := range ctls {
				ctl := &ctls[i]
				prefix := "├──"
				if i == len(ctls)-1 {
					prefix = "└──"
				}
				fmt.Fprintf(w, "  %s %s — %s [%s]\n",
					prefix, ctl.ID, oneLineSummary(ctl), strings.ToLower(ctl.Severity.String()))
			}
			fmt.Fprintln(w)
		}
	}

	if snap != nil {
		fmt.Fprintln(w, "Snapshot coverage:")
		fmt.Fprintln(w)
		all := append(append([]string{}, snap.Found...), snap.Missing...)
		sort.Strings(all)
		foundSet := make(map[string]bool, len(snap.Found))
		for _, s := range snap.Found {
			foundSet[s] = true
		}
		for _, svc := range all {
			if foundSet[svc] {
				fmt.Fprintf(w, "  ✓ %-15s snapshot found\n", svc)
			} else {
				fmt.Fprintf(w, "  ✗ %-15s no snapshot — run: stave snapshot %s\n", svc, svc)
			}
		}
		if len(snap.Missing) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Generate missing snapshots, then re-run:")
			fmt.Fprintln(w, "  stave verify")
		}
	}

	return nil
}

// renderJSON emits the structured form of a single-archetype expand.
func renderJSON(w io.Writer, arch archetype.Archetype, matched []policy.ControlDefinition, snap *expand.SnapshotStatus, finding *policy.ControlDefinition) error {
	type controlEntry struct {
		ID       string `json:"id"`
		Service  string `json:"service"`
		Severity string `json:"severity"`
		Summary  string `json:"summary"`
	}
	type payload struct {
		Finding          *findingEntry          `json:"finding,omitempty"`
		Archetype        archetypeEntry         `json:"archetype"`
		Controls         []controlEntry         `json:"controls"`
		ServicesAffected []string               `json:"services_affected"`
		SnapshotStatus   *expand.SnapshotStatus `json:"snapshot_status,omitempty"`
		SnapshotCommands []string               `json:"snapshot_commands,omitempty"`
	}

	out := payload{
		Archetype: archetypeEntry{
			ID:          arch.ID.String(),
			Name:        arch.Name,
			Description: arch.Description,
			Guidance:    arch.Guidance,
		},
		Controls: make([]controlEntry, 0, len(matched)),
	}

	if finding != nil {
		out.Finding = &findingEntry{ID: string(finding.ID), Name: finding.Name}
	}

	groups := groupByService(matched)
	out.ServicesAffected = sortedKeys(groups)
	for _, svc := range out.ServicesAffected {
		ctls := groups[svc]
		for i := range ctls {
			ctl := &ctls[i]
			out.Controls = append(out.Controls, controlEntry{
				ID:       string(ctl.ID),
				Service:  svc,
				Severity: strings.ToLower(ctl.Severity.String()),
				Summary:  oneLineSummary(ctl),
			})
		}
	}

	if snap != nil {
		out.SnapshotStatus = snap
		for _, svc := range snap.Missing {
			out.SnapshotCommands = append(out.SnapshotCommands, "stave snapshot "+svc)
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

type archetypeEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Guidance    string `json:"guidance"`
}

type findingEntry struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// renderList writes the catalog summary in text or JSON form.
func renderList(w io.Writer, format string, controls []policy.ControlDefinition) error {
	counts := make(map[string]int, len(archetype.Catalog))
	for i := range controls {
		if !controls[i].Archetype.IsEmpty() {
			counts[controls[i].Archetype.String()]++
		}
	}

	if format == "json" {
		type entry struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			Description  string `json:"description"`
			ControlCount int    `json:"control_count"`
		}
		out := make([]entry, 0, len(archetype.Catalog))
		for _, a := range archetype.Catalog {
			out = append(out, entry{
				ID:           a.ID.String(),
				Name:         a.Name,
				Description:  a.Description,
				ControlCount: counts[a.ID.String()],
			})
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"archetypes": out})
	}

	fmt.Fprintln(w, "Archetypes:")
	fmt.Fprintln(w)
	for _, a := range archetype.Catalog {
		short := firstSentence(a.Description)
		fmt.Fprintf(w, "  %-23s %s — %s (%d controls)\n", a.ID, a.Name, short, counts[a.ID.String()])
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use: stave expand --archetype <id>")
	return nil
}

// --- internal helpers ---

func groupByService(ctls []policy.ControlDefinition) map[string][]policy.ControlDefinition {
	out := make(map[string][]policy.ControlDefinition)
	for i := range ctls {
		svc := expand.ServiceFromControlID(ctls[i].ID)
		out[svc] = append(out[svc], ctls[i])
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func oneLineSummary(ctl *policy.ControlDefinition) string {
	// Prefer the authored Defect (one sentence triage); fall back to Name.
	if ctl.HasDiagnosis() {
		return firstSentence(ctl.Defect)
	}
	return ctl.Name
}

// firstSentence returns the text up to the first period or newline,
// trimmed. Whitespace is collapsed so multi-line YAML folded scalars
// render as a single readable line.
func firstSentence(s string) string {
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if i := strings.IndexAny(s, ".\n"); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// wrapParagraph soft-wraps a paragraph at the given width on word boundaries.
// Newlines in the input are preserved as paragraph breaks.
func wrapParagraph(s string, width int) string {
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if s == "" {
		return ""
	}
	var lines []string
	words := strings.Fields(s)
	var cur strings.Builder
	for _, word := range words {
		if cur.Len() == 0 {
			cur.WriteString(word)
			continue
		}
		if cur.Len()+1+len(word) > width {
			lines = append(lines, cur.String())
			cur.Reset()
			cur.WriteString(word)
			continue
		}
		cur.WriteByte(' ')
		cur.WriteString(word)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return strings.Join(lines, "\n")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// --- error helpers — exit codes 2 (user input) and 4 (internal) ---

func inputErrorf(format string, args ...any) error {
	return &ui.UserError{Err: fmt.Errorf(format, args...)}
}

// internalErrorf returns a plain wrapped error: the executor maps
// unclassified errors to exit code 4 and renders the message to stderr.
// Wrapping ui.ErrInternal would suppress the message via the sentinel
// filter, which is the wrong shape for runtime failures the user can act
// on (missing controls dir, parse errors, etc.).
func internalErrorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

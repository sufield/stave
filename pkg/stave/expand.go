package stave

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/adapters/controls/archetype"
	"github.com/sufield/stave/internal/app/expand"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ExpandList loads the control catalog from controlsDir and renders the
// archetype catalog summary (control counts per archetype) in the
// requested format ("json" or "text"/""). A control-loader failure stays
// plain (exit 4). It is the library entry point behind
// `stave expand --list`.
func ExpandList(ctx context.Context, controlsDir, format string) ([]byte, error) {
	controls, err := loadControlsFromDir(ctx, controlsDir)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}
	return renderExpandList(controls, format)
}

// ExpandArchetype loads the control catalog from controlsDir and expands a
// single archetype — identified directly by archetypeID or resolved from a
// findingID (control ID) — into its control family, with optional snapshot
// coverage from snapshotsDir. Output is rendered in the requested format
// ("json" or "text"/""). A control-loader failure stays plain (exit 4);
// unresolvable findings/archetypes wrap [ErrInvalidInput] (exit 2). It is
// the library entry point behind `stave expand`.
func ExpandArchetype(ctx context.Context, controlsDir, archetypeID, findingID, snapshotsDir, format string) ([]byte, error) {
	controls, err := loadControlsFromDir(ctx, controlsDir)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}
	return expandArchetypeFromControls(controls, controlsDir, archetypeID, findingID, snapshotsDir, format)
}

// expandArchetypeFromControls is the resolve+filter+scan+render core,
// split out so it can be unit-tested with a hand-built control set.
func expandArchetypeFromControls(controls []policy.ControlDefinition, controlsDir, archetypeID, findingID, snapshotsDir, format string) ([]byte, error) {
	archID := archetypeID
	var finding *policy.ControlDefinition
	if findingID != "" {
		ctlID := kernel.ControlID(findingID)
		for i := range controls {
			if controls[i].ID == ctlID {
				finding = &controls[i]
				break
			}
		}
		if finding == nil {
			return nil, fmt.Errorf("control %q not found in %s: %w", findingID, controlsDir, ErrInvalidInput)
		}
		if finding.Archetype.IsEmpty() {
			return nil, fmt.Errorf("control %q has no archetype field: %w", findingID, ErrInvalidInput)
		}
		archID = finding.Archetype.String()
	}

	arch, ok := archetype.Lookup(archID)
	if !ok {
		return nil, fmt.Errorf("unknown archetype %q (use --list to see catalog): %w", archID, ErrInvalidInput)
	}

	matched := expand.FilterByArchetype(controls, kernel.ArchetypeID(archID))
	snap := expand.ScanSnapshots(snapshotsDir, arch.Services)

	var buf bytes.Buffer
	if format == "json" {
		if err := renderExpandJSON(&buf, arch, matched, snap, finding); err != nil {
			return nil, fmt.Errorf("render expansion: %w", err)
		}
	} else {
		renderExpandText(&buf, arch, matched, snap, finding)
	}
	return buf.Bytes(), nil
}

func renderExpandList(controls []policy.ControlDefinition, format string) ([]byte, error) {
	var buf bytes.Buffer
	if format == "json" {
		if err := renderExpandListJSON(&buf, controls); err != nil {
			return nil, fmt.Errorf("render expansion: %w", err)
		}
	} else {
		renderExpandListText(&buf, controls)
	}
	return buf.Bytes(), nil
}

// renderExpandText writes the human-readable form of a single-archetype expand.
func renderExpandText(w io.Writer, arch archetype.Archetype, matched []policy.ControlDefinition, snap *expand.SnapshotStatus, finding *policy.ControlDefinition) {
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
		for _, svc := range slices.Sorted(maps.Keys(groups)) {
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
		slices.Sort(all)
		foundSet := make(map[string]struct{}, len(snap.Found))
		for _, s := range snap.Found {
			foundSet[s] = struct{}{}
		}
		for _, svc := range all {
			if _, ok := foundSet[svc]; ok {
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
}

// renderExpandJSON emits the structured form of a single-archetype expand.
func renderExpandJSON(w io.Writer, arch archetype.Archetype, matched []policy.ControlDefinition, snap *expand.SnapshotStatus, finding *policy.ControlDefinition) error {
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
	out.ServicesAffected = slices.Sorted(maps.Keys(groups))
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

// renderExpandListJSON emits the catalog summary in JSON form.
func renderExpandListJSON(w io.Writer, controls []policy.ControlDefinition) error {
	counts := archetypeCounts(controls)

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

// renderExpandListText writes the catalog summary in human-readable text form.
func renderExpandListText(w io.Writer, controls []policy.ControlDefinition) {
	counts := archetypeCounts(controls)

	fmt.Fprintln(w, "Archetypes:")
	fmt.Fprintln(w)
	for _, a := range archetype.Catalog {
		short := firstSentence(a.Description)
		fmt.Fprintf(w, "  %-23s %s — %s (%d controls)\n", a.ID, a.Name, short, counts[a.ID.String()])
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use: stave expand --archetype <id>")
}

// archetypeCounts tallies controls per archetype ID, skipping controls
// with no archetype field.
func archetypeCounts(controls []policy.ControlDefinition) map[string]int {
	counts := make(map[string]int, len(archetype.Catalog))
	for i := range controls {
		if !controls[i].Archetype.IsEmpty() {
			counts[controls[i].Archetype.String()]++
		}
	}
	return counts
}

func groupByService(ctls []policy.ControlDefinition) map[string][]policy.ControlDefinition {
	out := make(map[string][]policy.ControlDefinition)
	for i := range ctls {
		svc := expand.ServiceFromControlID(ctls[i].ID)
		out[svc] = append(out[svc], ctls[i])
	}
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

// wrapParagraph soft-wraps a paragraph at the given width on word
// boundaries. Newlines in the input are preserved as paragraph breaks.
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

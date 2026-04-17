// Package catalogdiff computes the impact of upgrading between
// two control catalog versions against a snapshot.
package catalogdiff

import (
	"slices"
	"sort"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Delta describes the difference between two catalog versions.
type Delta struct {
	CatalogBefore   int              `json:"catalog_before_count"`
	CatalogAfter    int              `json:"catalog_after_count"`
	NewControls     []string         `json:"new_controls"`
	RemovedControls []string         `json:"removed_controls"`
	SeverityChanges []SeverityChange `json:"severity_changes,omitempty"`
}

// SeverityChange records a control whose severity changed.
type SeverityChange struct {
	ControlID string `json:"control_id"`
	Before    string `json:"before"`
	After     string `json:"after"`
}

// Compute produces a Delta from two sets of control definitions.
func Compute(before, after []policy.ControlDefinition) *Delta {
	beforeMap := make(map[kernel.ControlID]*policy.ControlDefinition, len(before))
	for i := range before {
		beforeMap[before[i].ID] = &before[i]
	}
	afterMap := make(map[kernel.ControlID]*policy.ControlDefinition, len(after))
	for i := range after {
		afterMap[after[i].ID] = &after[i]
	}

	var newControls, removedControls []string
	var sevChanges []SeverityChange

	// New controls: in after, not in before.
	for id := range afterMap {
		if _, ok := beforeMap[id]; !ok {
			newControls = append(newControls, string(id))
		}
	}

	// Removed controls: in before, not in after.
	for id := range beforeMap {
		if _, ok := afterMap[id]; !ok {
			removedControls = append(removedControls, string(id))
		}
	}

	// Severity changes: in both, different severity.
	for id, ctlB := range beforeMap {
		if ctlA, ok := afterMap[id]; ok {
			if ctlB.Severity != ctlA.Severity {
				sevChanges = append(sevChanges, SeverityChange{
					ControlID: string(id),
					Before:    ctlB.Severity.String(),
					After:     ctlA.Severity.String(),
				})
			}
		}
	}

	slices.Sort(newControls)
	slices.Sort(removedControls)
	sort.Slice(sevChanges, func(i, j int) bool {
		return sevChanges[i].ControlID < sevChanges[j].ControlID
	})

	return &Delta{
		CatalogBefore:   len(before),
		CatalogAfter:    len(after),
		NewControls:     newControls,
		RemovedControls: removedControls,
		SeverityChanges: sevChanges,
	}
}

// FormatTable produces a human-readable diff summary.
func FormatTable(d *Delta) string {
	var b strings.Builder
	b.WriteString("CATALOG UPGRADE IMPACT ANALYSIS\n")
	b.WriteString(strings.Repeat("-", 50) + "\n")
	if len(d.NewControls) > 0 {
		b.WriteString("\nNEW CONTROLS\n")
		for _, c := range d.NewControls {
			b.WriteString("  + " + c + "\n")
		}
	}
	if len(d.RemovedControls) > 0 {
		b.WriteString("\nREMOVED CONTROLS\n")
		for _, c := range d.RemovedControls {
			b.WriteString("  - " + c + "\n")
		}
	}
	if len(d.SeverityChanges) > 0 {
		b.WriteString("\nSEVERITY CHANGES\n")
		for _, sc := range d.SeverityChanges {
			b.WriteString("  " + sc.ControlID + ": " + sc.Before + " → " + sc.After + "\n")
		}
	}
	return b.String()
}

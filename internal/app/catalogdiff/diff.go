// Package catalogdiff computes the impact of upgrading between
// two control catalog versions against a snapshot.
package catalogdiff

import (
	"cmp"
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// SeverityChange records a control whose severity changed.
type SeverityChange struct {
	ControlID kernel.ControlID `json:"control_id"`
	Before    policy.Severity  `json:"before"`
	After     policy.Severity  `json:"after"`
}

// SeverityChanges is a domain collection of SeverityChange items with querying methods.
type SeverityChanges []SeverityChange

// Len returns the number of severity changes in the collection.
func (scs SeverityChanges) Len() int {
	return len(scs)
}

// Escalated returns severity changes where severity increased (e.g. Medium -> High).
func (scs SeverityChanges) Escalated() SeverityChanges {
	if len(scs) == 0 {
		return nil
	}
	var filtered SeverityChanges
	for i := range scs {
		if scs[i].After > scs[i].Before {
			filtered = append(filtered, scs[i])
		}
	}
	return filtered
}

// Deescalated returns severity changes where severity decreased (e.g. High -> Medium).
func (scs SeverityChanges) Deescalated() SeverityChanges {
	if len(scs) == 0 {
		return nil
	}
	var filtered SeverityChanges
	for i := range scs {
		if scs[i].After < scs[i].Before {
			filtered = append(filtered, scs[i])
		}
	}
	return filtered
}

// Delta describes the difference between two catalog versions.
type Delta struct {
	CatalogBefore   int                `json:"catalog_before_count"`
	CatalogAfter    int                `json:"catalog_after_count"`
	NewControls     []kernel.ControlID `json:"new_controls"`
	RemovedControls []kernel.ControlID `json:"removed_controls"`
	SeverityChanges SeverityChanges    `json:"severity_changes,omitempty"`
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

	var newControls, removedControls []kernel.ControlID
	var sevChanges []SeverityChange

	// New controls: in after, not in before.
	for id := range afterMap {
		if _, ok := beforeMap[id]; !ok {
			newControls = append(newControls, id)
		}
	}

	// Removed controls: in before, not in after.
	for id := range beforeMap {
		if _, ok := afterMap[id]; !ok {
			removedControls = append(removedControls, id)
		}
	}

	// Severity changes: in both, different severity.
	for id, ctlB := range beforeMap {
		if ctlA, ok := afterMap[id]; ok {
			if ctlB.Severity != ctlA.Severity {
				sevChanges = append(sevChanges, SeverityChange{
					ControlID: id,
					Before:    ctlB.Severity,
					After:     ctlA.Severity,
				})
			}
		}
	}

	slices.Sort(newControls)
	slices.Sort(removedControls)
	slices.SortFunc(sevChanges, func(a, b SeverityChange) int {
		return cmp.Compare(string(a.ControlID), string(b.ControlID))
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
	if d == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("CATALOG UPGRADE IMPACT ANALYSIS\n")
	b.WriteString(strings.Repeat("-", 50) + "\n")
	if len(d.NewControls) > 0 {
		b.WriteString("\nNEW CONTROLS\n")
		for _, c := range d.NewControls {
			b.WriteString("  + " + string(c) + "\n")
		}
	}
	if len(d.RemovedControls) > 0 {
		b.WriteString("\nREMOVED CONTROLS\n")
		for _, c := range d.RemovedControls {
			b.WriteString("  - " + string(c) + "\n")
		}
	}
	if len(d.SeverityChanges) > 0 {
		b.WriteString("\nSEVERITY CHANGES\n")
		for _, sc := range d.SeverityChanges {
			b.WriteString("  " + string(sc.ControlID) + ": " + sc.Before.String() + " → " + sc.After.String() + "\n")
		}
	}
	return b.String()
}

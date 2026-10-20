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

// IsEscalated reports whether the control severity increased.
func (sc SeverityChange) IsEscalated() bool {
	return sc.After > sc.Before
}

// IsDeescalated reports whether the control severity decreased.
func (sc SeverityChange) IsDeescalated() bool {
	return sc.After < sc.Before
}

// String returns a human-readable representation of the severity change.
func (sc SeverityChange) String() string {
	return string(sc.ControlID) + ": " + sc.Before.String() + " → " + sc.After.String()
}

// SeverityChanges is a domain collection of SeverityChange items with querying methods.
type SeverityChanges []SeverityChange

// Len returns the number of severity changes in the collection.
func (scs SeverityChanges) Len() int {
	return len(scs)
}

// IsEmpty reports whether the collection contains no severity changes.
func (scs SeverityChanges) IsEmpty() bool {
	return len(scs) == 0
}

// Escalated returns severity changes where severity increased (e.g. Medium -> High).
func (scs SeverityChanges) Escalated() SeverityChanges {
	if len(scs) == 0 {
		return nil
	}
	var filtered SeverityChanges
	for i := range scs {
		if scs[i].IsEscalated() {
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
		if scs[i].IsDeescalated() {
			filtered = append(filtered, scs[i])
		}
	}
	return filtered
}

// ByControlID returns the severity change for the specified control ID, or nil if not found.
func (scs SeverityChanges) ByControlID(id kernel.ControlID) *SeverityChange {
	for i := range scs {
		if scs[i].ControlID == id {
			return &scs[i]
		}
	}
	return nil
}

// ControlIDs returns the control IDs for all severity changes in the collection.
func (scs SeverityChanges) ControlIDs() ControlIDs {
	if len(scs) == 0 {
		return nil
	}
	ids := make(ControlIDs, len(scs))
	for i, sc := range scs {
		ids[i] = sc.ControlID
	}
	return ids
}

// ControlIDs is a domain collection of ControlID objects with domain querying methods.
type ControlIDs []kernel.ControlID

// Len returns the number of control IDs in the collection.
func (ids ControlIDs) Len() int {
	return len(ids)
}

// IsEmpty reports whether the collection contains no control IDs.
func (ids ControlIDs) IsEmpty() bool {
	return len(ids) == 0
}

// Contains returns true if target control ID is in the list.
func (ids ControlIDs) Contains(target kernel.ControlID) bool {
	return slices.Contains(ids, target)
}

// Strings returns the control IDs as raw strings.
func (ids ControlIDs) Strings() []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

// CatalogCount encapsulates a count of control definitions in a catalog.
type CatalogCount int

// Int returns the raw integer count value.
func (c CatalogCount) Int() int {
	return int(c)
}

// IsEmpty reports whether the catalog control count is zero.
func (c CatalogCount) IsEmpty() bool {
	return c == 0
}

// Delta returns the net change in control count relative to another catalog count.
func (c CatalogCount) Delta(other CatalogCount) int {
	return int(c) - int(other)
}

// Delta describes the difference between two catalog versions.
type Delta struct {
	CatalogBefore   CatalogCount    `json:"catalog_before_count"`
	CatalogAfter    CatalogCount    `json:"catalog_after_count"`
	NewControls     ControlIDs      `json:"new_controls"`
	RemovedControls ControlIDs      `json:"removed_controls"`
	SeverityChanges SeverityChanges `json:"severity_changes,omitempty"`
}

// HasChanges reports whether there are any new, removed, or severity-changed controls.
func (d *Delta) HasChanges() bool {
	return d != nil && (d.HasNew() || d.HasRemoved() || d.HasSeverityChanges())
}

// HasNew reports whether any new controls were introduced.
func (d *Delta) HasNew() bool {
	return d != nil && !d.NewControls.IsEmpty()
}

// HasRemoved reports whether any existing controls were removed.
func (d *Delta) HasRemoved() bool {
	return d != nil && !d.RemovedControls.IsEmpty()
}

// HasSeverityChanges reports whether any controls changed severity.
func (d *Delta) HasSeverityChanges() bool {
	return d != nil && !d.SeverityChanges.IsEmpty()
}

// TotalChanges returns the total number of control additions, removals, and severity changes.
func (d *Delta) TotalChanges() int {
	if d == nil {
		return 0
	}
	return d.NewControls.Len() + d.RemovedControls.Len() + d.SeverityChanges.Len()
}

// NetCountDelta returns the net difference between after and before catalog sizes.
func (d *Delta) NetCountDelta() int {
	if d == nil {
		return 0
	}
	return d.CatalogAfter.Delta(d.CatalogBefore)
}

// IsClean reports whether there were no differences between catalog versions.
func (d *Delta) IsClean() bool {
	return d != nil && !d.HasChanges()
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
		CatalogBefore:   CatalogCount(len(before)),
		CatalogAfter:    CatalogCount(len(after)),
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
	if d.HasNew() {
		b.WriteString("\nNEW CONTROLS\n")
		for _, c := range d.NewControls {
			b.WriteString("  + " + string(c) + "\n")
		}
	}
	if d.HasRemoved() {
		b.WriteString("\nREMOVED CONTROLS\n")
		for _, c := range d.RemovedControls {
			b.WriteString("  - " + string(c) + "\n")
		}
	}
	if d.HasSeverityChanges() {
		b.WriteString("\nSEVERITY CHANGES\n")
		for _, sc := range d.SeverityChanges {
			b.WriteString("  " + sc.String() + "\n")
		}
	}
	return b.String()
}

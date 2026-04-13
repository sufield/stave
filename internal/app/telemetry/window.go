package telemetry

import "time"

// WindowTracker tracks active violation windows per (control, resource)
// pair across a chronological sequence of assessments.
type WindowTracker struct {
	active map[string]string // key → window_id for active violations
}

// NewWindowTracker creates an empty tracker.
func NewWindowTracker() *WindowTracker {
	return &WindowTracker{active: make(map[string]string)}
}

// Track processes a finding key and returns the window_id.
// If the key is newly violated (wasn't active before), a new window_id
// is generated. If it was already active, the existing window_id is returned.
func (w *WindowTracker) Track(resourceID, controlID string, capturedAt time.Time) string {
	key := resourceID + "/" + controlID
	if wid, exists := w.active[key]; exists {
		return wid // continuing violation — same window
	}
	// New violation — open a window.
	wid := resourceID + "/" + controlID + "/" + capturedAt.Format(time.RFC3339)
	w.active[key] = wid
	return wid
}

// CloseAbsent closes windows for any (control, resource) pairs that
// are NOT in the current finding set. Call after processing all findings
// for one assessment. Returns the set of closed window IDs.
func (w *WindowTracker) CloseAbsent(currentFindings map[string]bool) []string {
	var closed []string
	for key, wid := range w.active {
		if !currentFindings[key] {
			closed = append(closed, wid)
			delete(w.active, key)
		}
	}
	return closed
}

// FindingKey returns the tracking key for a (resource, control) pair.
func FindingKey(resourceID, controlID string) string {
	return resourceID + "/" + controlID
}

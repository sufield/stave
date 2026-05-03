// Package forensics provides multi-snapshot forensic timeline reconstruction.
package forensics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// VerdictState is the typed wire-format value the timeline uses to
// describe a control's pass/fail state at a point in time. Mirrors
// the Verdict enum on asset.ExposureLifecycle in spirit; the
// timeline stores it directly so reconstructed events stay
// comparable across runs without a separate string-to-state lookup.
//
// Control-verdict-change events use this in the Event.From / .To
// fields; property-change events still use arbitrary scalar values
// (the field type stays `any` to span both cases).
type VerdictState string

// Verdict-state vocabulary for control_verdict_change events.
const (
	VerdictStatePass VerdictState = "pass"
	VerdictStateFail VerdictState = "fail"
)

// Event represents a change detected between consecutive snapshots.
//
// From / To carry either a VerdictState (for control_verdict_change
// events) or an arbitrary scalar (for property-change events). They
// remain `any` because the two event families have intentionally
// different value vocabularies; the IsFail / IsPass predicates
// safely handle the verdict case without callers asserting types.
type Event struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	Property  string `json:"property,omitempty"`
	From      any    `json:"from,omitempty"`
	To        any    `json:"to,omitempty"`
	ControlID string `json:"control_id,omitempty"`
	ChainID   string `json:"chain_id,omitempty"`
	Severity  string `json:"severity,omitempty"`
}

// FormattedSeverity returns the parenthesised, uppercased severity
// suffix the forensics text renderer appends to control_verdict_change
// rows. Returns "" when no severity is set, or " (CRITICAL)" /
// " (HIGH)" / etc. otherwise. Centralises the "" → "(SEV)" decoration
// rule so cmd/forensics drops the inline conditional + concatenation.
func (e *Event) FormattedSeverity() string {
	if e == nil || e.Severity == "" {
		return ""
	}
	return " (" + strings.ToUpper(e.Severity) + ")"
}

// FormatLine returns the single-line text-renderer representation of
// this event. Centralises the per-EventType formatting that
// cmd/forensics used to switch on at every iteration. Returns ""
// for unknown EventType values so a future event variety lands as
// a silent skip rather than a panic.
func (e *Event) FormatLine() string {
	if e == nil {
		return ""
	}
	switch e.EventType {
	case "first_seen":
		return e.Timestamp + "  FIRST SEEN"
	case "last_seen":
		return e.Timestamp + "  LAST SEEN"
	case "property_change":
		return fmt.Sprintf("%s  PROPERTY  %s  %v → %v", e.Timestamp, e.Property, e.From, e.To)
	case "control_verdict_change":
		return fmt.Sprintf("%s  CONTROL   %s  %s → %s%s",
			e.Timestamp, e.ControlID, e.From, e.To, e.FormattedSeverity())
	case "chain_activation":
		return fmt.Sprintf("%s  CHAIN ACTIVE  %s", e.Timestamp, e.ChainID)
	case "chain_deactivation":
		return fmt.Sprintf("%s  CHAIN DORMANT %s", e.Timestamp, e.ChainID)
	default:
		return ""
	}
}

// IsFail reports whether this event records a transition to the
// failing state. Returns true only when To is a VerdictState equal
// to VerdictStateFail; property-change events (whose To carries a
// scalar) and unrelated event types both return false.
func (e *Event) IsFail() bool {
	if e == nil {
		return false
	}
	v, ok := e.To.(VerdictState)
	return ok && v == VerdictStateFail
}

// IsPass reports whether this event records a transition to the
// passing state. Symmetric with IsFail.
func (e *Event) IsPass() bool {
	if e == nil {
		return false
	}
	v, ok := e.To.(VerdictState)
	return ok && v == VerdictStatePass
}

// ExposureWindow records how long a control has been failing.
type ExposureWindow struct {
	ControlID    string  `json:"control_id"`
	FirstFailed  string  `json:"first_failed"`
	LastFailing  string  `json:"last_seen_failing"`
	RemediatedAt *string `json:"remediated_at"`
	ExposureDays float64 `json:"exposure_days"`
	Status       string  `json:"status"` // ongoing | remediated
}

// DisplayStatus returns the window's status in uppercase for the
// timeline report. Centralised so cmd-side renderers stop calling
// strings.ToUpper inline at every site.
func (w ExposureWindow) DisplayStatus() string {
	return strings.ToUpper(w.Status)
}

// Timeline is the complete forensic reconstruction for an asset.
type Timeline struct {
	AssetID           string           `json:"asset_id"`
	AssetType         string           `json:"asset_type,omitempty"`
	Period            Period           `json:"period"`
	SnapshotsAnalyzed int              `json:"snapshots_analyzed"`
	Events            []Event          `json:"events"`
	ExposureWindows   []ExposureWindow `json:"exposure_windows"`
}

// Period is the time range of the forensic analysis.
type Period struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Input holds the parameters for timeline reconstruction.
type Input struct {
	AssetID   string
	Snapshots []asset.Snapshot
	Controls  []policy.ControlDefinition
	CELEval   policy.PredicateEval
	Clock     ports.Clock
	// Hasher is injected from the cmd/ composition root because the
	// forensics app layer cannot import platform/crypto under the
	// hexagonal-architecture rules. May be nil — FingerprintPolicy()
	// degrades to "" when no hasher is supplied.
	Hasher ports.Digester
}

// BuildTimeline reconstructs the forensic timeline for a single asset
// across multiple snapshots.
func BuildTimeline(ctx context.Context, input Input) (*Timeline, error) {
	if ctx == nil {
		return nil, errors.New("BuildTimeline requires a non-nil context")
	}
	if len(input.Snapshots) == 0 {
		return nil, errors.New("no snapshots provided")
	}

	tl := &Timeline{
		AssetID:           input.AssetID,
		SnapshotsAnalyzed: len(input.Snapshots),
	}

	if len(input.Snapshots) > 0 {
		tl.Period.From = input.Snapshots[0].CapturedAt.Format(time.RFC3339)
		tl.Period.To = input.Snapshots[len(input.Snapshots)-1].CapturedAt.Format(time.RFC3339)
	}

	// Track previous state for delta detection.
	var prevProps map[string]any
	prevVerdicts := make(map[kernel.ControlID]bool) // true = failing

	for i, snap := range input.Snapshots {
		ts := snap.CapturedAt.Format(time.RFC3339)

		// Find the target asset in this snapshot.
		var targetAsset *asset.Asset
		for ai := range snap.Assets {
			if string(snap.Assets[ai].ID) == input.AssetID {
				targetAsset = &snap.Assets[ai]
				break
			}
		}

		if targetAsset == nil {
			if prevProps != nil {
				tl.Events = append(tl.Events, Event{
					Timestamp: ts, EventType: "last_seen",
				})
				prevProps = nil
			}
			continue
		}

		if tl.AssetType == "" {
			tl.AssetType = string(targetAsset.Type)
		}

		// First appearance.
		if i == 0 || prevProps == nil {
			tl.Events = append(tl.Events, Event{
				Timestamp: ts, EventType: "first_seen",
			})
		}

		// Property deltas.
		if prevProps != nil {
			deltas := diffProperties("", prevProps, targetAsset.Properties)
			for _, d := range deltas {
				tl.Events = append(tl.Events, Event{
					Timestamp: ts, EventType: "property_change",
					Property: d.path, From: d.from, To: d.to,
				})
			}
		}

		// Control verdict changes.
		if input.CELEval != nil {
			a := engine.NewAssessor(
				engine.WithControls(input.Controls),
				engine.WithClock(input.Clock),
				engine.WithHasher(input.Hasher),
				engine.WithPredicateEval(input.CELEval),
				engine.WithPredicateParser(func(_ any) (*policy.UnsafePredicate, error) {
					return &policy.UnsafePredicate{}, nil
				}),
			)
			report, err := a.Assess(ctx, []asset.Snapshot{snap})
			if err == nil {
				currentVerdicts := make(map[kernel.ControlID]bool)
				for fi := range report.Findings {
					currentVerdicts[report.Findings[fi].ControlID] = true
				}

				// Detect transitions.
				for ci := range input.Controls {
					wasFailing := prevVerdicts[input.Controls[ci].ID]
					nowFailing := currentVerdicts[input.Controls[ci].ID]

					if !wasFailing && nowFailing {
						tl.Events = append(tl.Events, Event{
							Timestamp: ts, EventType: "control_verdict_change",
							ControlID: string(input.Controls[ci].ID),
							From:      VerdictStatePass,
							To:        VerdictStateFail,
							Severity:  input.Controls[ci].Severity.String(),
						})
					} else if wasFailing && !nowFailing {
						tl.Events = append(tl.Events, Event{
							Timestamp: ts, EventType: "control_verdict_change",
							ControlID: string(input.Controls[ci].ID),
							From:      VerdictStateFail,
							To:        VerdictStatePass,
						})
					}
				}

				prevVerdicts = currentVerdicts
			}
		}

		prevProps = targetAsset.Properties
	}

	// Compute exposure windows.
	tl.ExposureWindows = computeExposureWindows(tl.Events)

	return tl, nil
}

type propDelta struct {
	path string
	from any
	to   any
}

func diffProperties(prefix string, prev, curr map[string]any) []propDelta {
	var deltas []propDelta

	for key, currVal := range curr {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		prevVal, exists := prev[key]
		if !exists {
			deltas = append(deltas, propDelta{path: path, from: nil, to: currVal})
			continue
		}

		// Recurse into nested maps.
		prevMap, prevIsMap := prevVal.(map[string]any)
		currMap, currIsMap := currVal.(map[string]any)
		if prevIsMap && currIsMap {
			deltas = append(deltas, diffProperties(path, prevMap, currMap)...)
			continue
		}

		if fmt.Sprintf("%v", prevVal) != fmt.Sprintf("%v", currVal) {
			deltas = append(deltas, propDelta{path: path, from: prevVal, to: currVal})
		}
	}

	// Detect removed keys.
	for key, prevVal := range prev {
		if _, exists := curr[key]; !exists {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			deltas = append(deltas, propDelta{path: path, from: prevVal, to: nil})
		}
	}

	return deltas
}

func computeExposureWindows(events []Event) []ExposureWindow {
	type windowState struct {
		firstFailed string
		lastFailing string
		remediated  *string
	}

	windows := make(map[string]*windowState)

	for i := range events {
		ev := &events[i]
		if ev.EventType != "control_verdict_change" {
			continue
		}
		switch {
		case ev.IsFail():
			if windows[ev.ControlID] == nil {
				windows[ev.ControlID] = &windowState{
					firstFailed: ev.Timestamp,
				}
			}
			windows[ev.ControlID].lastFailing = ev.Timestamp
		case ev.IsPass():
			if w := windows[ev.ControlID]; w != nil {
				ts := ev.Timestamp
				w.remediated = &ts
			}
		}
	}

	var result []ExposureWindow
	for ctlID, w := range windows {
		status := "ongoing"
		lastTS := w.lastFailing
		if w.remediated != nil {
			status = "remediated"
			lastTS = *w.remediated
		}

		days := float64(-1)
		first, firstErr := time.Parse(time.RFC3339, w.firstFailed)
		last, lastErr := time.Parse(time.RFC3339, lastTS)
		if firstErr == nil && lastErr == nil {
			days = last.Sub(first).Hours() / 24
		}

		result = append(result, ExposureWindow{
			ControlID:    ctlID,
			FirstFailed:  w.firstFailed,
			LastFailing:  w.lastFailing,
			RemediatedAt: w.remediated,
			ExposureDays: days,
			Status:       status,
		})
	}

	return result
}

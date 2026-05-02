// Package forensics provides multi-snapshot forensic timeline reconstruction.
package forensics

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// Event represents a change detected between consecutive snapshots.
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

// ExposureWindow records how long a control has been failing.
type ExposureWindow struct {
	ControlID    string  `json:"control_id"`
	FirstFailed  string  `json:"first_failed"`
	LastFailing  string  `json:"last_seen_failing"`
	RemediatedAt *string `json:"remediated_at"`
	ExposureDays float64 `json:"exposure_days"`
	Status       string  `json:"status"` // ongoing | remediated
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
							ControlID: string(input.Controls[ci].ID), From: "pass", To: "fail",
							Severity: input.Controls[ci].Severity.String(),
						})
					} else if wasFailing && !nowFailing {
						tl.Events = append(tl.Events, Event{
							Timestamp: ts, EventType: "control_verdict_change",
							ControlID: string(input.Controls[ci].ID), From: "fail", To: "pass",
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
		switch ev.To {
		case "fail":
			if windows[ev.ControlID] == nil {
				windows[ev.ControlID] = &windowState{
					firstFailed: ev.Timestamp,
				}
			}
			windows[ev.ControlID].lastFailing = ev.Timestamp
		case "pass":
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

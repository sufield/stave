package telemetry

import (
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// Filter controls which findings are included in the telemetry stream.
type Filter struct {
	Severities  map[string]struct{} // empty = all
	ResourceARN string              // empty = all
}

// ControlFingerprints maps control IDs to their per-control hashes.
// Populated by the CLI layer using ControlDefinition.Fingerprint().
type ControlFingerprints map[kernel.ControlID]kernel.Digest

// MapAssessment converts an Assessment into a slice of telemetry Events.
// One event per finding. controlFPs is optional (nil = no per-control fingerprints).
func MapAssessment(a *report.Assessment, filter Filter, controlFPs ControlFingerprints) []Event {
	var events []Event
	for i := range a.Findings {
		f := &a.Findings[i]
		if !matchesFilter(f, filter) {
			continue
		}
		e := Event{
			SchemaVersion:     schemaVersion,
			CapturedAt:        a.Run.EvalTime,
			FindingID:         string(f.FindingID),
			ControlID:         string(f.ControlID),
			ControlName:       f.ControlName,
			Severity:          f.SeverityLabel(),
			ResourceID:        string(f.AssetID),
			ResourceType:      string(f.AssetType),
			Verdict:           "violation",
			PolicyFingerprint: string(a.Run.PolicyFingerprint),
			Status:            string(a.Status),
		}
		if controlFPs != nil {
			e.ControlFingerprint = string(controlFPs[f.ControlID])
		}
		if score := computeEnvironmentalScore(f); score > 0 {
			e.EnvironmentalScore = &score
		}
		events = append(events, e)
	}
	return events
}

// MapAssessmentWithWindows converts an Assessment into events with window tracking.
// The tracker is updated in place — call CloseAbsent after processing each assessment.
func MapAssessmentWithWindows(a *report.Assessment, filter Filter, controlFPs ControlFingerprints, tracker *WindowTracker) []Event {
	events := MapAssessment(a, filter, controlFPs)
	for i := range events {
		wid := tracker.Track(events[i].ResourceID, events[i].ControlID, events[i].CapturedAt)
		events[i].WindowID = &wid
	}
	return events
}

func matchesFilter(f *remediation.Finding, filter Filter) bool {
	if !f.MatchesSeverityFilter(filter.Severities) {
		return false
	}
	if filter.ResourceARN != "" && string(f.AssetID) != filter.ResourceARN {
		return false
	}
	return true
}

func computeEnvironmentalScore(f *remediation.Finding) float64 {
	baseImpact := 5 // default
	sensitivity := 1.0
	exposure := 1.0

	if f.HasExposure() {
		exposure = risk.LookupExposure(f.PrincipalScopeString())
	}

	return risk.Environmental(baseImpact, sensitivity, exposure)
}

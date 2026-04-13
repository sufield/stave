package telemetry

import (
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// Filter controls which findings are included in the telemetry stream.
type Filter struct {
	Severities  map[string]bool // empty = all
	ResourceARN string          // empty = all
}

// MapAssessment converts an Assessment into a slice of telemetry Events.
// One event per finding.
func MapAssessment(a *report.Assessment, filter Filter) []Event {
	var events []Event
	for i := range a.Findings {
		f := &a.Findings[i]
		if !matchesFilter(f, filter) {
			continue
		}
		events = append(events, Event{
			SchemaVersion:     schemaVersion,
			CapturedAt:        a.Run.Now,
			ControlID:         string(f.ControlID),
			ControlName:       f.ControlName,
			Severity:          f.ControlSeverity.String(),
			ResourceID:        string(f.AssetID),
			ResourceType:      string(f.AssetType),
			Verdict:           "violation",
			PolicyFingerprint: string(a.Run.PolicyFingerprint),
			Status:            string(a.Status),
		})
	}
	return events
}

func matchesFilter(f *remediation.Finding, filter Filter) bool {
	if len(filter.Severities) > 0 {
		if !filter.Severities[strings.ToLower(f.ControlSeverity.String())] {
			return false
		}
	}
	if filter.ResourceARN != "" && string(f.AssetID) != filter.ResourceARN {
		return false
	}
	return true
}

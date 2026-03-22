// Package status provides project health inspection and next-step guidance.
package status

import (
	"fmt"
	"path/filepath"
	"time"
)

// Summary captures metadata about a group of files (e.g., controls or observations).
type Summary struct {
	Count     int       `json:"count"`
	Latest    time.Time `json:"latest"`
	HasLatest bool      `json:"has_latest"`
}

// ProjectState holds the artifact counts and timestamps needed to recommend
// the next workflow step. This is the domain-layer projection — it does not
// carry CLI-specific types like session state.
type ProjectState struct {
	Root         string
	Controls     Summary
	RawSnapshots Summary
	Observations Summary
	EvalTime     time.Time
	HasEval      bool
}

// RecommendNext returns a string command suggesting the most logical next step.
func (s ProjectState) RecommendNext() string {
	ctlDir := filepath.Join(s.Root, "controls")
	obsDir := filepath.Join(s.Root, "observations")
	outPath := filepath.Join(s.Root, "output", "evaluation.json")

	if s.RawSnapshots.Count > 0 && (s.Observations.Count == 0 || s.isRawNewerThanObs()) {
		return fmt.Sprintf("Create observation snapshots in %s from your AWS environment data", obsDir)
	}
	if s.Controls.Count == 0 {
		return fmt.Sprintf("stave generate control --id CTL.S3.PUBLIC.901 --out %s", filepath.Join(ctlDir, "CTL.S3.PUBLIC.901.yaml"))
	}
	if s.Observations.Count == 0 {
		return fmt.Sprintf("Create observation snapshots in %s from your AWS environment data", obsDir)
	}
	if s.NeedsReevaluation() {
		return fmt.Sprintf("stave validate --controls %s --observations %s && stave apply --controls %s --observations %s --format json > %s",
			ctlDir, obsDir, ctlDir, obsDir, outPath)
	}
	return fmt.Sprintf("stave diagnose --controls %s --observations %s --previous-output %s",
		ctlDir, obsDir, outPath)
}

func (s ProjectState) isRawNewerThanObs() bool {
	return s.RawSnapshots.HasLatest &&
		s.Observations.HasLatest &&
		s.RawSnapshots.Latest.After(s.Observations.Latest)
}

// NeedsReevaluation reports whether inputs have changed since the last evaluation.
func (s ProjectState) NeedsReevaluation() bool {
	if !s.HasEval {
		return true
	}
	latestInput := s.Controls.Latest
	if s.Observations.HasLatest && s.Observations.Latest.After(latestInput) {
		latestInput = s.Observations.Latest
	}
	return latestInput.After(s.EvalTime)
}

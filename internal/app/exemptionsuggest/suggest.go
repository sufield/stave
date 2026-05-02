// Package exemptionsuggest analyzes assessment history to identify
// findings that have been open long enough to warrant a formal
// governance decision — either fix, formally accept risk, or escalate.
package exemptionsuggest

import (
	"fmt"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// findingKey uniquely identifies a finding across assessments.
type findingKey struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
}

// Pattern describes the temporal behavior of a finding.
type Pattern string

const (
	// PatternOscillating means the finding has been fixed and returned
	// multiple times, indicating a systemic issue.
	PatternOscillating Pattern = "oscillating"
	// PatternChronic means the finding has been continuously open
	// without exemption for longer than the threshold.
	PatternChronic Pattern = "chronic"
)

// Candidate is a finding that needs a governance decision.
type Candidate struct {
	ControlID   kernel.ControlID `json:"control_id"`
	AssetID     asset.ID         `json:"asset_id"`
	Severity    string           `json:"severity"`
	Pattern     Pattern          `json:"pattern"`
	DwellDays   float64          `json:"dwell_days"`
	Cycles      int              `json:"cycles,omitempty"`
	OwnerTeamID string           `json:"owner_team_id,omitempty"`
	ExemptCmd   string           `json:"exempt_command"`
}

// Result holds the exemption suggestions.
type Result struct {
	Oscillating  []Candidate `json:"oscillating"`
	Chronic      []Candidate `json:"chronic"`
	WindowDays   int         `json:"window_days"`
	MinDwellDays int         `json:"min_dwell_days"`
}

// Input configures the suggestion analysis.
type Input struct {
	// History is the set of historical assessments (unsorted).
	History []*report.Assessment
	// Window is how far back to look for patterns.
	Window time.Duration
	// MinDwell is the minimum time a finding must be open to be
	// considered chronic.
	MinDwell time.Duration
	// Now is the reference time.
	Now time.Time
	// ExemptedKeys is the set of (control@asset) keys that already
	// have active exemptions — these are excluded from suggestions.
	ExemptedKeys map[string]bool
}

// Suggest analyzes assessment history and produces exemption candidates.
func Suggest(in Input) *Result {
	if len(in.History) == 0 {
		return &Result{
			WindowDays:   int(in.Window.Hours() / 24),
			MinDwellDays: int(in.MinDwell.Hours() / 24),
		}
	}

	// Sort history by time.
	sorted := make([]*report.Assessment, len(in.History))
	copy(sorted, in.History)
	slices.SortFunc(sorted, func(a, b *report.Assessment) int {
		return a.Run.Now.Compare(b.Run.Now)
	})

	// Apply window filter.
	cutoff := in.Now.Add(-in.Window)
	filtered := make([]*report.Assessment, 0, len(sorted))
	for _, a := range sorted {
		if !a.Run.Now.Before(cutoff) {
			filtered = append(filtered, a)
		}
	}
	if len(filtered) == 0 {
		return &Result{
			WindowDays:   int(in.Window.Hours() / 24),
			MinDwellDays: int(in.MinDwell.Hours() / 24),
		}
	}

	// Build per-finding timeline: track first seen, last seen, presence
	// in each assessment, and metadata.
	type findingMeta struct {
		controlID   kernel.ControlID
		assetID     asset.ID
		severity    string
		ownerTeamID string
		firstSeen   time.Time
		lastSeen    time.Time
		appearances []bool // true for each assessment where present
	}
	meta := make(map[findingKey]*findingMeta)
	assessmentCount := len(filtered)

	for idx, a := range filtered {
		for i := range a.Findings {
			f := &a.Findings[i]
			k := findingKey{ControlID: f.ControlID, AssetID: f.AssetID}
			m, exists := meta[k]
			if !exists {
				m = &findingMeta{
					controlID:   f.ControlID,
					assetID:     f.AssetID,
					severity:    f.ControlSeverity.String(),
					ownerTeamID: f.OwnerTeamID.String(),
					firstSeen:   a.Run.Now,
					appearances: make([]bool, assessmentCount),
				}
				meta[k] = m
			}
			m.lastSeen = a.Run.Now
			m.appearances[idx] = true
			if !f.OwnerTeamID.IsEmpty() {
				m.ownerTeamID = f.OwnerTeamID.String()
			}
		}
	}

	// Classify findings.
	var oscillating, chronic []Candidate

	for k, m := range meta {
		// Skip if already exempted.
		exemptKey := string(k.ControlID) + "@" + string(k.AssetID)
		if in.ExemptedKeys[exemptKey] {
			continue
		}

		// Must be in the latest assessment (still active).
		if !m.appearances[assessmentCount-1] {
			continue
		}

		dwellDays := in.Now.Sub(m.firstSeen).Hours() / 24

		// Count oscillation cycles (gaps where finding disappeared then returned).
		cycles := countCycles(m.appearances)

		cmd := fmt.Sprintf("stave exempt acknowledge --control-id %s --asset-id %s --reason \"<reason>\" --approver \"<approver>\" --expires %s",
			k.ControlID, k.AssetID, in.Now.AddDate(0, 0, 30).Format("2006-01-02"))

		if cycles >= 2 {
			oscillating = append(oscillating, Candidate{
				ControlID:   k.ControlID,
				AssetID:     k.AssetID,
				Severity:    m.severity,
				Pattern:     PatternOscillating,
				DwellDays:   dwellDays,
				Cycles:      cycles,
				OwnerTeamID: m.ownerTeamID,
				ExemptCmd:   cmd,
			})
			continue
		}

		// Chronic: open longer than min-dwell threshold.
		if dwellDays >= in.MinDwell.Hours()/24 {
			chronic = append(chronic, Candidate{
				ControlID:   k.ControlID,
				AssetID:     k.AssetID,
				Severity:    m.severity,
				Pattern:     PatternChronic,
				DwellDays:   dwellDays,
				OwnerTeamID: m.ownerTeamID,
				ExemptCmd:   cmd,
			})
		}
	}

	// Sort by severity (critical first) then by dwell time (longest first).
	sortCandidates := func(s []Candidate) {
		slices.SortFunc(s, func(a, b Candidate) int {
			oa := policy.SeverityOrderOf(a.Severity)
			ob := policy.SeverityOrderOf(b.Severity)
			if oa != ob {
				return oa - ob
			}
			if a.DwellDays != b.DwellDays {
				if a.DwellDays > b.DwellDays {
					return -1
				}
				return 1
			}
			return 0
		})
	}
	sortCandidates(oscillating)
	sortCandidates(chronic)

	return &Result{
		Oscillating:  oscillating,
		Chronic:      chronic,
		WindowDays:   int(in.Window.Hours() / 24),
		MinDwellDays: int(in.MinDwell.Hours() / 24),
	}
}

// countCycles counts the number of times a finding disappeared and
// reappeared across consecutive assessments. A cycle is a transition
// from present → absent → present.
func countCycles(appearances []bool) int {
	cycles := 0
	wasPresent := false
	wasAbsent := false
	for _, present := range appearances {
		if present {
			if wasAbsent && wasPresent {
				cycles++
			}
			wasPresent = true
			wasAbsent = false
		} else {
			if wasPresent {
				wasAbsent = true
			}
		}
	}
	return cycles
}

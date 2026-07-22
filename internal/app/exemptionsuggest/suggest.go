package exemptionsuggest

import (
	"cmp"
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

// HasOwner reports whether this candidate carries an owner-team
// identifier. Mirrors the Finding.HasOwner shape so cmd-side
// renderers can ask either type the same question.
func (c *Candidate) HasOwner() bool {
	return c != nil && c.OwnerTeamID != ""
}

// OwnerKey returns the owner-team identifier or "" when no owner is
// set. Mirrors Finding.OwnerKey so cmd-side text / markdown
// renderers stop reading the field directly.
func (c *Candidate) OwnerKey() string {
	if c == nil {
		return ""
	}
	return c.OwnerTeamID
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
	EvalTime time.Time
	// ExemptedKeys is the set of (control@asset) keys that already
	// have active exemptions — these are excluded from suggestions.
	ExemptedKeys map[string]struct{}
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
		return a.Run.EvalTime.Compare(b.Run.EvalTime)
	})

	// Apply window filter.
	cutoff := in.EvalTime.Add(-in.Window)
	filtered := make([]*report.Assessment, 0, len(sorted))
	for _, a := range sorted {
		if !a.Run.EvalTime.Before(cutoff) {
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

	for _, a := range sorted {
		presentThisRun := make(map[findingKey]struct{})
		for i := range a.Findings {
			f := &a.Findings[i]
			k := findingKey{ControlID: f.ControlID, AssetID: f.AssetID}
			presentThisRun[k] = struct{}{}

			m, exists := meta[k]
			if !exists {
				m = &findingMeta{
					controlID:   f.ControlID,
					assetID:     f.AssetID,
					severity:    f.SeverityLabel(),
					ownerTeamID: f.OwnerKey(),
					firstSeen:   a.Run.EvalTime,
					appearances: make([]bool, assessmentCount),
				}
				meta[k] = m
			} else if m.firstSeen.IsZero() {
				m.firstSeen = a.Run.EvalTime
			}
		}

		for k, m := range meta {
			if _, present := presentThisRun[k]; !present {
				m.firstSeen = time.Time{}
			}
		}
	}

	for idx, a := range filtered {
		for i := range a.Findings {
			f := &a.Findings[i]
			k := findingKey{ControlID: f.ControlID, AssetID: f.AssetID}
			m := meta[k]
			m.lastSeen = a.Run.EvalTime
			m.appearances[idx] = true
			if k := f.OwnerKey(); k != "" {
				m.ownerTeamID = k
			}
		}
	}

	// Classify findings.
	var oscillating, chronic []Candidate

	for k, m := range meta {
		// Skip if already exempted.
		exemptKey := string(k.ControlID) + "@" + string(k.AssetID)
		if _, ok := in.ExemptedKeys[exemptKey]; ok {
			continue
		}

		// Must be in the latest assessment (still active).
		if !m.appearances[assessmentCount-1] {
			continue
		}

		dwellDays := in.EvalTime.Sub(m.firstSeen).Hours() / 24

		// Count oscillation cycles (gaps where finding disappeared then returned).
		cycles := countCycles(m.appearances)

		cmd := fmt.Sprintf("stave exempt acknowledge --control-id %s --asset-id %s --reason \"<reason>\" --approver \"<approver>\" --expires %s",
			k.ControlID, k.AssetID, in.EvalTime.AddDate(0, 0, 30).Format("2006-01-02"))

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
			if n := cmp.Compare(string(a.ControlID), string(b.ControlID)); n != 0 {
				return n
			}
			return cmp.Compare(string(a.AssetID), string(b.AssetID))
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

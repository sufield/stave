// Package profile defines compliance profiles that select and configure
// controls for evaluation against observation snapshots. The built-in
// HIPAA profile maps controls to Security Rule citations with severity
// overrides, compound risk detection, and acknowledged exceptions.
package profile

import (
	"fmt"
	"sort"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/compliance"
	"github.com/sufield/stave/internal/core/compliance/compound"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// ProfileControl binds an control to a profile with optional overrides.
type ProfileControl struct {
	// ControlID references a registered control.
	ControlID string

	// SeverityOverride replaces the control's default severity when non-nil.
	SeverityOverride *policy.Severity

	// ComplianceRef is the regulatory citation (e.g. "§164.312(b)").
	ComplianceRef string

	// Rationale explains why this control is included in the profile.
	Rationale string
}

// Profile is a named set of invariants configured for a compliance framework.
type Profile struct {
	ID          string
	Name        string
	Description string
	Controls    []ProfileControl
}

// ProfileResult extends an control Result with profile-level metadata.
type ProfileResult struct {
	compliance.Result
	ComplianceRef string `json:"compliance_ref,omitempty"`
	Rationale     string `json:"rationale,omitempty"`
}

// ProfileReport is the output of evaluating a profile against a snapshot.
type ProfileReport struct {
	ProfileID        string                     `json:"profile_id"`
	ProfileName      string                     `json:"profile_name"`
	Pass             bool                       `json:"pass"`
	CompoundFindings []compound.CompoundFinding `json:"compound_findings,omitempty"`
	Acknowledged     []AcknowledgedEntry        `json:"acknowledged,omitempty"`
	Results          []ProfileResult            `json:"results"`
	Counts           map[policy.Severity]int    `json:"counts"`
	FailCounts       map[policy.Severity]int    `json:"fail_counts"`
}

// AcknowledgedEntry surfaces an exception in the report.
type AcknowledgedEntry struct {
	ControlID      string `json:"control_id"`
	Bucket         string `json:"bucket"`
	Rationale      string `json:"rationale"`
	AcknowledgedBy string `json:"acknowledged_by"`
	Valid          bool   `json:"valid"`
	InvalidReason  string `json:"invalid_reason,omitempty"`
}

// Evaluate runs all profile invariants against the snapshot.
// It validates for incompatible pairs, resolves invariants from registries,
// applies severity overrides, and returns a sorted report.
//
// When p.Controls is empty the profile discovers its controls from the
// registries using each control's ComplianceProfiles() metadata — no
// hardcoded list required.
func (p *Profile) Evaluate(snap asset.Snapshot, registries ...*compliance.Registry) (ProfileReport, error) {
	controls := p.Controls
	if len(controls) == 0 {
		controls = discoverProfileControls(p.ID, registries)
	}

	// Collect all control IDs for profile validation.
	ids := make([]string, len(controls))
	for i, c := range controls {
		ids[i] = c.ControlID
	}
	if err := compliance.ValidateProfile(ids); err != nil {
		return ProfileReport{}, fmt.Errorf("profile %s: %w", p.ID, err)
	}

	// Build lookup from all registries.
	lookup := buildLookup(registries)

	var results []ProfileResult
	for _, ctrl := range controls {
		inv := lookup[ctrl.ControlID]
		if inv == nil {
			// Control not yet implemented — skip silently.
			continue
		}

		r := inv.Evaluate(snap)

		// Apply severity override.
		if ctrl.SeverityOverride != nil {
			r.Severity = *ctrl.SeverityOverride
		}

		results = append(results, ProfileResult{
			Result:        r,
			ComplianceRef: ctrl.ComplianceRef,
			Rationale:     ctrl.Rationale,
		})
	}

	// Sort: failures first, then by severity descending.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Pass != results[j].Pass {
			return !results[i].Pass // failures first
		}
		return results[i].Severity > results[j].Severity
	})

	// Detect compound risks from the raw control results.
	rawResults := make([]compliance.Result, len(results))
	for i, r := range results {
		rawResults[i] = r.Result
	}
	compoundFindings := compound.Detect(compound.DefaultRules(), rawResults)

	counts := make(map[policy.Severity]int)
	failCounts := make(map[policy.Severity]int)
	allPass := true
	for _, r := range results {
		counts[r.Severity]++
		if !r.Pass {
			failCounts[r.Severity]++
			allPass = false
		}
	}
	if len(compoundFindings) > 0 {
		allPass = false
	}

	return ProfileReport{
		ProfileID:        p.ID,
		ProfileName:      p.Name,
		Pass:             allPass,
		CompoundFindings: compoundFindings,
		Results:          results,
		Counts:           counts,
		FailCounts:       failCounts,
	}, nil
}

// discoverProfileControls builds the ProfileControl list by querying all
// registries for controls that declare membership in the given profile.
func discoverProfileControls(profileID string, registries []*compliance.Registry) []ProfileControl {
	var controls []ProfileControl
	for _, reg := range registries {
		for _, ctrl := range reg.ByProfile(profileID) {
			def := ctrl.Def()
			pc := ProfileControl{
				ControlID:     def.ID(),
				ComplianceRef: def.ComplianceRefs()[profileID],
				Rationale:     def.ProfileRationale(profileID),
			}
			if sev, ok := def.ProfileSeverityOverride(profileID); ok {
				pc.SeverityOverride = &sev
			}
			controls = append(controls, pc)
		}
	}
	return controls
}

func buildLookup(registries []*compliance.Registry) map[string]compliance.Control {
	lookup := make(map[string]compliance.Control)
	for _, reg := range registries {
		for _, inv := range reg.All() {
			lookup[inv.Def().ID()] = inv
		}
	}
	return lookup
}

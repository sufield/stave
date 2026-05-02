// Package profile defines compliance profiles that select and configure
// controls for evaluation against observation snapshots. The built-in
// HIPAA profile maps controls to Security Rule citations with severity
// overrides, compound risk detection, and acknowledged exceptions.
package profile

import (
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/compliance"
	"github.com/sufield/stave/internal/core/compliance/compound"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ProfileID identifies a compliance profile (e.g. "hipaa", "soc2").
// The slug-case constraint (lowercase + digits + _-) prevents two
// classes of bugs: filesystem-level mismatches (some operators ship
// profiles as profile-id.yaml files; case-folding filesystems would
// merge "Hipaa" and "hipaa" into the same name elsewhere), and
// duplicate registry entries when an init() in one package
// registers "Default" while another registers "default".
type ProfileID string

var profileIDPattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

// String returns the raw ID.
func (p ProfileID) String() string { return string(p) }

// IsEmpty reports whether the ID is unset.
func (p ProfileID) IsEmpty() bool { return p == "" }

// ParseProfileID validates and returns a ProfileID. The caller
// constraints are: non-empty, lowercase, alphanumeric with -_. CLI
// flags should run their string through ParseProfileID before
// passing it to LoadProfile so a user typo or accidental capital
// fails at boundary, not at "profile not found" later.
func ParseProfileID(raw string) (ProfileID, error) {
	if raw == "" {
		return "", errors.New("profile ID must not be empty")
	}
	if !profileIDPattern.MatchString(raw) {
		return "", fmt.Errorf("invalid profile ID %q: must be lowercase slug-case (a-z, 0-9, -, _)", raw)
	}
	return ProfileID(raw), nil
}

// Control binds an control to a profile with optional overrides.
type Control struct {
	// ControlID references a registered control.
	ControlID kernel.ControlID

	// SeverityOverride replaces the control's default severity when non-nil.
	SeverityOverride *policy.Severity

	// ComplianceRef is the regulatory citation (e.g. "§164.312(b)").
	ComplianceRef string

	// Rationale explains why this control is included in the profile.
	Rationale string
}

// Profile is a named set of invariants configured for a compliance framework.
type Profile struct {
	ID          ProfileID
	Name        string
	Description string
	Controls    []Control
}

// Result extends an control Result with profile-level metadata.
type Result struct {
	compliance.Outcome
	ComplianceRef string `json:"compliance_ref,omitempty"`
	Rationale     string `json:"rationale,omitempty"`
}

// MarkExempt records that a valid acknowledged exception applies to
// this result: the underlying check stays a fail, but the policy
// outcome is treated as a pass at the configured downgraded severity.
// Replaces the external `r.Pass = true; r.Severity = severity` pair
// in profile/exception so the caller (the exception applier) tells
// the Result what happened rather than reaching into its fields.
//
// nil receiver is a no-op so a defensive caller can call this without
// nil-checking when the exception path may have skipped construction.
func (r *Result) MarkExempt(severity policy.Severity) {
	if r == nil {
		return
	}
	r.Pass = true
	r.Severity = severity
}

// StatusLabel returns the canonical label a text reporter should
// display for this result's pass/fail state. Centralises the
// (r.Pass ? "PASS" : "FAIL") branch so renderers stop reproducing
// it at every section heading. Pointer receiver for consistency
// with the mutating MarkExempt — keeps the Result method set on a
// single receiver kind (recvcheck-clean).
func (r *Result) StatusLabel() string {
	if r.Pass {
		return "PASS"
	}
	return "FAIL"
}

// MatchesSeverity reports whether this result's severity equals sev.
// Used by per-severity grouping in text reporters; centralising the
// equality check on the Result lets a future severity-aliasing or
// case-folding rule live in one place.
func (r *Result) MatchesSeverity(sev policy.Severity) bool {
	return r.Severity == sev
}

// Less reports whether r should sort before other in the standard
// profile-report display order: failing results first, then by
// descending severity. Replaces the inline sort.SliceStable comparator
// in Profile.Evaluate so the ordering policy lives on the type.
func (r *Result) Less(other *Result) bool {
	if r.Pass != other.Pass {
		return !r.Pass // failures first
	}
	return r.Severity > other.Severity
}

// Report is the output of evaluating a profile against a snapshot.
type Report struct {
	ProfileID        string                  `json:"profile_id"`
	ProfileName      string                  `json:"profile_name"`
	Pass             bool                    `json:"pass"`
	CompoundFindings []compound.Finding      `json:"compound_findings,omitempty"`
	Acknowledged     []AcknowledgedEntry     `json:"acknowledged,omitempty"`
	Results          []Result                `json:"results"`
	Counts           map[policy.Severity]int `json:"counts"`
	FailCounts       map[policy.Severity]int `json:"fail_counts"`
}

// CriticalFailureCount returns the number of failing controls at
// the Critical severity. Replaces direct
// (report.FailCounts[policy.SeverityCritical]) reads at the
// cmd/evaluate gating site so the count expression lives on the
// type that owns FailCounts.
func (r *Report) CriticalFailureCount() int {
	if r == nil {
		return 0
	}
	return r.FailCounts[policy.SeverityCritical]
}

// HasCriticalFailures reports whether any Critical-severity control
// failed in this report. Sibling of CriticalFailureCount for
// callers that only need the boolean signal.
func (r *Report) HasCriticalFailures() bool {
	return r.CriticalFailureCount() > 0
}

// CompoundCount returns the number of compound (chain) findings
// active in this report.
func (r *Report) CompoundCount() int {
	if r == nil {
		return 0
	}
	return len(r.CompoundFindings)
}

// HasCompoundFindings reports whether any compound (chain) finding
// is active. Replaces (len(report.CompoundFindings) > 0) gates at
// the cmd/evaluate exit-code site with a named accessor.
func (r *Report) HasCompoundFindings() bool {
	return r.CompoundCount() > 0
}

// FilterUnacknowledgedCompound drops any compound finding whose
// trigger set is fully covered by the supplied valid acknowledgment
// keys, mutating CompoundFindings in place. Replaces the open-coded
// filter loop at cmd/evaluate/cmd.go so the
// "fully-acknowledged → drop" rule lives on the type that owns the
// slice.
//
// The validAcks argument keys by stringified control ID, matching
// the format produced by the cmd/evaluate exception applier.
func (r *Report) FilterUnacknowledgedCompound(validAcks map[string]struct{}) {
	if r == nil {
		return
	}
	filtered := make([]compound.Finding, 0, len(r.CompoundFindings))
	for i := range r.CompoundFindings {
		cf := &r.CompoundFindings[i]
		if !cf.IsFullyAcknowledged(validAcks) {
			filtered = append(filtered, *cf)
		}
	}
	r.CompoundFindings = filtered
}

// Recount rebuilds FailCounts and Pass from the current Results and
// CompoundFindings slices. The previous shape ran this only inside the
// "exceptions applied" branch in cmd/evaluate, so a profile evaluation
// without exceptions silently used the stale FailCounts that
// Profile.Evaluate computed before any post-processing — including
// before compound findings were folded in. Centralising the recount
// on the type means every mutation site (filter compound findings,
// drop excepted controls, append a synthetic result) can call one
// method and trust that derived counts stay consistent.
//
// Compound findings carry their own severity (often higher than any
// single contributing control's severity, which is the entire point
// of "compound risk"); they fold into FailCounts and force Pass=false.
func (r *Report) Recount() {
	r.FailCounts = make(map[policy.Severity]int)
	r.Pass = true
	for i := range r.Results {
		if !r.Results[i].Pass {
			r.FailCounts[r.Results[i].Severity]++
			r.Pass = false
		}
	}
	for i := range r.CompoundFindings {
		r.FailCounts[r.CompoundFindings[i].Severity]++
	}
	if len(r.CompoundFindings) > 0 {
		r.Pass = false
	}
}

// AcknowledgedEntry surfaces an exception in the report.
type AcknowledgedEntry struct {
	ControlID      kernel.ControlID `json:"control_id"`
	Bucket         string           `json:"bucket"`
	Rationale      string           `json:"rationale"`
	AcknowledgedBy string           `json:"acknowledged_by"`
	Valid          bool             `json:"valid"`
	InvalidReason  string           `json:"invalid_reason,omitempty"`
	InvalidDetail  string           `json:"invalid_detail,omitempty"`
}

// StatusLabel returns the canonical label a text reporter should
// display for this acknowledged entry: "VALID" when the exception
// holds, "INVALID" otherwise. Renderers stop reproducing the
// (ack.Valid ? "VALID" : "INVALID") branch.
func (a AcknowledgedEntry) StatusLabel() string {
	if a.Valid {
		return "VALID"
	}
	return "INVALID"
}

// Evaluate runs all profile invariants against the snapshot.
// It validates for incompatible pairs, resolves invariants from registries,
// applies severity overrides, and returns a sorted report.
//
// When p.Controls is empty the profile discovers its controls from the
// registries using each control's ComplianceProfiles() metadata — no
// hardcoded list required.
func (p *Profile) Evaluate(snap asset.Snapshot, registries ...*compliance.ControlCatalog) (Report, error) {
	controls := p.Controls
	if len(controls) == 0 {
		controls = discoverControls(p.ID.String(), registries)
	}
	// Zero-controls guard. A profile that resolves to no controls
	// would silently produce a Report with allPass=true — making it
	// look as if the snapshot satisfied the profile when in fact
	// nothing was checked. The previous shape produced exactly that
	// false-positive when a profile ID was misspelled, when its
	// catalog membership had been removed in a refactor, or when
	// the wrong registry set was passed to Evaluate.
	if len(controls) == 0 {
		return Report{}, fmt.Errorf("profile %q resolved to zero controls (registries searched: %d) — check the profile ID and that the controls in this profile are loaded into the registry", p.ID, len(registries))
	}

	// Collect all control IDs for profile validation.
	ids := make([]kernel.ControlID, len(controls))
	for i, c := range controls {
		ids[i] = c.ControlID
	}
	if err := compliance.ValidateProfile(ids); err != nil {
		return Report{}, fmt.Errorf("profile %s: %w", p.ID, err)
	}

	// Build lookup from all registries.
	lookup := buildLookup(registries)

	var results []Result
	for _, ctrl := range controls {
		ctl := lookup[ctrl.ControlID]
		if ctl == nil {
			return Report{}, fmt.Errorf("control %s declared in profile but not found in any registry", ctrl.ControlID)
		}

		r := ctl.Evaluate(snap)

		// Apply severity override.
		if ctrl.SeverityOverride != nil {
			r.Severity = *ctrl.SeverityOverride
		}

		results = append(results, Result{
			Outcome:       r,
			ComplianceRef: ctrl.ComplianceRef,
			Rationale:     ctrl.Rationale,
		})
	}

	// Capture outcomes in the original control-iteration order
	// before the display sort runs. compound.Detect's chain rules
	// can be order-sensitive (the same set of failing controls
	// across different orderings could produce different chain
	// matches if a rule short-circuits on the first hit), so the
	// detection input must come from the deterministic pre-sort
	// view rather than the post-sort display order.
	preSortOutcomes := make([]compliance.Outcome, len(results))
	for i, r := range results {
		preSortOutcomes[i] = r.Outcome
	}

	// Sort: failures first, then by severity descending. This is
	// for display only; compound detection ran above against the
	// stable pre-sort input. Comparator lives on Result.Less.
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Less(&results[j])
	})

	compoundFindings := compound.Detect(compound.DefaultRules(), preSortOutcomes)

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

	return Report{
		ProfileID:        p.ID.String(),
		ProfileName:      p.Name,
		Pass:             allPass,
		CompoundFindings: compoundFindings,
		Results:          results,
		Counts:           counts,
		FailCounts:       failCounts,
	}, nil
}

// discoverControls builds the Control list by querying all
// registries for controls that declare membership in the given profile.
func discoverControls(profileID string, registries []*compliance.ControlCatalog) []Control {
	var controls []Control
	for _, reg := range registries {
		for _, ctrl := range reg.ByProfile(profileID) {
			def := ctrl.Def()
			pc := Control{
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

func buildLookup(registries []*compliance.ControlCatalog) map[kernel.ControlID]compliance.Control {
	lookup := make(map[kernel.ControlID]compliance.Control)
	for _, reg := range registries {
		for _, ctl := range reg.All() {
			lookup[ctl.Def().ID()] = ctl
		}
	}
	return lookup
}

func init() {
	RegisterProfile(&Profile{
		ID:          "hipaa",
		Name:        "HIPAA Security Rule",
		Description: "S3 configuration invariants required for HIPAA compliance covering access control, encryption, audit logging, integrity, and retention.",
		// Controls discovered from registries at Evaluate() time via
		// each control's ComplianceProfiles("hipaa") declaration.
	})
}

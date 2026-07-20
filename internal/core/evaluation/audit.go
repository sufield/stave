package evaluation

import (
	"cmp"
	"maps"
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evidence"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/util/sets"
)

// ConfidenceLevel quantifies the certainty of an evaluation result.
type ConfidenceLevel string

const (
	ConfidenceHigh         ConfidenceLevel = "HIGH"
	ConfidenceMedium       ConfidenceLevel = "MEDIUM"
	ConfidenceLow          ConfidenceLevel = "LOW"
	ConfidenceInconclusive ConfidenceLevel = "INCONCLUSIVE"
)

// SecurityState classifies the high-level security posture of the environment.
type SecurityState string

const (
	StateCompliant    SecurityState = "COMPLIANT"
	StateAtRisk       SecurityState = "AT_RISK"
	StateNonCompliant SecurityState = "NON_COMPLIANT"
	// StateUnknown is the explicit zero/error value: used when an
	// assessment short-circuits before posture can be derived (data
	// load failed, audit prep errored). Callers comparing posture
	// strings should not collapse this to "" silently — that path
	// previously rendered an unset wire field that downstream
	// consumers could not distinguish from a missing assessment.
	StateUnknown SecurityState = ""
)

// SecurityState derives the overall posture from the summary's
// violation count plus the supplied risk-signal set.
// NON_COMPLIANT when any active violations exist, AT_RISK when no
// violations but at least one upcoming-risk signal fires,
// COMPLIANT otherwise.
//
// Methodised so callers stop open-coding the (violations > 0) /
// (HasAnyRisk) precedence and so a future precedence change is one
// edit on the type. The signature still takes upcoming as an
// argument because risk-signal computation lives outside the
// summary's own state — the summary owns counts, not the timeline
// data that produces signals.
func (s ComplianceSummary) SecurityState(upcoming findings.ThresholdItems) SecurityState {
	if s.Violations > 0 {
		return StateNonCompliant
	}
	if upcoming.HasAnyRisk() {
		return StateAtRisk
	}
	return StateCompliant
}

// DeriveSecurityState is a thin wrapper around
// ComplianceSummary.SecurityState for callers that have a violation
// count in hand without a full summary value yet (assessor at the
// moment it constructs the report). New code should prefer the
// method when a summary already exists.
func DeriveSecurityState(violations int, upcoming findings.ThresholdItems) SecurityState {
	return ComplianceSummary{Violations: violations}.SecurityState(upcoming)
}

// Verdict represents the final outcome of a security control check against a resource.
type Verdict string

const (
	VerdictViolation     Verdict = "VIOLATION"
	VerdictPass          Verdict = "PASS"
	VerdictInconclusive  Verdict = "INCONCLUSIVE"
	VerdictNotApplicable Verdict = "NOT_APPLICABLE"
	VerdictSkipped       Verdict = "SKIPPED"
)

// ResourceCheck captures the granular result for a single control/asset pairing.
type ResourceCheck struct {
	ControlID    kernel.ControlID   `json:"control_id"`
	AssetID      asset.ID           `json:"asset_id"`
	AssetType    kernel.AssetType   `json:"asset_type"`
	AssetDomain  kernel.AssetDomain `json:"asset_domain"`
	Verdict      Verdict            `json:"verdict"`
	Confidence   ConfidenceLevel    `json:"confidence"`
	Evidence     *Evidence          `json:"evidence,omitempty"`
	TemporalRisk string             `json:"temporal_risk,omitempty"`
	Reason       string             `json:"reason,omitempty"`
}

// MarkInconclusive shifts a check to an inconclusive state with a specific explanation.
func (c *ResourceCheck) MarkInconclusive(reason string) {
	if c == nil {
		return
	}
	c.Verdict = VerdictInconclusive
	c.Confidence = ConfidenceInconclusive
	c.Reason = reason
}

// IsViolation reports whether the check produced a violation
// verdict. Replaces the c.Verdict == VerdictViolation comparisons
// at the assessor / evidence-hook / domain-summary / verify / export
// call sites so a future verdict-vocabulary change is a single-line
// edit on the type rather than a sweep.
func (c *ResourceCheck) IsViolation() bool {
	return c != nil && c.Verdict == VerdictViolation
}

// IsPass reports whether the check produced a pass verdict.
func (c *ResourceCheck) IsPass() bool {
	return c != nil && c.Verdict == VerdictPass
}

// IsInconclusive reports whether the check produced an inconclusive
// verdict — usually missing data or a degraded predicate evaluation
// rather than a definite pass/fail.
func (c *ResourceCheck) IsInconclusive() bool {
	return c != nil && c.Verdict == VerdictInconclusive
}

// ComplianceSummary provides high-level metrics for an evaluation run.
type ComplianceSummary struct {
	TotalAssets                 int                  `json:"total_assets"`
	ExposedResources            int                  `json:"exposed_resources"`
	Violations                  int                  `json:"violations"`
	FrameworkReadiness          []FrameworkReadiness `json:"framework_readiness,omitempty"`
	FrameworkCitationsSatisfied int                  `json:"framework_citations_satisfied,omitempty"`
	SuperFix                    *SuperFix            `json:"super_fix,omitempty"`
	NearbyFrameworks            []NearbyFramework    `json:"nearby_frameworks,omitempty"`
}

// FrameworkReadiness shows per-framework compliance scores.
type FrameworkReadiness struct {
	Framework        string `json:"framework"`
	TotalControls    int    `json:"total_controls"`
	PassingControls  int    `json:"passing_controls"`
	ReadinessPercent int    `json:"readiness_percent"`
}

// SuperFix identifies the single highest-impact remediation —
// the violated control that satisfies the most framework citations.
type SuperFix struct {
	ControlID      kernel.ControlID `json:"control_id"`
	FrameworkCount int              `json:"framework_count"`
	Frameworks     []string         `json:"frameworks"`
	CitationsFixed int              `json:"citations_fixed"`
}

// NearbyFramework is a framework the user did not request but is
// nearly compliant with based on the evaluated controls.
type NearbyFramework struct {
	Framework        string `json:"framework"`
	ReadinessPercent int    `json:"readiness_percent"`
	GapCount         int    `json:"gap_count"`
}

// CalculateReadiness computes per-framework readiness scores from
// the evaluated controls and findings. Each framework is scored
// independently: readiness = passing / total × 100.
func (r *ComplianceReport) CalculateReadiness(frameworks []string, allControlIDs []kernel.ControlID, controlCompliance map[kernel.ControlID]map[policy.ComplianceFramework]string) {
	if len(frameworks) == 0 {
		return
	}

	failingIDs := sets.New[kernel.ControlID]()
	for i := range r.Findings {
		failingIDs.Add(r.Findings[i].ControlID)
	}

	var totalCitations int
	readiness := make([]FrameworkReadiness, 0, len(frameworks))

	for _, fw := range frameworks {
		total := 0
		passing := 0
		for _, ctlID := range allControlIDs {
			cc, ok := controlCompliance[ctlID]
			if !ok {
				continue
			}
			if _, hasFW := cc[policy.ComplianceFramework(fw)]; !hasFW {
				continue
			}
			total++
			if !failingIDs.Contains(ctlID) {
				passing++
				totalCitations++
			}
		}
		// A requested framework with zero mapped controls is NOT 100%
		// compliant — that would be a false guarantee. Report 0% so it
		// can never be mistaken for full coverage; TotalControls: 0
		// distinguishes "no controls mapped" from "0 of N passing". The
		// framework stays in the list (the user requested it explicitly)
		// rather than being silently dropped like the nearby path.
		pct := 0
		if total > 0 {
			pct = passing * 100 / total
		}
		readiness = append(readiness, FrameworkReadiness{
			Framework:        fw,
			TotalControls:    total,
			PassingControls:  passing,
			ReadinessPercent: pct,
		})
	}

	r.Summary.FrameworkReadiness = readiness
	r.Summary.FrameworkCitationsSatisfied = totalCitations

	// Super-Fix: find the violated control covering the most frameworks.
	r.Summary.SuperFix = computeSuperFix(failingIDs, controlCompliance, frameworks)

	// Nearby frameworks: check all frameworks for near-readiness.
	requestedSet := sets.New[string](frameworks...)
	r.Summary.NearbyFrameworks = computeNearbyFrameworks(failingIDs, allControlIDs, controlCompliance, requestedSet)
}

func computeSuperFix(failingIDs sets.Set[kernel.ControlID], controlCompliance map[kernel.ControlID]map[policy.ComplianceFramework]string, frameworks []string) *SuperFix {
	fwSet := sets.New[string](frameworks...)

	// Iterate control IDs in sorted order so that when several controls
	// tie for the maximum framework count, the winner is deterministic
	// (the lexicographically-smallest control ID, via the strict > below)
	// rather than chosen by Go map iteration order — identical inputs must
	// yield identical "most impactful fix" recommendations.
	sortedIDs := slices.Sorted(maps.Keys(failingIDs))

	var best *SuperFix
	for _, ctlID := range sortedIDs {
		cc, ok := controlCompliance[ctlID]
		if !ok {
			continue
		}
		var fws []string
		for fw := range cc {
			if fwSet.Contains(string(fw)) {
				fws = append(fws, string(fw))
			}
		}
		// Sort the framework list so SuperFix.Frameworks is stable too.
		slices.Sort(fws)
		if len(fws) > 0 && (best == nil || len(fws) > best.FrameworkCount) {
			best = &SuperFix{
				ControlID:      ctlID,
				FrameworkCount: len(fws),
				Frameworks:     fws,
				CitationsFixed: len(fws),
			}
		}
	}
	return best
}

func computeNearbyFrameworks(failingIDs sets.Set[kernel.ControlID], allControlIDs []kernel.ControlID, controlCompliance map[kernel.ControlID]map[policy.ComplianceFramework]string, requestedSet sets.Set[string]) []NearbyFramework {
	// Discover all frameworks across all controls.
	allFWs := sets.New[string]()
	for _, cc := range controlCompliance {
		for fw := range cc {
			if !requestedSet.Contains(string(fw)) {
				allFWs.Add(string(fw))
			}
		}
	}

	var nearby []NearbyFramework
	for fw := range allFWs {
		total := 0
		passing := 0
		for _, ctlID := range allControlIDs {
			cc, ok := controlCompliance[ctlID]
			if !ok {
				continue
			}
			if _, has := cc[policy.ComplianceFramework(fw)]; !has {
				continue
			}
			total++
			if !failingIDs.Contains(ctlID) {
				passing++
			}
		}
		if total == 0 {
			continue
		}
		pct := passing * 100 / total
		gap := total - passing
		// Only report frameworks with >= 80% readiness.
		if pct >= 80 {
			nearby = append(nearby, NearbyFramework{
				Framework:        fw,
				ReadinessPercent: pct,
				GapCount:         gap,
			})
		}
	}
	// allFWs is a set (map) iterated in random order; sort the result by
	// framework name so the nearby-frameworks report section is stable
	// between runs with identical inputs (mirrors CompareBaseline's
	// SortBaselineEntries). Rendered directly in finding_writer.go.
	slices.SortFunc(nearby, func(a, b NearbyFramework) int {
		return cmp.Compare(a.Framework, b.Framework)
	})
	return nearby
}

// InputFreshness summarises the age of the input snapshots relative to
// a staleness threshold. Populated by the post-eval freshness pass
// (FM-034). Nil when --skip-freshness is active or no threshold applies.
type InputFreshness struct {
	MostRecent     string  `json:"most_recent"`
	AgeHours       float64 `json:"age_hours"`
	ThresholdHours float64 `json:"threshold_hours"`
	Stale          bool    `json:"stale"`
	StaleFindings  int     `json:"stale_findings"`
}

// SkippedControl identifies a control that was ignored during the run.
type SkippedControl struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	Reason      string           `json:"reason"`
}

// ComplianceReport is the root aggregate of an evaluation execution.
//
// Findings carries violations only — the items that count toward
// Summary.Violations, flip SecurityState, and trigger exit code 3.
//
// MarkerFindings carries findings emitted by TypeMarker controls:
// fact-recording predicates that are NOT violations in isolation
// (e.g. "this S3 bucket is tagged data-classification=phi"). They
// participate in chain detection so cross-resource compounds can
// compose them with violation findings, but never affect posture
// or exit codes on their own.
type ComplianceReport struct {
	Run                RunInfo                       `json:"run"`
	Summary            ComplianceSummary             `json:"summary"`
	SecurityState      SecurityState                 `json:"security_state"`
	RiskSignals        findings.ThresholdItems       `json:"risk_signals,omitempty"`
	Findings           []Finding                     `json:"findings"`
	MarkerFindings     []Finding                     `json:"marker_findings,omitempty"`
	Issues             []Issue                       `json:"issues,omitempty"`
	ChainFindings      []findings.CompoundFinding    `json:"chain_findings,omitempty"`
	NearMissChains     []findings.NearMissChain      `json:"near_miss_chains,omitempty"`
	AttackStageSummary map[kernel.AttackStage]string `json:"attack_stage_summary,omitempty"`
	TopExposures       []findings.ExposureRank       `json:"top_exposures,omitempty"`
	InputFreshness     *InputFreshness               `json:"input_freshness,omitempty"`
	SkippedControls    []SkippedControl              `json:"skipped_controls,omitempty"`
	ExemptedAssets     []asset.ExemptedAsset         `json:"exempted_assets,omitempty"`
	Metadata           Metadata                      `json:"-"`
	Checks             []ResourceCheck               `json:"checks,omitempty"`
	EvidencePackage    *evidence.EvidencePackage     `json:"evidence_package,omitempty"`

	// CompoundOnlyMode signals that atomic findings were suppressed from
	// output (compound-only default). Renderers use this to emit the
	// suppressed count in the summary line.
	CompoundOnlyMode      bool            `json:"compound_only_mode,omitempty"`
	SuppressedAtomicCount int             `json:"suppressed_atomic_count,omitempty"`
	SuppressedBySeverity  *SeverityCounts `json:"suppressed_by_severity,omitempty"`

	// UnchainedHighSeverity lists control IDs of critical/high findings
	// not covered by any compound chain — potential blind spots.
	UnchainedHighSeverity []string `json:"unchained_high_severity,omitempty"`

	// ChainSuggestions lists candidate chain definitions inferred from
	// unchained controls that co-fail on the same asset(s).
	ChainSuggestions []findings.ChainSuggestion `json:"chain_suggestions,omitempty"`
}

// GetFindingByResource retrieves a finding for a specific control/asset pair.
func (r *ComplianceReport) GetFindingByResource(ctlID kernel.ControlID, astID asset.ID) *Finding {
	for i := range r.Findings {
		if r.Findings[i].ControlID == ctlID && r.Findings[i].AssetID == astID {
			return &r.Findings[i]
		}
	}
	return nil
}

// FindByID returns the finding matching the given FindingID and ok =
// true; ok = false when no finding matches. Replaces the
// open-coded scan in text/finding_writer's Issues renderer where
// a member-FindingID needs to resolve back to its (Control, Asset)
// pair.
func (r *ComplianceReport) FindByID(fid string) (*Finding, bool) {
	if r == nil {
		return nil, false
	}
	for i := range r.Findings {
		if string(r.Findings[i].FindingID) == fid {
			return &r.Findings[i], true
		}
	}
	return nil, false
}

// CountBySeverity tallies the report's findings by the four named
// severity tiers (plus Info for unrecognised values). Wraps the
// package-level CountBySeverity free function so callers can ask
// the report directly — replaces
// evaluation.CountBySeverity(report.Findings) with
// report.CountBySeverity() at the cmd/collect score-summary site.
func (r *ComplianceReport) CountBySeverity() SeverityCounts {
	if r == nil {
		return SeverityCounts{}
	}
	return CountBySeverity(r.Findings)
}

// SLASummary returns the (total, breached) pair that summarises the
// report's SLA posture: total counts findings carrying an SLA
// deadline; breached counts the subset that have lapsed past it.
// Mirrors report.Assessment.SLASummary so callers holding either
// shape can ask the same question of the same name.
//
// Returns (0, 0) on a nil receiver so the cmd/collect posture-score
// path stays non-panicking.
func (r *ComplianceReport) SLASummary() (total, breached int) {
	if r == nil {
		return 0, 0
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		if !f.HasSLA() {
			continue
		}
		total++
		if f.IsOverdue() {
			breached++
		}
	}
	return total, breached
}

// HasAnySLABreach reports whether any finding has breached its SLA,
// regardless of severity. Encapsulates the "scan findings to set a
// caller-side flag" loop the apply runner used to do so callers ask
// the report directly instead of iterating Findings themselves.
func (r *ComplianceReport) HasAnySLABreach() bool {
	if r == nil {
		return false
	}
	for i := range r.Findings {
		if r.Findings[i].IsAnyBreach() {
			return true
		}
	}
	return false
}

// HasCriticalSLABreach reports whether any finding has breached its
// SLA AND is (or escalated to) Critical severity. Used by the apply
// runner's exit-code gate; mirrors HasAnySLABreach so the gating logic
// stays one method call wide.
func (r *ComplianceReport) HasCriticalSLABreach() bool {
	if r == nil {
		return false
	}
	for i := range r.Findings {
		if r.Findings[i].IsCriticalSLABreach() {
			return true
		}
	}
	return false
}

// Package compare provides compliance posture gap analysis between
// two compliance frameworks.
package compare

import (
	"fmt"
	"sort"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Result holds the gap analysis output.
type Result struct {
	GeneratedAt       string            `json:"generated_at"`
	Baseline          ProfileSummary    `json:"baseline"`
	Target            ProfileSummary    `json:"target"`
	AdoptionReadiness AdoptionReadiness `json:"adoption_readiness"`
	SharedViolations  []CompareItem     `json:"shared_violations"`
	TargetOnly        []CompareItem     `json:"target_only_violations"`
	BaselineOnly      []CompareItem     `json:"baseline_only_violations"`
	FreeCoverage      int               `json:"free_coverage_count"`
	Roadmap           Roadmap           `json:"roadmap"`
	LeadershipSummary string            `json:"leadership_summary"`
}

// ProfileSummary describes one side of the comparison.
type ProfileSummary struct {
	Profile string `json:"profile"`
	Total   int    `json:"controls_total"`
	Passing int    `json:"controls_passing"`
	Failing int    `json:"controls_failing"`
}

// AdoptionReadiness holds the marginal cost metrics.
type AdoptionReadiness struct {
	ReadinessPct     float64 `json:"readiness_pct"`
	MarginalFindings int     `json:"marginal_findings"`
	SharedViolations int     `json:"shared_violations"`
	FreeCoverage     int     `json:"free_coverage"`
}

// CompareItem is a finding in the gap analysis.
type CompareItem struct {
	ControlID  string   `json:"control_id"`
	Severity   string   `json:"severity"`
	DwellHours float64  `json:"dwell_hours,omitempty"`
	Baseline   []string `json:"satisfies_baseline,omitempty"`
	Target     []string `json:"satisfies_target,omitempty"`
}

// Roadmap describes the upgrade phases.
type Roadmap struct {
	Phase1 Phase `json:"phase_1"`
	Phase2 Phase `json:"phase_2"`
}

// Phase is one phase of the roadmap.
type Phase struct {
	Description string   `json:"description"`
	Controls    []string `json:"findings"`
	Count       int      `json:"count"`
}

// Input holds the data for gap analysis.
type Input struct {
	GeneratedAt  string
	BaselineName string
	TargetName   string
	BaselineKey  string // compliance framework key
	TargetKey    string
	Findings     []remediation.Finding
}

// Analyze performs the gap analysis between two frameworks.
func Analyze(input Input) *Result {
	// Classify each finding by framework membership.
	type classified struct {
		finding    *remediation.Finding
		inBaseline bool
		inTarget   bool
		failing    bool
	}

	// Collect unique controls and their framework membership.
	controlMap := make(map[string]*classified)

	for i := range input.Findings {
		f := &input.Findings[i]
		cid := string(f.ControlID)
		c, exists := controlMap[cid]
		if !exists {
			c = &classified{finding: f, failing: true}
			controlMap[cid] = c
		}
		if hasFramework(f.ControlCompliance, input.BaselineKey) {
			c.inBaseline = true
		}
		if hasFramework(f.ControlCompliance, input.TargetKey) {
			c.inTarget = true
		}
	}

	// Note: we only see failing controls in findings.
	// Controls that pass don't appear in findings.
	// For free coverage estimation, we need the total control count
	// from framework metadata — approximate from what we can see.

	var shared, targetOnly, baselineOnly []CompareItem
	sevOrder := kernel.SeverityOrder

	for cid, c := range controlMap {
		item := CompareItem{
			ControlID:  cid,
			Severity:   c.finding.ControlSeverity.String(),
			DwellHours: c.finding.Evidence.UnsafeDurationHours,
		}
		if c.inBaseline {
			item.Baseline = extractCitations(c.finding.ControlCompliance, input.BaselineKey)
		}
		if c.inTarget {
			item.Target = extractCitations(c.finding.ControlCompliance, input.TargetKey)
		}

		switch {
		case c.inBaseline && c.inTarget:
			shared = append(shared, item)
		case c.inBaseline && !c.inTarget:
			baselineOnly = append(baselineOnly, item)
		case !c.inBaseline && c.inTarget:
			targetOnly = append(targetOnly, item)
		}
	}

	// Sort: shared by severity, target-only by severity.
	sortBySeverity := func(items []CompareItem) {
		sort.Slice(items, func(i, j int) bool {
			si := sevOrder[strings.ToLower(items[i].Severity)]
			sj := sevOrder[strings.ToLower(items[j].Severity)]
			if si != sj {
				return si < sj
			}
			return items[i].ControlID < items[j].ControlID
		})
	}
	sortBySeverity(shared)
	sortBySeverity(targetOnly)
	sortBySeverity(baselineOnly)

	// Profile summaries from what we can observe.
	baselineTotal := len(shared) + len(baselineOnly)
	targetTotal := len(shared) + len(targetOnly)
	baselineFailing := baselineTotal // all observed are failing
	targetFailing := len(shared) + len(targetOnly)

	// Readiness: controls in target that are not failing.
	// Since we only see failures, we can't know passing count precisely.
	// Readiness = 1 - (target_only_violations / target_total_estimated).
	readinessPct := 0.0
	if targetTotal > 0 {
		readinessPct = (1.0 - float64(len(targetOnly))/float64(targetTotal)) * 100
	}

	// Roadmap.
	var phase1IDs, phase2IDs []string
	for _, s := range shared {
		phase1IDs = append(phase1IDs, s.ControlID)
	}
	for _, s := range targetOnly {
		phase2IDs = append(phase2IDs, s.ControlID)
	}

	// Leadership summary.
	summary := fmt.Sprintf("Your current %s compliance program provides %.1f%% coverage toward %s. "+
		"Adopting %s requires fixing %d additional findings — %d of which also improve %s posture.",
		input.BaselineName, readinessPct, input.TargetName,
		input.TargetName, len(targetOnly)+len(shared), len(shared), input.BaselineName)

	return &Result{
		GeneratedAt: input.GeneratedAt,
		Baseline: ProfileSummary{
			Profile: input.BaselineName,
			Total:   baselineTotal,
			Failing: baselineFailing,
		},
		Target: ProfileSummary{
			Profile: input.TargetName,
			Total:   targetTotal,
			Failing: targetFailing,
		},
		AdoptionReadiness: AdoptionReadiness{
			ReadinessPct:     readinessPct,
			MarginalFindings: len(targetOnly),
			SharedViolations: len(shared),
		},
		SharedViolations: shared,
		TargetOnly:       targetOnly,
		BaselineOnly:     baselineOnly,
		Roadmap: Roadmap{
			Phase1: Phase{
				Description: "Fix shared violations — improves both frameworks",
				Controls:    phase1IDs,
				Count:       len(phase1IDs),
			},
			Phase2: Phase{
				Description: "Fix target-specific gaps — completes adoption",
				Controls:    phase2IDs,
				Count:       len(phase2IDs),
			},
		},
		LeadershipSummary: summary,
	}
}

func hasFramework(compliance policy.ComplianceMapping, key string) bool {
	if compliance == nil {
		return false
	}
	_, ok := compliance[policy.ComplianceFramework(key)]
	return ok
}

func extractCitations(compliance policy.ComplianceMapping, key string) []string {
	if compliance == nil {
		return nil
	}
	cite, ok := compliance[policy.ComplianceFramework(key)]
	if !ok || cite == "" {
		return nil
	}
	return []string{cite}
}

// Package execreport aggregates all assessment dimensions into a
// single executive report document.
package execreport

import (
	"fmt"
	"strings"
)

// Report is the top-level executive report structure.
type Report struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	Title         string `json:"title"`
	Period        string `json:"period"`
	PeriodStart   string `json:"period_start,omitempty"`
	PeriodEnd     string `json:"period_end,omitempty"`

	Posture          PostureSection        `json:"posture"`
	FindingsSummary  FindingsSummary       `json:"findings_summary"`
	SLA              *SLASection           `json:"sla,omitempty"`
	TopFindings      []TopFinding          `json:"top_findings"`
	Chains           ChainsSection         `json:"chains"`
	AttackCoverage   AttackCoverageSection `json:"attack_coverage"`
	FrameworkReady   []FrameworkReadiness  `json:"framework_readiness,omitempty"`
	Teams            []TeamSection         `json:"teams,omitempty"`
	Catalog          CatalogSection        `json:"catalog"`
	ExecutiveSummary ExecutiveSummary      `json:"executive_summary"`
}

// Trajectory classifies the recent posture-score movement. The
// closed vocabulary lets renderers and downstream alerting compare
// against named constants instead of repeating string literals.
type Trajectory string

const (
	TrajectoryStable     Trajectory = "STABLE"
	TrajectoryImproving  Trajectory = "IMPROVING"
	TrajectoryRegressing Trajectory = "REGRESSING"
)

// PostureBand represents the posture classification category.
type PostureBand string

const (
	BandCritical  PostureBand = "CRITICAL"
	BandPoor      PostureBand = "POOR"
	BandFair      PostureBand = "FAIR"
	BandGood      PostureBand = "GOOD"
	BandStrong    PostureBand = "STRONG"
	BandExcellent PostureBand = "EXCELLENT"
)

// PostureSection holds posture score data.
type PostureSection struct {
	Score           float64            `json:"score"`
	Band            PostureBand        `json:"band"`
	BandDescription string             `json:"band_description"`
	Delta30d        float64            `json:"delta_30d"`
	Trajectory      Trajectory         `json:"trajectory"`
	Dimensions      map[string]float64 `json:"dimensions,omitempty"`
	Sparkline       []float64          `json:"sparkline,omitempty"`
}

// FindingsSummary holds finding counts.
type FindingsSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// SLASection holds SLA compliance data.
type SLASection struct {
	ProfileName   string             `json:"profile_name"`
	CompliancePct float64            `json:"compliance_overall_pct"`
	BySeverity    map[string]SLASev  `json:"by_severity"`
	BurnRates     map[string]float64 `json:"burn_rates"`
}

// SLASev holds per-severity SLA data.
type SLASev struct {
	Total    int     `json:"total"`
	Within   int     `json:"within_sla"`
	Breached int     `json:"breached"`
	Pct      float64 `json:"pct"`
}

// TopFinding is a ranked finding for the report.
type TopFinding struct {
	Rank              int      `json:"rank"`
	ControlID         string   `json:"control_id"`
	Severity          string   `json:"severity"`
	AssetID           string   `json:"asset_id,omitempty"`
	Team              string   `json:"team,omitempty"`
	DwellHours        float64  `json:"dwell_hours"`
	SLABurnRate       float64  `json:"sla_burn_rate,omitempty"`
	SLABreached       bool     `json:"sla_breached,omitempty"`
	RemediationAction string   `json:"remediation_action,omitempty"`
	Frameworks        []string `json:"compliance_frameworks,omitempty"`
}

// IsAnyBreach reports whether the underlying finding has breached
// its SLA. Mirrors evaluation.Finding.IsAnyBreach so the markdown
// renderer asks the DTO for the answer instead of reading the field
// directly.
func (t *TopFinding) IsAnyBreach() bool {
	return t != nil && t.SLABreached
}

// ChainsSection holds active chain data.
type ChainsSection struct {
	ActiveCount int           `json:"active_count"`
	Active      []ActiveChain `json:"active,omitempty"`
}

// ActiveChain is an active compound chain.
type ActiveChain struct {
	ChainID   string   `json:"chain_id"`
	Severity  string   `json:"severity"`
	Members   []string `json:"member_findings"`
	Narrative string   `json:"narrative,omitempty"`
}

// AttackCoverageSection holds ATT&CK data.
type AttackCoverageSection struct {
	TacticsCovered int          `json:"tactics_covered"`
	TacticsTotal   int          `json:"tactics_total"`
	CoveragePct    float64      `json:"coverage_pct"`
	ByTactic       []TacticItem `json:"by_tactic,omitempty"`
}

// TacticItem is a single ATT&CK tactic.
type TacticItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Controls int    `json:"controls"`
	Status   string `json:"status"`
}

// FrameworkReadiness holds compliance framework data.
type FrameworkReadiness struct {
	Framework    string  `json:"framework"`
	Total        int     `json:"controls_total"`
	Passing      int     `json:"controls_passing"`
	Failing      int     `json:"controls_failing"`
	ReadinessPct float64 `json:"readiness_pct"`
}

// TeamSection holds per-team data.
type TeamSection struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Score        float64    `json:"posture_score"`
	Trajectory   Trajectory `json:"trajectory"`
	OpenFindings int        `json:"open_findings"`
	CriticalOpen int        `json:"critical_open"`
	SLACompPct   float64    `json:"sla_compliance_pct"`
	MTTRHours    float64    `json:"mttr_hours"`
	Contact      string     `json:"contact,omitempty"`
}

// CatalogSection holds catalog metadata.
type CatalogSection struct {
	ControlsTotal int `json:"controls_total"`
	ChainsTotal   int `json:"chains_total"`
}

// ExecutiveSummary holds generated summary text.
type ExecutiveSummary struct {
	OneLiner  string          `json:"one_liner"`
	Paragraph string          `json:"paragraph"`
	Attention []AttentionItem `json:"attention_required,omitempty"`
	Positive  []string        `json:"positive_signals,omitempty"`
}

// AttentionItem is something requiring executive attention.
type AttentionItem struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
	Contact string `json:"contact,omitempty"`
	Action  string `json:"action,omitempty"`
}

// Band classifies a posture score into a PostureBand and description.
func Band(score float64) (name PostureBand, description string) {
	switch {
	case score < 40:
		return BandCritical, "Immediate executive escalation required"
	case score < 60:
		return BandPoor, "Significant risk, remediation plan required"
	case score < 70:
		return BandFair, "Moderate risk, active improvement needed"
	case score < 85:
		return BandGood, "Manageable risk, SLA compliance is key"
	case score < 95:
		return BandStrong, "Strong posture, maintain vigilance"
	default:
		return BandExcellent, "Exemplary posture"
	}
}

// GenerateSummary produces the executive summary from report data.
func GenerateSummary(r *Report) ExecutiveSummary {
	if r == nil {
		return ExecutiveSummary{}
	}
	score := r.Posture.Score
	delta := r.Posture.Delta30d
	period := r.Period
	if period == "" {
		period = "the reporting period"
	}

	// Direction.
	direction := fmt.Sprintf("remained stable at %.1f", score)
	if delta > 0 {
		direction = fmt.Sprintf("improved %.1f points to %.1f", delta, score)
	} else if delta < 0 {
		direction = fmt.Sprintf("declined %.1f points to %.1f", -delta, score)
	}

	// One-liner.
	oneLiner := fmt.Sprintf("Posture %s during %s.", direction, period)
	if len(r.Teams) > 0 {
		regressing := 0
		for _, t := range r.Teams {
			if t.Trajectory == "REGRESSING" {
				regressing++
			}
		}
		if regressing > 0 {
			oneLiner += fmt.Sprintf(" %d team(s) require attention.", regressing)
		}
	}

	// Paragraph.
	var parts []string
	parts = append(parts, fmt.Sprintf("Account security posture %s during %s.", direction, period))
	parts = append(parts, fmt.Sprintf("%d findings are currently open.", r.FindingsSummary.Total))

	if r.Chains.ActiveCount > 0 {
		parts = append(parts, fmt.Sprintf("%d active compound chain(s) indicate elevated risk.", r.Chains.ActiveCount))
	}

	for _, t := range r.Teams {
		if t.Trajectory == "REGRESSING" {
			parts = append(parts, fmt.Sprintf("Team %s is regressing (score %.1f) with %d critical findings.", t.Name, t.Score, t.CriticalOpen))
		}
	}

	for _, fw := range r.FrameworkReady {
		if fw.Failing > 0 {
			parts = append(parts, fmt.Sprintf("%s compliance is %.1f%% — %d controls require remediation.", fw.Framework, fw.ReadinessPct, fw.Failing))
		}
	}

	// Attention items.
	var attention []AttentionItem
	for _, t := range r.Teams {
		if t.Trajectory == "REGRESSING" {
			attention = append(attention, AttentionItem{
				Subject: t.Name,
				Reason:  fmt.Sprintf("Score %.1f, %d critical findings open", t.Score, t.CriticalOpen),
				Contact: t.Contact,
			})
		}
	}

	// Positive signals.
	var positive []string
	if r.Posture.Delta30d > 0 {
		positive = append(positive, fmt.Sprintf("Posture improved %.1f points", r.Posture.Delta30d))
	}
	if r.AttackCoverage.TacticsCovered == r.AttackCoverage.TacticsTotal && r.AttackCoverage.TacticsTotal > 0 {
		positive = append(positive, fmt.Sprintf("Full ATT&CK tactic coverage (%d/%d)", r.AttackCoverage.TacticsCovered, r.AttackCoverage.TacticsTotal))
	}

	return ExecutiveSummary{
		OneLiner:  oneLiner,
		Paragraph: strings.Join(parts, " "),
		Attention: attention,
		Positive:  positive,
	}
}

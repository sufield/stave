package contracts

import (
	"encoding/json"
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
)

// HygieneAssessment bundles the metrics required to evaluate the health of the
// security audit trail and the urgency of pending remediations.
type HygieneAssessment struct {
	AuditContext    AuditContext
	Evidence        EvidenceInventory
	SLAPosture      SLAPosture
	ExposureHistory []evaluation.TrendMetric
}

// AuditContext provides the temporal boundaries for the hygiene report.
type AuditContext struct {
	Now             time.Time
	PreviousAuditAt time.Time
	LookbackWindow  time.Duration
	SLAWarning      time.Duration
}

// EvidenceInventory summarizes the state of collected cloud resource snapshots.
type EvidenceInventory struct {
	CurrentInventory   int           `json:"current_inventory"`
	HistoricalEvidence int           `json:"historical_evidence"`
	PurgeCandidates    int           `json:"purge_candidates"`
	ComplianceTier     string        `json:"compliance_tier"`
	RetentionPolicy    time.Duration `json:"retention_policy"`
	MinEvidenceCount   int           `json:"min_evidence_count"`
}

// TotalEvidence returns the sum of current and historical records.
func (s EvidenceInventory) TotalEvidence() int { return s.CurrentInventory + s.HistoricalEvidence }

// MarshalJSON includes the computed total in the JSON output.
func (s EvidenceInventory) MarshalJSON() ([]byte, error) {
	type raw EvidenceInventory
	return json.Marshal(struct {
		raw
		TotalEvidence int `json:"total_evidence"`
	}{raw: raw(s), TotalEvidence: s.TotalEvidence()})
}

// SLAPosture captures the current remediation health against defined thresholds.
type SLAPosture struct {
	ActiveFindings  int `json:"active_findings"`
	SLABreaches     int `json:"sla_breaches"`
	BreachingNow    int `json:"breaching_now"`
	NearBreach      int `json:"near_breach"`
	CompliantWindow int `json:"compliant_window"`
}

// PendingRemediations returns the sum of all findings requiring action.
func (s SLAPosture) PendingRemediations() int {
	return s.SLABreaches + s.BreachingNow + s.NearBreach + s.CompliantWindow
}

// MarshalJSON includes the aggregate pending count.
func (s SLAPosture) MarshalJSON() ([]byte, error) {
	type raw SLAPosture
	return json.Marshal(struct {
		raw
		PendingRemediations int `json:"pending_remediations"`
	}{raw: raw(s), PendingRemediations: s.PendingRemediations()})
}

// NewSLAPosture maps risk threshold summaries into the SLA compliance domain.
func NewSLAPosture(activeFindings int, summary risk.ThresholdSummary) SLAPosture {
	return SLAPosture{
		ActiveFindings:  activeFindings,
		SLABreaches:     summary.Overdue,
		BreachingNow:    summary.DueNow,
		NearBreach:      summary.DueSoon,
		CompliantWindow: summary.Later,
	}
}

// Package consolidate provides multi-account security posture consolidation.
package consolidate

import "time"

// ConsolidatedReport is the output of multi-account consolidation.
type ConsolidatedReport struct {
	GeneratedAt    time.Time             `json:"generated_at"`
	OrgName        string                `json:"org_name"`
	AccountCount   int                   `json:"account_count"`
	SnapshotPeriod SnapshotPeriod        `json:"snapshot_period"`
	Accounts       []AccountSummary      `json:"accounts"`
	OrgPosture     OrgPosture            `json:"org_posture"`
	CrossAccount   []CrossAccountFinding `json:"cross_account_findings,omitempty"`
}

// SnapshotPeriod records the time span of consolidated snapshots.
type SnapshotPeriod struct {
	Earliest    time.Time `json:"earliest"`
	Latest      time.Time `json:"latest"`
	MaxGapHours float64   `json:"max_gap_hours"`
}

// AccountSummary summarizes one account's posture within the org.
type AccountSummary struct {
	AccountID     string    `json:"account_id"`
	AccountName   string    `json:"account_name"`
	Environment   string    `json:"environment"`
	BusinessUnit  string    `json:"business_unit"`
	SnapshotAt    time.Time `json:"snapshot_at"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	MediumCount   int       `json:"medium_count"`
	LowCount      int       `json:"low_count"`
	TotalFindings int       `json:"total_findings"`
	SLABreached   int       `json:"sla_breached_count"`
	ActiveChains  int       `json:"active_chains"`
	RiskScore     float64   `json:"risk_score"`
	OrgRiskRank   int       `json:"org_risk_rank"`
}

// OrgPosture aggregates posture across all accounts.
type OrgPosture struct {
	TotalFindings          int     `json:"total_findings"`
	CriticalFindings       int     `json:"critical_findings"`
	ChainFindings          int     `json:"chain_findings"`
	SLABreached            int     `json:"sla_breached"`
	HighestRiskAccount     string  `json:"highest_risk_account"`
	ProductionRisk         float64 `json:"production_risk_percent"`
	NonProductionRisk      float64 `json:"non_production_risk_percent"`
	CrossAccountIdentities int     `json:"cross_account_identities"`
}

// CrossAccountFinding represents a finding visible only in consolidated view.
type CrossAccountFinding struct {
	FindingID       string   `json:"finding_id"`
	Type            string   `json:"type"`
	SourceAccountID string   `json:"source_account_id"`
	TargetAccountID string   `json:"target_account_id"`
	SourcePrincipal string   `json:"source_principal"`
	TargetResource  string   `json:"target_resource"`
	AttackStageSpan []string `json:"attack_stage_span"`
	Severity        string   `json:"severity"`
	Description     string   `json:"description"`
}

// AccountManifest is the YAML schema for multi-account metadata.
type AccountManifest struct {
	Organization string         `yaml:"organization"`
	Accounts     []AccountEntry `yaml:"accounts"`
}

// AccountEntry describes one account in the manifest.
type AccountEntry struct {
	AccountID    string `yaml:"account_id"`
	AccountName  string `yaml:"account_name"`
	Environment  string `yaml:"environment"`
	BusinessUnit string `yaml:"business_unit"`
	Snapshot     string `yaml:"snapshot"`
}

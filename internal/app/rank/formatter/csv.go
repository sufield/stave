package formatter

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	apprank "github.com/sufield/stave/internal/app/rank"
	"github.com/sufield/stave/internal/core/report"
)

// CSV renders a Roadmap as a CSV table for spreadsheet pipelines.
type CSV struct{}

var _ RoadmapFormatter = (*CSV)(nil)

// findingMeta carries per-finding fields the Roadmap entries don't
// duplicate but the CSV row needs (severity, asset type, owner, SLA,
// chain memberships). Built once from the assessment, looked up by
// "controlID@assetID".
type findingMeta struct {
	severity  string
	assetType string
	chainIDs  []string
	slaHours  string
	slaStatus string
	owner     string
}

// Render writes the roadmap as CSV. The header line is fixed; each
// subsequent row is one Roadmap entry.
func (CSV) Render(w io.Writer, rm apprank.Roadmap, assessment *report.Assessment) error {
	findingIdx := buildFindingIndex(assessment)

	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"rank", "control_id", "control_name", "severity", "asset_id",
		"asset_type", "team", "risk_score", "sla_deadline_hours",
		"sla_status", "chain_membership", "remediation_action",
	}); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}

	for i := range rm.Entries {
		e := &rm.Entries[i]
		key := string(e.ControlID) + "@" + string(e.AssetID)
		m := findingIdx[key]

		severity := ""
		assetType := ""
		owner := ""
		slaHours := ""
		slaStatus := ""
		chainMembership := ""
		if m != nil {
			severity = m.severity
			assetType = m.assetType
			owner = m.owner
			slaHours = m.slaHours
			slaStatus = m.slaStatus
			chainMembership = strings.Join(m.chainIDs, ",")
		}

		if err := cw.Write([]string{
			strconv.Itoa(e.Rank),
			string(e.ControlID),
			e.ControlName,
			severity,
			string(e.AssetID),
			assetType,
			owner,
			fmt.Sprintf("%.1f", e.PriorityScore),
			slaHours,
			slaStatus,
			chainMembership,
			e.FixAction,
		}); err != nil {
			return fmt.Errorf("write csv row %d: %w", e.Rank, err)
		}
	}

	cw.Flush()
	return cw.Error()
}

// buildFindingIndex pre-computes per-(control,asset) metadata so the
// per-row lookup in Render is constant-time. Nil assessment returns
// an empty index — Render must still produce a header + zero rows.
func buildFindingIndex(assessment *report.Assessment) map[string]*findingMeta {
	if assessment == nil {
		return nil
	}
	idx := make(map[string]*findingMeta, len(assessment.Findings))
	for i := range assessment.Findings {
		f := &assessment.Findings[i]
		key := string(f.ControlID) + "@" + string(f.AssetID)
		m := &findingMeta{
			severity:  f.ControlSeverity.String(),
			assetType: string(f.AssetType),
			owner:     f.OwnerTeamID,
		}
		if f.SLADeadlineHours != nil {
			m.slaHours = fmt.Sprintf("%.0f", *f.SLADeadlineHours)
		}
		if f.SLABreached {
			m.slaStatus = "BREACHED"
		} else if f.SLADeadlineHours != nil {
			m.slaStatus = "OK"
		}
		for j := range f.ChainMembership {
			m.chainIDs = append(m.chainIDs, string(f.ChainMembership[j].ChainID))
		}
		idx[key] = m
	}
	return idx
}

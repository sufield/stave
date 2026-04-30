// Package rank implements the 'stave rank' command for producing a
// prioritized remediation roadmap from assessment output.
package rank

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/adapters/observations"
	apprank "github.com/sufield/stave/internal/app/rank"
	"github.com/sufield/stave/internal/app/sprintplanner"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	InputPath           string
	TopN                int
	Format              string
	IncludeAcknowledged bool
	Identity            bool
	SnapshotPath        string
	GroupBy             string
	TeamManifest        string
	SortBy              string
	Capacity            string
	EffortModel         string
}

// NewCmd constructs the top-level rank command.
func NewCmd() *cobra.Command {
	opts := &options{
		TopN:   5,
		Format: "text",
	}

	cmd := &cobra.Command{
		Use:   "rank",
		Short: "Produce a prioritized remediation roadmap from assessment output",
		Long: `Rank reads assessment JSON (from stave apply) and produces a prioritized
remediation roadmap. Findings are ranked by priority score (severity x
duration x blast radius x SLA urgency), grouped by remediation action,
and annotated with risk impact percentages and strategic narratives.

This answers the hardest question in security: "I have 1,000 findings;
what do I fix first to make the environment safest?"

Inputs:
  stdin or --in     Assessment JSON from stave apply --format json
  --top             Number of top findings to show (default: 5)
  --format          Output format: text or json (default: text)

Exit Codes:
  0   Roadmap produced
  2   Input error`,
		Example: `  stave apply --format json | stave rank --top 10
  stave rank --in assessment.json --top 5
  stave rank --in assessment.json --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.InputPath, "in", "", "Path to assessment JSON (default: stdin)")
	cmd.Flags().IntVar(&opts.TopN, "top", opts.TopN, "Number of top findings to show")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "Output format: text or json")
	cmd.Flags().BoolVar(&opts.IncludeAcknowledged, "include-acknowledged", false, "Include acknowledged findings in output")
	cmd.Flags().BoolVar(&opts.Identity, "identity", false, "Identity-centric blast radius ranking")
	cmd.Flags().StringVar(&opts.SnapshotPath, "snapshot", "", "Path to observation snapshot (required for --identity)")
	cmd.Flags().StringVar(&opts.GroupBy, "group-by", "", "Group roadmap by field (owner)")
	cmd.Flags().StringVar(&opts.TeamManifest, "team-manifest", "", "Path to stave-teams.yaml")
	cmd.Flags().StringVar(&opts.SortBy, "sort-by", "severity", "Sort order: severity | blast-radius | sla")
	cmd.Flags().StringVar(&opts.Capacity, "capacity", "", "Engineer-hour budget for sprint planning (e.g. 40h, 5d)")
	cmd.Flags().StringVar(&opts.EffortModel, "effort-model", "", "Path to effort model YAML (control_id -> hours)")

	return cmd
}

func run(stdout, _ io.Writer, opts *options) error {
	// Read assessment JSON.
	var data []byte
	var err error
	if opts.InputPath != "" {
		inputPath := fsutil.CleanUserPath(opts.InputPath)
		data, err = os.ReadFile(inputPath) //nolint:gosec // user-specified path, cleaned via fsutil.CleanUserPath
		if err != nil {
			return fmt.Errorf("read %s: %w", inputPath, err)
		}
	} else {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
	}

	if len(data) == 0 {
		return errors.New("no assessment data provided (pipe from stave apply --format json or use --in)")
	}

	// Parse assessment.
	var assessment report.Assessment
	if jsonErr := json.Unmarshal(data, &assessment); jsonErr != nil {
		return fmt.Errorf("parse assessment: %w", jsonErr)
	}

	// Identity-centric ranking.
	if opts.Identity {
		return runIdentity(stdout, opts, &assessment)
	}

	// Sprint planning mode.
	if opts.Capacity != "" {
		return runSprint(stdout, opts, &assessment)
	}

	// Build roadmap.
	roadmap := apprank.BuildRoadmap(assessment.Findings, assessment.TopExposures, opts.TopN)

	// Re-sort by blast radius if requested.
	if opts.SortBy == "blast-radius" {
		blastIndex := buildBlastIndex(&assessment)
		slices.SortFunc(roadmap.Entries, func(a, b apprank.PriorityEntry) int {
			as := blastIndex[string(a.ControlID)+"@"+string(a.AssetID)]
			bs := blastIndex[string(b.ControlID)+"@"+string(b.AssetID)]
			if as > bs {
				return -1
			}
			if as < bs {
				return 1
			}
			return 0
		})
		for i := range roadmap.Entries {
			roadmap.Entries[i].Rank = i + 1
		}
	}

	// Group by owner if requested.
	if opts.GroupBy == "owner" {
		return runGroupByOwner(stdout, opts, &assessment, roadmap)
	}

	// Output.
	switch opts.Format {
	case "json":
		output, marshalErr := json.MarshalIndent(roadmap, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshal roadmap: %w", marshalErr)
		}
		fmt.Fprintln(stdout, string(output))
	case "csv":
		if err := writeCSVRoadmap(stdout, roadmap, &assessment); err != nil {
			return fmt.Errorf("write CSV roadmap: %w", err)
		}
	default:
		writeTextRoadmap(stdout, roadmap, opts.SortBy == "blast-radius", &assessment)
	}

	// Show acknowledged findings if requested.
	if opts.IncludeAcknowledged && len(assessment.AcknowledgedFindings) > 0 {
		fmt.Fprintf(stdout, "\nACKNOWLEDGED FINDINGS (%d)\n", len(assessment.AcknowledgedFindings))
		fmt.Fprintln(stdout, strings.Repeat("-", 50))
		for i := range assessment.AcknowledgedFindings {
			af := &assessment.AcknowledgedFindings[i]
			status := "[ACK]"
			if !af.Valid {
				status = "[INVALID: " + af.InvalidReason + "]"
			}
			fmt.Fprintf(stdout, "  %s  %s on %s\n", status, af.ControlID, af.AssetID)
			if af.Rationale != "" {
				fmt.Fprintf(stdout, "         Rationale: %s\n", af.Rationale)
			}
			if af.AcknowledgedBy != "" {
				fmt.Fprintf(stdout, "         By: %s on %s\n", af.AcknowledgedBy, af.AcknowledgedDate)
			}
			if af.ExpiryDate != "" {
				fmt.Fprintf(stdout, "         Expires: %s\n", af.ExpiryDate)
			}
		}
	}

	return nil
}

func buildBlastIndex(a *report.Assessment) map[string]float64 {
	idx := make(map[string]float64, len(a.Findings))
	for i := range a.Findings {
		f := &a.Findings[i]
		if f.Reachability != nil {
			idx[string(f.ControlID)+"@"+string(f.AssetID)] = f.Reachability.BlastRadiusScore
		}
	}
	return idx
}

func writeTextRoadmap(w io.Writer, rm apprank.Roadmap, showReach bool, assessment *report.Assessment) {
	if len(rm.Entries) == 0 {
		fmt.Fprintln(w, "No findings to rank.")
		return
	}

	fmt.Fprintf(w, "REMEDIATION STRATEGY (Top %d Actions)\n", len(rm.Entries))
	fmt.Fprintln(w, strings.Repeat("=", 50))

	for idx := range rm.Entries {
		e := &rm.Entries[idx]
		severity := "HIGH"
		if e.PriorityScore >= 500 {
			severity = "CRITICAL"
		} else if e.PriorityScore < 100 {
			severity = "MEDIUM"
		}

		fmt.Fprintf(w, "\n[#%d]  PRIORITY: %.1f (%s)\n", e.Rank, e.PriorityScore, severity)
		if e.IsChainMember {
			fmt.Fprintf(w, "      [ATTACK PATH: %s]  %s on %s\n", e.ChainID, e.ControlID, e.AssetID)
		} else {
			fmt.Fprintf(w, "      %s on %s\n", e.ControlID, e.AssetID)
		}
		if showReach && assessment != nil {
			key := string(e.ControlID) + "@" + string(e.AssetID)
			blastIdx := buildBlastIndex(assessment)
			if score, ok := blastIdx[key]; ok {
				fmt.Fprintf(w, "      Reach: blast_radius=%.0f\n", score)
			} else {
				fmt.Fprintf(w, "      Reach: \u2014\n")
			}
		}
		if e.SLABreached {
			fmt.Fprintf(w, "      SLA: BREACHED  %s overdue\n", e.SLAOverdue)
		}
		if e.Narrative != "" {
			fmt.Fprintf(w, "      %s\n", e.Narrative)
		}
		fmt.Fprintf(w, "      Risk Impact: %.0f%% of total environment risk  |  Changes: %d  |  Confidence: %.0f%%\n",
			e.RiskImpact, len(e.Changes), e.Confidence*100)

		b := &e.Breakdown
		fmt.Fprintf(w, "      Score: base=%d \u00d7 duration=%.1f \u00d7 blast=%.1f \u00d7 exposure=%.1f",
			b.BaseScore, b.DurationFactor, b.BlastMultiplier, b.ExposureMultiplier)
		if e.SLAUrgency > 1.0 {
			fmt.Fprintf(w, " \u00d7 sla=%.1f", e.SLAUrgency)
		}
		fmt.Fprintln(w)

		if e.FixAction != "" {
			action := e.FixAction
			if len(action) > 80 {
				action = action[:77] + "..."
			}
			fmt.Fprintf(w, "      Fix: %s\n", action)
		}
	}

	if len(rm.Bundles) > 0 {
		fmt.Fprintf(w, "\nREMEDIATION BUNDLES (Highest ROI)\n")
		fmt.Fprintln(w, strings.Repeat("-", 40))
		for i, b := range rm.Bundles {
			action := b.Action
			if len(action) > 60 {
				action = action[:57] + "..."
			}
			fmt.Fprintf(w, "  %d. Resolve %d findings (risk reduced: %.0f, efficiency: %.1f)\n",
				i+1, b.FindingCount, b.TotalRiskReduced, b.Efficiency)
			fmt.Fprintf(w, "     %s\n", action)
		}
	}
}

// TeamRoadmap groups prioritized entries by team.
type TeamRoadmap struct {
	TeamID       string                  `json:"team_id"`
	TeamName     string                  `json:"team_name"`
	FindingCount int                     `json:"finding_count"`
	TotalRisk    float64                 `json:"total_risk_score"`
	SLABreaches  int                     `json:"sla_breaches"`
	ActiveChains int                     `json:"active_chains"`
	Entries      []apprank.PriorityEntry `json:"entries"`
}

func runGroupByOwner(stdout io.Writer, opts *options, _ *report.Assessment, roadmap apprank.Roadmap) error {
	manifestPath := opts.TeamManifest
	if manifestPath == "" {
		manifestPath = "stave-teams.yaml"
	}
	manifest, err := teams.LoadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("load team manifest: %w", err)
	}

	// Group entries by team.
	teamMap := make(map[string]*TeamRoadmap)
	for i := range roadmap.Entries {
		e := &roadmap.Entries[i]
		owner := manifest.ResolveOwner(nil, string(e.AssetID), string(e.ControlID))
		tr, ok := teamMap[owner.TeamID]
		if !ok {
			tr = &TeamRoadmap{TeamID: owner.TeamID, TeamName: owner.TeamName}
			teamMap[owner.TeamID] = tr
		}
		tr.FindingCount++
		tr.TotalRisk += e.PriorityScore
		if e.SLABreached {
			tr.SLABreaches++
		}
		if e.IsChainMember {
			tr.ActiveChains++
		}
		tr.Entries = append(tr.Entries, *e)
	}

	// Collect teams sorted by total risk (highest first).
	var teamRoadmaps []TeamRoadmap
	for _, tr := range teamMap {
		teamRoadmaps = append(teamRoadmaps, *tr)
	}
	slices.SortFunc(teamRoadmaps, func(a, b TeamRoadmap) int {
		if a.TotalRisk > b.TotalRisk {
			return -1
		}
		if a.TotalRisk < b.TotalRisk {
			return 1
		}
		return strings.Compare(a.TeamID, b.TeamID)
	})

	switch opts.Format {
	case "json":
		output := struct {
			Roadmap      apprank.Roadmap `json:"roadmap"`
			TeamRoadmaps []TeamRoadmap   `json:"team_roadmaps"`
		}{Roadmap: roadmap, TeamRoadmaps: teamRoadmaps}
		data, marshalErr := json.MarshalIndent(output, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshal grouped roadmap: %w", marshalErr)
		}
		fmt.Fprintln(stdout, string(data))
	default:
		for _, tr := range teamRoadmaps {
			fmt.Fprintf(stdout, "\nTEAM: %s (%s)\n", tr.TeamName, tr.TeamID)
			fmt.Fprintf(stdout, "  Findings: %d  |  Risk Score: %.0f  |  SLA Breaches: %d  |  Active Chains: %d\n",
				tr.FindingCount, tr.TotalRisk, tr.SLABreaches, tr.ActiveChains)
			fmt.Fprintln(stdout, strings.Repeat("-", 60))
			for j := range tr.Entries {
				e := &tr.Entries[j]
				fmt.Fprintf(stdout, "  [#%d]  %.1f  %s on %s\n", e.Rank, e.PriorityScore, e.ControlID, e.AssetID)
			}
		}
	}
	return nil
}

func runIdentity(stdout io.Writer, opts *options, assessment *report.Assessment) error {
	if opts.SnapshotPath == "" {
		return errors.New("--snapshot is required for --identity (path to observation snapshots)")
	}

	snapshots, err := observations.LoadBundle(opts.SnapshotPath)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}

	ranking := apprank.BuildIdentityRanking(apprank.IdentityRankingConfig{
		Findings:     assessment.Findings,
		TopExposures: assessment.TopExposures,
		Snapshots:    snapshots,
		TopN:         opts.TopN,
	})

	switch opts.Format {
	case "json":
		output, marshalErr := json.MarshalIndent(ranking, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshal identity ranking: %w", marshalErr)
		}
		fmt.Fprintln(stdout, string(output))
	default:
		writeTextIdentityRanking(stdout, ranking)
	}
	return nil
}

func writeCSVRoadmap(w io.Writer, rm apprank.Roadmap, assessment *report.Assessment) error {
	// Build a finding index for enrichment.
	type findingMeta struct {
		severity  string
		assetType string
		chainIDs  []string
		slaHours  string
		slaStatus string
		owner     string
	}
	findingIdx := make(map[string]*findingMeta)
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
			m.chainIDs = append(m.chainIDs, f.ChainMembership[j].ChainID)
		}
		findingIdx[key] = m
	}

	cw := csv.NewWriter(w)

	// Header.
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

func runSprint(stdout io.Writer, opts *options, assessment *report.Assessment) error {
	capacityHours, err := parseCapacity(opts.Capacity)
	if err != nil {
		return fmt.Errorf("invalid --capacity %q: %w", opts.Capacity, err)
	}

	var controlHours map[string]float64
	if opts.EffortModel != "" {
		effortPath := fsutil.CleanUserPath(opts.EffortModel)
		data, readErr := os.ReadFile(effortPath) //nolint:gosec // user-specified path, cleaned via fsutil.CleanUserPath
		if readErr != nil {
			return fmt.Errorf("read effort model: %w", readErr)
		}
		controlHours = make(map[string]float64)
		if yamlErr := yaml.Unmarshal(data, &controlHours); yamlErr != nil {
			return fmt.Errorf("parse effort model: %w", yamlErr)
		}
	}

	result := sprintplanner.Plan(sprintplanner.Input{
		Findings:      assessment.Findings,
		CapacityHours: capacityHours,
		DefaultHours:  4,
		ControlHours:  controlHours,
	})

	switch opts.Format {
	case "json":
		output, marshalErr := json.MarshalIndent(result, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshal sprint result: %w", marshalErr)
		}
		fmt.Fprintln(stdout, string(output))
	default:
		writeTextSprint(stdout, result)
	}
	return nil
}

func parseCapacity(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty capacity")
	}

	if before, ok := strings.CutSuffix(s, "d"); ok {
		val, err := strconv.ParseFloat(before, 64)
		if err != nil {
			return 0, err
		}
		return val * 8, nil
	}

	if before, ok := strings.CutSuffix(s, "h"); ok {
		val, err := strconv.ParseFloat(before, 64)
		if err != nil {
			return 0, err
		}
		return val, nil
	}

	// Try bare number as hours.
	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, errors.New("use format: 40h or 5d")
	}
	return val, nil
}

func writeTextSprint(w io.Writer, r sprintplanner.SprintResult) {
	fmt.Fprintf(w, "SPRINT PLAN (%.0fh capacity)\n", r.Capacity)
	fmt.Fprintln(w, strings.Repeat("=", 60))

	if len(r.Items) == 0 {
		fmt.Fprintln(w, "No items fit within the capacity budget.")
		return
	}

	fmt.Fprintf(w, "\nINCLUDED (%d items, %.1fh total, %.1f risk reduction)\n",
		len(r.Items), r.TotalHours, r.RiskReduction)
	fmt.Fprintln(w, strings.Repeat("-", 60))
	fmt.Fprintf(w, "  %-8s %-30s %-15s %6s %6s\n", "Severity", "Control", "Asset", "Hours", "ROI")

	for i := range r.Items {
		item := &r.Items[i]
		ctl := item.ControlID
		if len(ctl) > 30 {
			ctl = ctl[:27] + "..."
		}
		ast := item.AssetID
		if len(ast) > 15 {
			ast = ast[:12] + "..."
		}
		fmt.Fprintf(w, "  %-8s %-30s %-15s %6.1f %6.1f\n",
			strings.ToUpper(item.Severity), ctl, ast, item.EffortHours, item.ROI)
	}

	if len(r.LeftOut) > 0 {
		fmt.Fprintf(w, "\nLEFT OUT (%d items)\n", len(r.LeftOut))
		fmt.Fprintln(w, strings.Repeat("-", 60))
		for i := range r.LeftOut {
			item := &r.LeftOut[i]
			fmt.Fprintf(w, "  %-8s %s on %s (%.1fh)\n",
				strings.ToUpper(item.Severity), item.ControlID, item.AssetID, item.EffortHours)
		}
	}
}

func writeTextIdentityRanking(w io.Writer, ranking apprank.IdentityRanking) {
	if len(ranking.Entries) == 0 {
		fmt.Fprintln(w, "No identity risk entries found.")
		return
	}

	fmt.Fprintf(w, "IDENTITY BLAST RADIUS RANKING\n")
	fmt.Fprintf(w, "Identities evaluated: %d  |  Total risk score: %.0f\n",
		ranking.IdentitiesEvaluated, ranking.TotalPortfolioRisk)
	fmt.Fprintln(w, strings.Repeat("=", 90))

	for idx := range ranking.Entries {
		e := &ranking.Entries[idx]

		privilegeLabel := strings.ToUpper(e.PrivilegeLevel)
		if privilegeLabel == "" {
			privilegeLabel = "STANDARD"
		}

		directLabel := "\u2014"
		if len(e.DirectFindingIDs) > 0 {
			directLabel = fmt.Sprintf("%d findings (%s)", len(e.DirectFindingIDs), strings.ToUpper(e.DirectSeverity))
		}

		fmt.Fprintf(w, "\n[#%d]  %s\n", e.Rank, e.IdentityARN)
		fmt.Fprintf(w, "      Type: %s  |  Privilege: %s  |  Reaches: %d resources  |  Risk\u2193 %.1f%%\n",
			e.IdentityType, privilegeLabel, e.ReachableCount, e.RiskReductionPercent)
		fmt.Fprintf(w, "      Direct: %s\n", directLabel)

		if len(e.ReachableResources) > 0 {
			fmt.Fprintf(w, "      Reachable resources with findings:\n")
			limit := min(len(e.ReachableResources), 10)
			for ri := range limit {
				rr := &e.ReachableResources[ri]
				if len(rr.FindingIDs) == 0 {
					continue
				}
				sevLabel := strings.ToUpper(rr.MaxSeverity)
				if sevLabel == "" {
					sevLabel = "?"
				}
				fmt.Fprintf(w, "        %-50s [%s] via %s\n",
					rr.ResourceARN, sevLabel, rr.AccessPath)
			}
			if len(e.ReachableResources) > 10 {
				fmt.Fprintf(w, "        ... (%d more resources)\n", len(e.ReachableResources)-10)
			}
		}

		if len(e.RemediationActions) > 0 {
			fmt.Fprintf(w, "      Recommended actions:\n")
			for i, act := range e.RemediationActions {
				action := act
				if len(action) > 76 {
					action = action[:73] + "..."
				}
				fmt.Fprintf(w, "        %d. %s\n", i+1, action)
			}
		}
	}
}

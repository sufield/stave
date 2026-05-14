// Package rank implements the 'stave rank' command for producing a
// prioritized remediation roadmap from assessment output.
package rank

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	apprank "github.com/sufield/stave/internal/app/rank"
	"github.com/sufield/stave/internal/app/rank/formatter"
	"github.com/sufield/stave/internal/app/sprintplanner"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
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

// sortByBlastRadius is the recognised --sort-by value that flips the
// ranker into blast-radius ordering (and the text renderer into
// blast-radius display). Centralised so the literal lives next to
// SortsByBlastRadius and the help text in NewCmdWithDeps.
const sortByBlastRadius = "blast-radius"

// SortsByBlastRadius reports whether the operator asked for the
// blast-radius sort order. Replaces the (opts.SortBy == "blast-radius")
// probes at lines 144 and 192.
func (o *options) SortsByBlastRadius() bool {
	return o != nil && o.SortBy == sortByBlastRadius
}

// NewCmd constructs the rank command with the given dependencies.
// commands.go is responsible for resolving the production factories.
func NewCmd(deps Deps) *cobra.Command {
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
			return run(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, deps)
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

func run(ctx context.Context, stdout, _ io.Writer, opts *options, deps Deps) error {
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
		return runIdentity(ctx, stdout, opts, &assessment, deps)
	}

	// Sprint planning mode.
	if opts.Capacity != "" {
		return runSprint(stdout, opts, &assessment)
	}

	// Build roadmap.
	roadmap := apprank.BuildRoadmap(assessment.Findings, assessment.TopExposures, opts.TopN)

	// Re-sort by blast radius if requested.
	if opts.SortsByBlastRadius() {
		apprank.SortByBlastRadius(&roadmap, apprank.BuildBlastIndex(&assessment))
	}

	// Group by owner if requested.
	if opts.GroupBy == "owner" {
		return runGroupByOwner(stdout, opts, &assessment, roadmap)
	}

	// Output.
	if err := dispatchRoadmap(stdout, opts, roadmap, &assessment); err != nil {
		return err
	}

	// Show acknowledged findings if requested.
	if opts.IncludeAcknowledged && len(assessment.AcknowledgedFindings) > 0 {
		fmt.Fprintf(stdout, "\nACKNOWLEDGED FINDINGS (%d)\n", len(assessment.AcknowledgedFindings))
		fmt.Fprintln(stdout, strings.Repeat("-", 50))
		for i := range assessment.AcknowledgedFindings {
			af := &assessment.AcknowledgedFindings[i]
			fmt.Fprintf(stdout, "  %s  %s on %s\n", af.StatusLabel(), af.ControlID, af.AssetID)
			af.WriteDetails(stdout)
		}
	}

	return nil
}

// dispatchRoadmap selects the appropriate formatter based on the
// --format flag and renders the roadmap. Output formatting lives in
// internal/app/rank/formatter; this dispatch is the only CLI-side
// formatting concern remaining (which format the user picked).
func dispatchRoadmap(w io.Writer, opts *options, rm apprank.Roadmap, assessment *report.Assessment) error {
	var f formatter.RoadmapFormatter
	switch opts.Format {
	case "json":
		f = formatter.JSON{}
	case "csv":
		f = formatter.CSV{}
	default:
		f = &formatter.TextRoadmap{ShowReach: opts.SortsByBlastRadius()}
	}
	return f.Render(w, rm, assessment)
}

func runGroupByOwner(stdout io.Writer, opts *options, assessment *report.Assessment, roadmap apprank.Roadmap) error {
	manifestPath := opts.TeamManifest
	if manifestPath == "" {
		manifestPath = "stave-teams.yaml"
	}
	manifest, err := teams.LoadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("load team manifest: %w", err)
	}

	teamRoadmaps := apprank.GroupByOwner(assessment, roadmap, manifest)

	switch opts.Format {
	case "json":
		output := struct {
			Roadmap      apprank.Roadmap       `json:"roadmap"`
			TeamRoadmaps []apprank.TeamRoadmap `json:"team_roadmaps"`
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

func runIdentity(ctx context.Context, stdout io.Writer, opts *options, assessment *report.Assessment, deps Deps) error {
	if opts.SnapshotPath == "" {
		return errors.New("--snapshot is required for --identity (path to observation snapshots)")
	}

	bundleLoader, blErr := deps.NewSnapshotBundleLoader()
	if blErr != nil {
		return fmt.Errorf("create snapshot bundle loader: %w", blErr)
	}
	snapshots, err := bundleLoader.LoadBundle(ctx, opts.SnapshotPath)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}

	ranking := apprank.BuildIdentityRanking(apprank.IdentityRankingConfig{
		Findings:                 assessment.Findings,
		TopExposures:             assessment.TopExposures,
		Snapshots:                snapshots,
		TopN:                     opts.TopN,
		AccountIDFromARN:         iam.ExtractAccountID,
		BuildResourceAccessIndex: iam.BuildResourceAccessIndex,
	})

	if opts.Format == "json" {
		output, marshalErr := json.MarshalIndent(ranking, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshal identity ranking: %w", marshalErr)
		}
		fmt.Fprintln(stdout, string(output))
		return nil
	}
	return formatter.TextIdentityRanking{}.Render(stdout, ranking)
}

func runSprint(stdout io.Writer, opts *options, assessment *report.Assessment) error {
	capacityHours, err := apprank.ParseCapacity(opts.Capacity)
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
		return formatter.TextSprint{}.Render(stdout, result)
	}
	return nil
}

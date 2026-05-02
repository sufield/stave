// Package snapplan provides retention planning for observation snapshots.
//
// It computes multi-tier retention plans from snapshot file metadata and
// retention configuration. The resulting [PlanOutput] describes which files
// to keep, prune, or archive based on age thresholds and minimum-keep floors.
//
// This package is a pure domain kernel: it has zero I/O dependencies and can
// be imported by adopters to build custom retention tools.
package snapplan

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/retention"
)

// File represents one snapshot file discovered on disk.
type File struct {
	Path       string
	RelPath    string
	Name       string
	CapturedAt time.Time
}

// Action represents the recommended fate of a snapshot file in a
// retention plan. Stave never executes the action — external tools
// consume the plan output and decide whether to delete, move into an
// archive directory, or otherwise act on each entry.
type Action string

// Snapshot retention plan action constants.
const (
	ActionKeep  Action = "KEEP"
	ActionPrune Action = "PRUNE"
)

// Mode is retained for wire-format stability. The plan command is
// read-only; the only legitimate value is ModePreview.
type Mode string

// ModePreview is the only mode the plan command emits. The
// previously-supported ModePrune and ModeArchive were tied to the
// removed --apply / --force / --archive-dir execution path.
const (
	ModePreview Mode = "PREVIEW"
)

// PlanFile is one file row in the generated snapshot plan.
type PlanFile struct {
	RelPath    string    `json:"rel_path"`
	CapturedAt time.Time `json:"captured_at"`
	Tier       string    `json:"tier"`
	Action     Action    `json:"action"`
	Reason     string    `json:"reason"`
}

// PlanTierSummary aggregates plan counts per tier.
type PlanTierSummary struct {
	Tier        string `json:"tier"`
	OlderThan   string `json:"older_than"`
	KeepMin     int    `json:"keep_min"`
	Total       int    `json:"total"`
	KeepCount   int    `json:"keep_count"`
	ActionCount int    `json:"action_count"`
}

// PlanOutput is the materialized retention plan.
//
// The Mode field is always ModePreview. The Applied field is always
// false. Both are kept on the JSON wire format for stability across
// the read-only-plan transition; callers that consume the JSON
// should treat them as legacy informational fields.
type PlanOutput struct {
	SchemaVersion    kernel.Schema     `json:"schema_version"`
	Kind             kernel.OutputKind `json:"kind"`
	GeneratedAt      time.Time         `json:"generated_at"`
	ObservationsRoot string            `json:"observations_root"`
	Mode             Mode              `json:"mode"`
	Applied          bool              `json:"applied"`
	DefaultTier      string            `json:"default_tier"`
	TierSummaries    []PlanTierSummary `json:"tier_summaries"`
	TotalFiles       int               `json:"total_files"`
	TotalActions     int               `json:"total_actions"`
	Files            []PlanFile        `json:"files"`
}

// TierResolver maps a relative file path to a retention tier name.
type TierResolver interface {
	Resolve(relPath string) string
}

// TierResolverFunc adapts a plain function to the TierResolver interface.
type TierResolverFunc func(string) string

// Resolve implements TierResolver.
func (f TierResolverFunc) Resolve(path string) string { return f(path) }

// BuildPlanParams holds inputs for BuildPlan.
// Duration fields use time.Duration (pre-parsed by the caller) so the
// domain kernel does not handle string parsing.
type BuildPlanParams struct {
	Now              time.Time
	ObsRoot          string
	DefaultTier      string
	Tiers            map[string]retention.Tier
	Files            []File
	DefaultOlderThan time.Duration
	DefaultKeepMin   int
	TierResolver     TierResolver
}

// BuildPlan computes a snapshot prune/archive plan from retention config.
// Returns an error if tier configuration is invalid (e.g., unparseable
// duration strings in Tier.OlderThan).
func BuildPlan(params BuildPlanParams) (*PlanOutput, error) {
	if params.Now.IsZero() {
		return nil, errors.New("buildPlan requires non-zero now (resolve from --now flag or clock)")
	}

	byTier := groupFilesByTier(params.Files, params.DefaultTier, params.TierResolver)
	tierNames := sortedTierNames(byTier)

	allEntries := make([]PlanFile, 0, len(params.Files))
	summaries := make([]PlanTierSummary, 0, len(tierNames))
	totalActions := 0

	for _, tierName := range tierNames {
		tierPlan, err := buildTierPlan(params, tierName, byTier[tierName])
		if err != nil {
			return nil, fmt.Errorf("tier %q: %w", tierName, err)
		}
		allEntries = append(allEntries, tierPlan.entries...)
		summaries = append(summaries, tierPlan.summary)
		totalActions += tierPlan.actionCount
	}

	return &PlanOutput{
		SchemaVersion:    kernel.SchemaSnapshotPlan,
		Kind:             kernel.KindSnapshotPlan,
		GeneratedAt:      params.Now.UTC(),
		ObservationsRoot: params.ObsRoot,
		Mode:             ModePreview,
		Applied:          false,
		DefaultTier:      params.DefaultTier,
		TierSummaries:    summaries,
		TotalFiles:       len(params.Files),
		TotalActions:     totalActions,
		Files:            allEntries,
	}, nil
}

type tierPlanResult struct {
	entries     []PlanFile
	summary     PlanTierSummary
	actionCount int
}

func groupFilesByTier(files []File, defaultTier string, resolver TierResolver) map[string][]File {
	groups := make(map[string][]File)
	defaultTier = strings.TrimSpace(defaultTier)

	for _, f := range files {
		tier := defaultTier
		if resolver != nil {
			if resolved := resolver.Resolve(f.RelPath); resolved != "" {
				tier = resolved
			}
		}
		groups[tier] = append(groups[tier], f)
	}
	return groups
}

func sortedTierNames(byTier map[string][]File) []string {
	if len(byTier) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(byTier))
}

func buildTierPlan(params BuildPlanParams, tierName string, files []File) (tierPlanResult, error) {
	keepMin := params.DefaultKeepMin
	olderThan := params.DefaultOlderThan

	if tc, ok := params.Tiers[tierName]; ok {
		if tc.KeepMin > 0 {
			keepMin = tc.KeepMin
		}
		if raw := strings.TrimSpace(tc.OlderThan); raw != "" {
			d, err := kernel.ParseDuration(raw)
			if err != nil {
				return tierPlanResult{}, fmt.Errorf("invalid duration %q: %w", raw, err)
			}
			olderThan = d
		}
	}

	candidates := make([]retention.Candidate, len(files))
	for i, sf := range files {
		candidates[i] = retention.Candidate{
			Index:      i,
			CapturedAt: sf.CapturedAt.UTC(),
		}
	}
	slices.SortFunc(candidates, func(a, b retention.Candidate) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})

	toProcess := retention.PlanPrune(candidates, retention.Criteria{
		Now:       params.Now.UTC(),
		OlderThan: olderThan,
		KeepMin:   keepMin,
	})

	processedIdx := make(map[int]struct{}, len(toProcess))
	for _, c := range toProcess {
		processedIdx[c.Index] = struct{}{}
	}

	targetAction := ActionPrune

	entries := make([]PlanFile, 0, len(files))
	actionCount := 0
	cutoff := params.Now.UTC().Add(-olderThan)
	olderThanStr := olderThan.String()

	for i, f := range files {
		entry := PlanFile{
			RelPath:    f.RelPath,
			CapturedAt: f.CapturedAt.UTC(),
			Tier:       tierName,
		}

		if _, ok := processedIdx[i]; ok {
			entry.Action = targetAction
			entry.Reason = "older than " + olderThanStr
			actionCount++
		} else {
			entry.Action = ActionKeep
			if f.CapturedAt.UTC().Before(cutoff) {
				entry.Reason = "keep-min floor"
			} else {
				entry.Reason = "within retention"
			}
		}
		entries = append(entries, entry)
	}

	return tierPlanResult{
		entries:     entries,
		actionCount: actionCount,
		summary: PlanTierSummary{
			Tier:        tierName,
			OlderThan:   olderThanStr,
			KeepMin:     keepMin,
			Total:       len(files),
			KeepCount:   len(files) - actionCount,
			ActionCount: actionCount,
		},
	}, nil
}

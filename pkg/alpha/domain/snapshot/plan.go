// Package snapshot provides retention planning for observation snapshots.
//
// It computes multi-tier retention plans from snapshot file metadata and
// retention configuration. The resulting [PlanOutput] describes which files
// to keep, prune, or archive based on age thresholds and minimum-keep floors.
//
// This package is a pure domain kernel: it has zero I/O dependencies and can
// be imported by adopters to build custom retention tools.
package snapshot

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
)

// File represents one snapshot file discovered on disk.
type File struct {
	Path       string
	RelPath    string
	Name       string
	CapturedAt time.Time
}

// PlanAction is an alias for the domain retention PlanAction type.
type PlanAction = retention.PlanAction

// Action constants re-exported from domain retention.
const (
	ActionKeep    = retention.ActionKeep
	ActionPrune   = retention.ActionPrune
	ActionArchive = retention.ActionArchive
)

// PlanMode is an alias for the domain retention PlanMode type.
type PlanMode = retention.PlanMode

// Mode constants re-exported from domain retention.
const (
	ModePreview = retention.ModePreview
	ModePrune   = retention.ModePrune
	ModeArchive = retention.ModeArchive
)

// PlanFile is one file row in the generated snapshot plan.
type PlanFile struct {
	RelPath    string     `json:"rel_path"`
	CapturedAt time.Time  `json:"captured_at"`
	Tier       string     `json:"tier"`
	Action     PlanAction `json:"action"`
	Reason     string     `json:"reason"`
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
type PlanOutput struct {
	SchemaVersion    kernel.Schema     `json:"schema_version"`
	Kind             kernel.OutputKind `json:"kind"`
	GeneratedAt      time.Time         `json:"generated_at"`
	ObservationsRoot string            `json:"observations_root"`
	ArchiveDir       string            `json:"archive_dir,omitempty"`
	Mode             PlanMode          `json:"mode"`
	Applied          bool              `json:"applied"`
	DefaultTier      string            `json:"default_tier"`
	TierSummaries    []PlanTierSummary `json:"tier_summaries"`
	TotalFiles       int               `json:"total_files"`
	TotalActions     int               `json:"total_actions"`
	Files            []PlanFile        `json:"files"`
}

// PlanEntry is a single snapshot plan row for execution.
type PlanEntry struct {
	RelPath string
	Action  PlanAction
}

// BuildPlanParams holds inputs for BuildPlan.
type BuildPlanParams struct {
	Now                time.Time
	ObsRoot            string
	ArchiveDir         string
	DefaultTier        string
	TierRules          []retention.MappingRule
	Tiers              map[string]retention.TierConfig
	Files              []File
	Apply              bool
	Force              bool
	DefaultOlderThan   string
	DefaultKeepMin     int
	ParseDuration      func(string) (time.Duration, error)
	ResolveTierForPath func(relPath string, rules []retention.MappingRule, defaultTier string) string
}

// BuildPlan computes a snapshot prune/archive plan from retention config.
func BuildPlan(params BuildPlanParams) PlanOutput {
	mode, applied := resolvePlanMode(params.Apply, params.Force, params.ArchiveDir)
	byTier := groupFilesByTier(params.Files, params.TierRules, params.DefaultTier, params.ResolveTierForPath)
	tierNames := sortedTierNames(byTier)

	allEntries := make([]PlanFile, 0, len(params.Files))
	summaries := make([]PlanTierSummary, 0, len(tierNames))
	totalActions := 0

	for _, tierName := range tierNames {
		tierPlan := buildTierPlan(params, tierName, byTier[tierName])
		allEntries = append(allEntries, tierPlan.entries...)
		summaries = append(summaries, tierPlan.summary)
		totalActions += tierPlan.actionCount
	}

	return PlanOutput{
		SchemaVersion:    kernel.SchemaSnapshotPlan,
		Kind:             kernel.KindSnapshotPlan,
		GeneratedAt:      params.Now.UTC(),
		ObservationsRoot: params.ObsRoot,
		ArchiveDir:       params.ArchiveDir,
		Mode:             mode,
		Applied:          applied,
		DefaultTier:      params.DefaultTier,
		TierSummaries:    summaries,
		TotalFiles:       len(params.Files),
		TotalActions:     totalActions,
		Files:            allEntries,
	}
}

type tierPlanResult struct {
	entries     []PlanFile
	summary     PlanTierSummary
	actionCount int
}

func resolvePlanMode(apply, force bool, archiveDir string) (PlanMode, bool) {
	if !apply || !force {
		return ModePreview, false
	}
	if archiveDir != "" {
		return ModeArchive, true
	}
	return ModePrune, true
}

func groupFilesByTier(
	files []File,
	rules []retention.MappingRule,
	defaultTier string,
	resolver func(relPath string, rules []retention.MappingRule, defaultTier string) string,
) map[string][]File {
	if resolver == nil {
		resolver = func(_ string, _ []retention.MappingRule, fallback string) string { return fallback }
	}
	trimmedDefault := strings.TrimSpace(defaultTier)
	groups := make(map[string][]File, len(files))
	for _, sf := range files {
		tier := strings.TrimSpace(resolver(sf.RelPath, rules, defaultTier))
		if tier == "" {
			tier = trimmedDefault
		}
		groups[tier] = append(groups[tier], sf)
	}
	return groups
}

func sortedTierNames(byTier map[string][]File) []string {
	if len(byTier) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(byTier))
}

type tierCfg struct {
	olderThanStr string
	keepMin      int
	olderThan    time.Duration
}

func buildTierPlan(params BuildPlanParams, tierName string, files []File) tierPlanResult {
	cfg, err := resolveTierConfig(params, tierName)
	if err != nil {
		return buildInvalidTierPlan(tierName, files, cfg.olderThanStr, cfg.keepMin)
	}

	items := make([]retention.Candidate, 0, len(files))
	for i, sf := range files {
		items = append(items, retention.Candidate{
			Index:      i,
			CapturedAt: sf.CapturedAt,
		})
	}
	candidates := retention.PlanPrune(items, retention.Criteria{
		Now:       params.Now,
		OlderThan: cfg.olderThan,
		KeepMin:   cfg.keepMin,
	})
	candidateSet := buildCandidateSet(candidates)

	action := ActionPrune
	if params.ArchiveDir != "" {
		action = ActionArchive
	}

	entries, actionCount := buildTierEntries(files, candidateSet, tierName, action, cfg.olderThanStr, cfg.olderThan, params.Now)
	return tierPlanResult{
		entries: entries,
		summary: PlanTierSummary{
			Tier:        tierName,
			OlderThan:   cfg.olderThanStr,
			KeepMin:     cfg.keepMin,
			Total:       len(files),
			KeepCount:   len(files) - actionCount,
			ActionCount: actionCount,
		},
		actionCount: actionCount,
	}
}

func resolveTierConfig(params BuildPlanParams, tierName string) (tierCfg, error) {
	cfg := tierCfg{
		olderThanStr: params.DefaultOlderThan,
		keepMin:      params.DefaultKeepMin,
	}
	if tc, ok := params.Tiers[tierName]; ok {
		cfg.keepMin = effectiveKeepMin(tc.KeepMin, params.DefaultKeepMin)
		if strings.TrimSpace(tc.OlderThan) != "" {
			cfg.olderThanStr = tc.OlderThan
		}
	}
	olderThan, err := parseDuration(cfg.olderThanStr, params.ParseDuration)
	if err != nil {
		return cfg, err
	}
	cfg.olderThan = olderThan
	return cfg, nil
}

func parseDuration(raw string, parseFn func(string) (time.Duration, error)) (time.Duration, error) {
	if parseFn == nil {
		return 0, fmt.Errorf("duration parser is required")
	}
	return parseFn(raw)
}

func effectiveKeepMin(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func buildInvalidTierPlan(tierName string, files []File, olderThanStr string, keepMin int) tierPlanResult {
	entries := make([]PlanFile, 0, len(files))
	for _, sf := range files {
		entries = append(entries, PlanFile{
			RelPath:    sf.RelPath,
			CapturedAt: sf.CapturedAt.UTC(),
			Tier:       tierName,
			Action:     ActionKeep,
			Reason:     "invalid tier config",
		})
	}
	return tierPlanResult{
		entries: entries,
		summary: PlanTierSummary{
			Tier:        tierName,
			OlderThan:   olderThanStr,
			KeepMin:     keepMin,
			Total:       len(files),
			KeepCount:   len(files),
			ActionCount: 0,
		},
		actionCount: 0,
	}
}

func buildCandidateSet(candidates []retention.Candidate) map[int]struct{} {
	candidateSet := make(map[int]struct{}, len(candidates))
	for _, c := range candidates {
		candidateSet[c.Index] = struct{}{}
	}
	return candidateSet
}

func buildTierEntries(
	files []File,
	candidateSet map[int]struct{},
	tierName string, action PlanAction, olderThanStr string,
	olderThan time.Duration,
	now time.Time,
) ([]PlanFile, int) {
	entries := make([]PlanFile, 0, len(files))
	actionCount := 0
	cutoff := now.UTC().Add(-olderThan)
	pruneReason := "older than " + olderThanStr

	for i, sf := range files {
		entry := PlanFile{
			RelPath:    sf.RelPath,
			CapturedAt: sf.CapturedAt.UTC(),
			Tier:       tierName,
		}
		if _, ok := candidateSet[i]; ok {
			entry.Action = action
			entry.Reason = pruneReason
			actionCount++
		} else {
			entry.Action = ActionKeep
			if sf.CapturedAt.Before(cutoff) {
				entry.Reason = "keep-min floor"
			} else {
				entry.Reason = "within retention"
			}
		}
		entries = append(entries, entry)
	}
	return entries, actionCount
}

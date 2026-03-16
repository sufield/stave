package plan

import (
	"fmt"
	"strings"
	"time"

	"github.com/samber/lo"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/retention"
	"github.com/sufield/stave/internal/pkg/fp"
	"github.com/sufield/stave/internal/pruner"
)

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

// SnapshotPlanFile is one file row in the generated snapshot plan.
type SnapshotPlanFile struct {
	RelPath    string     `json:"rel_path"`
	CapturedAt time.Time  `json:"captured_at"`
	Tier       string     `json:"tier"`
	Action     PlanAction `json:"action"`
	Reason     string     `json:"reason"`
}

// SnapshotPlanTierSummary aggregates plan counts per tier.
type SnapshotPlanTierSummary struct {
	Tier        string `json:"tier"`
	OlderThan   string `json:"older_than"`
	KeepMin     int    `json:"keep_min"`
	Total       int    `json:"total"`
	KeepCount   int    `json:"keep_count"`
	ActionCount int    `json:"action_count"`
}

// SnapshotPlanOutput is the materialized retention plan.
type SnapshotPlanOutput struct {
	SchemaVersion    kernel.Schema             `json:"schema_version"`
	Kind             kernel.OutputKind         `json:"kind"`
	GeneratedAt      time.Time                 `json:"generated_at"`
	ObservationsRoot string                    `json:"observations_root"`
	ArchiveDir       string                    `json:"archive_dir,omitempty"`
	Mode             PlanMode                  `json:"mode"`
	Applied          bool                      `json:"applied"`
	DefaultTier      string                    `json:"default_tier"`
	TierSummaries    []SnapshotPlanTierSummary `json:"tier_summaries"`
	TotalFiles       int                       `json:"total_files"`
	TotalActions     int                       `json:"total_actions"`
	Files            []SnapshotPlanFile        `json:"files"`
}

// BuildSnapshotPlanParams holds inputs for BuildSnapshotPlan.
type BuildSnapshotPlanParams struct {
	Now                time.Time
	ObsRoot            string
	ArchiveDir         string
	DefaultTier        string
	TierRules          []retention.MappingRule
	Tiers              map[string]retention.TierConfig
	Files              []pruner.SnapshotFile
	Apply              bool
	Force              bool
	DefaultOlderThan   string
	DefaultKeepMin     int
	ParseDuration      func(string) (time.Duration, error)
	ResolveTierForPath func(relPath string, rules []retention.MappingRule, defaultTier string) string
}

// BuildSnapshotPlan computes a snapshot prune/archive plan from retention config.
func BuildSnapshotPlan(params BuildSnapshotPlanParams) SnapshotPlanOutput {
	mode, applied := resolveSnapshotPlanMode(params.Apply, params.Force, params.ArchiveDir)
	byTier := groupSnapshotFilesByTier(params.Files, params.TierRules, params.DefaultTier, params.ResolveTierForPath)
	tierNames := sortedSnapshotTierNames(byTier)

	allEntries := make([]SnapshotPlanFile, 0, len(params.Files))
	summaries := make([]SnapshotPlanTierSummary, 0, len(tierNames))
	totalActions := 0

	for _, tierName := range tierNames {
		tierPlan := buildTierPlan(params, tierName, byTier[tierName])
		allEntries = append(allEntries, tierPlan.entries...)
		summaries = append(summaries, tierPlan.summary)
		totalActions += tierPlan.actionCount
	}

	return SnapshotPlanOutput{
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
	entries     []SnapshotPlanFile
	summary     SnapshotPlanTierSummary
	actionCount int
}

func resolveSnapshotPlanMode(apply, force bool, archiveDir string) (PlanMode, bool) {
	if !apply || !force {
		return ModePreview, false
	}
	if archiveDir != "" {
		return ModeArchive, true
	}
	return ModePrune, true
}

func groupSnapshotFilesByTier(
	files []pruner.SnapshotFile,
	rules []retention.MappingRule,
	defaultTier string,
	resolver func(relPath string, rules []retention.MappingRule, defaultTier string) string,
) map[string][]pruner.SnapshotFile {
	if resolver == nil {
		resolver = func(_ string, _ []retention.MappingRule, fallback string) string { return fallback }
	}

	// Pre-trim default tier once instead of per-file.
	trimmedDefault := strings.TrimSpace(defaultTier)

	return lo.GroupBy(files, func(sf pruner.SnapshotFile) string {
		tier := strings.TrimSpace(resolver(sf.RelPath, rules, defaultTier))
		if tier == "" {
			return trimmedDefault
		}
		return tier
	})
}

func sortedSnapshotTierNames(byTier map[string][]pruner.SnapshotFile) []string {
	return fp.SortedKeys(byTier)
}

type tierCfg struct {
	olderThanStr string
	keepMin      int
	olderThan    time.Duration
}

func buildTierPlan(params BuildSnapshotPlanParams, tierName string, files []pruner.SnapshotFile) tierPlanResult {
	cfg, err := resolveTierPlanConfig(params, tierName)
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
	candidateSet := buildPlanCandidateSet(candidates)

	action := ActionPrune
	if params.ArchiveDir != "" {
		action = ActionArchive
	}

	entries, actionCount := buildTierEntries(files, candidateSet, tierName, action, cfg.olderThanStr, cfg.olderThan, params.Now)
	return tierPlanResult{
		entries: entries,
		summary: SnapshotPlanTierSummary{
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

func resolveTierPlanConfig(params BuildSnapshotPlanParams, tierName string) (tierCfg, error) {
	cfg := tierCfg{
		olderThanStr: params.DefaultOlderThan,
		keepMin:      params.DefaultKeepMin,
	}

	// Override with tier-specific settings if they exist.
	if tc, ok := params.Tiers[tierName]; ok {
		cfg.keepMin = effectiveKeepMin(tc.KeepMin, params.DefaultKeepMin)
		if strings.TrimSpace(tc.OlderThan) != "" {
			cfg.olderThanStr = tc.OlderThan
		}
	}

	// Single parse point for the resolved duration string.
	olderThan, err := parseSnapshotDuration(cfg.olderThanStr, params.ParseDuration)
	if err != nil {
		return cfg, err
	}
	cfg.olderThan = olderThan
	return cfg, nil
}

func parseSnapshotDuration(raw string, parseFn func(string) (time.Duration, error)) (time.Duration, error) {
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

func buildInvalidTierPlan(tierName string, files []pruner.SnapshotFile, olderThanStr string, keepMin int) tierPlanResult {
	entries := make([]SnapshotPlanFile, 0, len(files))
	for _, sf := range files {
		entries = append(entries, SnapshotPlanFile{
			RelPath:    sf.RelPath,
			CapturedAt: sf.CapturedAt.UTC(),
			Tier:       tierName,
			Action:     ActionKeep,
			Reason:     "invalid tier config",
		})
	}

	return tierPlanResult{
		entries: entries,
		summary: SnapshotPlanTierSummary{
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

func buildPlanCandidateSet(candidates []retention.Candidate) map[int]struct{} {
	candidateSet := make(map[int]struct{}, len(candidates))
	for _, c := range candidates {
		candidateSet[c.Index] = struct{}{}
	}
	return candidateSet
}

func buildTierEntries(
	files []pruner.SnapshotFile,
	candidateSet map[int]struct{},
	tierName string, action PlanAction, olderThanStr string,
	olderThan time.Duration,
	now time.Time,
) ([]SnapshotPlanFile, int) {
	entries := make([]SnapshotPlanFile, 0, len(files))
	actionCount := 0
	cutoff := now.UTC().Add(-olderThan)
	pruneReason := "older than " + olderThanStr

	for i, sf := range files {
		entry := SnapshotPlanFile{
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

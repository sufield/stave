package pruner

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// PlanAction represents the action to take on a snapshot in a retention plan.
type PlanAction string

const (
	ActionKeep    PlanAction = "KEEP"
	ActionPrune   PlanAction = "PRUNE"
	ActionArchive PlanAction = "ARCHIVE"
)

// PlanMode represents the execution mode of a snapshot retention plan.
type PlanMode string

const (
	ModePreview PlanMode = "PREVIEW"
	ModePrune   PlanMode = "PRUNE"
	ModeArchive PlanMode = "ARCHIVE"
)

// TierMappingRule assigns a relative snapshot path pattern to a retention tier.
type TierMappingRule struct {
	Pattern string
	Tier    string
}

// RetentionTier configures retention behavior for a tier.
type RetentionTier struct {
	OlderThan string
	KeepMin   int
}

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
	SchemaVersion    string                    `json:"schema_version"`
	Kind             string                    `json:"kind"`
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
	TierRules          []TierMappingRule
	Tiers              map[string]RetentionTier
	Files              []SnapshotFile
	Apply              bool
	Force              bool
	DefaultOlderThan   string
	DefaultKeepMin     int
	ParseDuration      func(string) (time.Duration, error)
	ResolveTierForPath func(relPath string, rules []TierMappingRule, defaultTier string) string
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
		SchemaVersion:    string(kernel.SchemaSnapshotPlan),
		Kind:             "snapshot_plan",
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
	files []SnapshotFile,
	rules []TierMappingRule,
	defaultTier string,
	resolver func(relPath string, rules []TierMappingRule, defaultTier string) string,
) map[string][]SnapshotFile {
	if resolver == nil {
		resolver = func(_ string, _ []TierMappingRule, fallback string) string { return fallback }
	}

	byTier := make(map[string][]SnapshotFile)
	for i := range files {
		sf := files[i]
		tier := resolver(sf.RelPath, rules, defaultTier)
		if strings.TrimSpace(tier) == "" {
			tier = defaultTier
		}
		byTier[tier] = append(byTier[tier], sf)
	}
	return byTier
}

func sortedSnapshotTierNames(byTier map[string][]SnapshotFile) []string {
	tierNames := make([]string, 0, len(byTier))
	for name := range byTier {
		tierNames = append(tierNames, name)
	}
	sort.Strings(tierNames)
	return tierNames
}

type tierConfig struct {
	olderThanStr string
	keepMin      int
	olderThan    time.Duration
}

func buildTierPlan(params BuildSnapshotPlanParams, tierName string, files []SnapshotFile) tierPlanResult {
	cfg, err := resolveTierPlanConfig(params, tierName)
	if err != nil {
		return buildInvalidTierPlan(tierName, files, cfg.olderThanStr, cfg.keepMin)
	}

	items := make([]Candidate, 0, len(files))
	for i, sf := range files {
		items = append(items, Candidate{
			Index:      i,
			CapturedAt: sf.CapturedAt,
		})
	}
	candidates := PlanPrune(items, Criteria{
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

func resolveTierPlanConfig(params BuildSnapshotPlanParams, tierName string) (tierConfig, error) {
	cfg := tierConfig{
		olderThanStr: params.DefaultOlderThan,
		keepMin:      params.DefaultKeepMin,
	}

	if tierCfg, ok := params.Tiers[tierName]; ok {
		cfg.keepMin = effectiveKeepMin(tierCfg.KeepMin, params.DefaultKeepMin)
		if strings.TrimSpace(tierCfg.OlderThan) != "" {
			cfg.olderThanStr = tierCfg.OlderThan
			olderThan, err := parseSnapshotDuration(cfg.olderThanStr, params.ParseDuration)
			if err != nil {
				return cfg, err
			}
			cfg.olderThan = olderThan
			return cfg, nil
		}
	}

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

func buildInvalidTierPlan(tierName string, files []SnapshotFile, olderThanStr string, keepMin int) tierPlanResult {
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

func buildPlanCandidateSet(candidates []Candidate) map[int]bool {
	candidateSet := make(map[int]bool, len(candidates))
	for _, c := range candidates {
		candidateSet[c.Index] = true
	}
	return candidateSet
}

func buildTierEntries(
	files []SnapshotFile,
	candidateSet map[int]bool,
	tierName string, action PlanAction, olderThanStr string,
	olderThan time.Duration,
	now time.Time,
) ([]SnapshotPlanFile, int) {
	entries := make([]SnapshotPlanFile, 0, len(files))
	actionCount := 0
	cutoff := now.Add(-olderThan)

	for i, sf := range files {
		entry := SnapshotPlanFile{
			RelPath:    sf.RelPath,
			CapturedAt: sf.CapturedAt.UTC(),
			Tier:       tierName,
		}
		if candidateSet[i] {
			entry.Action = action
			entry.Reason = "older than " + olderThanStr
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

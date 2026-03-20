package snapshot

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/pruner"
	pruneplan "github.com/sufield/stave/internal/pruner/plan"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
)

func TestBuildSnapshotPlan_SingleTier(t *testing.T) {
	now := time.Date(2026, 2, 23, 0, 0, 0, 0, time.UTC)
	files := []pruner.SnapshotFile{
		{RelPath: "2026-02-20.json", Name: "2026-02-20.json", CapturedAt: now.AddDate(0, 0, -3)},
		{RelPath: "2026-01-01.json", Name: "2026-01-01.json", CapturedAt: now.AddDate(0, 0, -53)},
	}

	plan := buildPlan(planBuildParams{
		Now:         now,
		ObsRoot:     "./observations",
		DefaultTier: "critical",
		Tiers: map[string]retention.TierConfig{
			"critical": {OlderThan: "30d", KeepMin: 2},
		},
		Files: files,
	})

	if plan.TotalFiles != 2 {
		t.Fatalf("TotalFiles=%d, want 2", plan.TotalFiles)
	}
	if plan.TotalActions != 0 {
		// keep-min=2 means we can't prune even though one is older than 30d
		t.Fatalf("TotalActions=%d, want 0 (keep-min floor)", plan.TotalActions)
	}
	if plan.Mode != pruneplan.ModePreview {
		t.Fatalf("Mode=%q, want PREVIEW", plan.Mode)
	}
}

func TestBuildSnapshotPlan_SingleTierPrunesOld(t *testing.T) {
	now := time.Date(2026, 2, 23, 0, 0, 0, 0, time.UTC)
	files := []pruner.SnapshotFile{
		{RelPath: "2026-02-20.json", Name: "2026-02-20.json", CapturedAt: now.AddDate(0, 0, -3)},
		{RelPath: "2026-02-15.json", Name: "2026-02-15.json", CapturedAt: now.AddDate(0, 0, -8)},
		{RelPath: "2026-01-01.json", Name: "2026-01-01.json", CapturedAt: now.AddDate(0, 0, -53)},
	}

	plan := buildPlan(planBuildParams{
		Now:         now,
		ObsRoot:     "./observations",
		DefaultTier: "critical",
		Tiers: map[string]retention.TierConfig{
			"critical": {OlderThan: "30d", KeepMin: 2},
		},
		Files: files,
	})

	if plan.TotalFiles != 3 {
		t.Fatalf("TotalFiles=%d, want 3", plan.TotalFiles)
	}
	if plan.TotalActions != 1 {
		t.Fatalf("TotalActions=%d, want 1", plan.TotalActions)
	}

	var pruned []pruneplan.SnapshotPlanFile
	for _, f := range plan.Files {
		if f.Action == pruneplan.ActionPrune {
			pruned = append(pruned, f)
		}
	}
	if len(pruned) != 1 || pruned[0].RelPath != "2026-01-01.json" {
		t.Fatalf("unexpected pruned files: %+v", pruned)
	}
}

func TestBuildSnapshotPlan_MultiTier(t *testing.T) {
	now := time.Date(2026, 2, 23, 0, 0, 0, 0, time.UTC)
	files := []pruner.SnapshotFile{
		{RelPath: "prod/2026-02-20.json", CapturedAt: now.AddDate(0, 0, -3)},
		{RelPath: "prod/2026-01-01.json", CapturedAt: now.AddDate(0, 0, -53)},
		{RelPath: "prod/2026-01-15.json", CapturedAt: now.AddDate(0, 0, -39)},
		{RelPath: "dev/2026-02-20.json", CapturedAt: now.AddDate(0, 0, -3)},
		{RelPath: "dev/2026-02-01.json", CapturedAt: now.AddDate(0, 0, -22)},
	}

	rules := []retention.MappingRule{
		{Pattern: "prod/**", Tier: "critical"},
		{Pattern: "dev/**", Tier: "non_critical"},
	}

	plan := buildPlan(planBuildParams{
		Now:         now,
		ObsRoot:     "./observations",
		DefaultTier: "critical",
		TierRules:   rules,
		Tiers: map[string]retention.TierConfig{
			"critical":     {OlderThan: "30d", KeepMin: 2},
			"non_critical": {OlderThan: "14d", KeepMin: 2},
		},
		Files: files,
	})

	if plan.TotalFiles != 5 {
		t.Fatalf("TotalFiles=%d, want 5", plan.TotalFiles)
	}
	if len(plan.TierSummaries) != 2 {
		t.Fatalf("TierSummaries count=%d, want 2", len(plan.TierSummaries))
	}

	// critical: 3 files, 1 older than 30d (2 left ≥ keep_min=2) → 1 prune
	var critSummary *pruneplan.SnapshotPlanTierSummary
	var ncSummary *pruneplan.SnapshotPlanTierSummary
	for i := range plan.TierSummaries {
		switch plan.TierSummaries[i].Tier {
		case "critical":
			critSummary = &plan.TierSummaries[i]
		case "non_critical":
			ncSummary = &plan.TierSummaries[i]
		}
	}
	if critSummary == nil {
		t.Fatal("missing critical tier summary")
	}
	if critSummary.Total != 3 {
		t.Fatalf("critical Total=%d, want 3", critSummary.Total)
	}
	if critSummary.ActionCount != 1 {
		t.Fatalf("critical ActionCount=%d, want 1", critSummary.ActionCount)
	}

	if ncSummary == nil {
		t.Fatal("missing non_critical tier summary")
	}
	if ncSummary.Total != 2 {
		t.Fatalf("non_critical Total=%d, want 2", ncSummary.Total)
	}
	// dev/2026-02-01 is 22 days old, > 14d, but keep_min=2 with only 2 files → 0 actions
	if ncSummary.ActionCount != 0 {
		t.Fatalf("non_critical ActionCount=%d, want 0 (keep-min floor)", ncSummary.ActionCount)
	}
}

func TestBuildSnapshotPlan_PerTierKeepMin(t *testing.T) {
	now := time.Date(2026, 2, 23, 0, 0, 0, 0, time.UTC)
	files := []pruner.SnapshotFile{
		{RelPath: "prod/new1.json", CapturedAt: now.AddDate(0, 0, -1)},
		{RelPath: "prod/new2.json", CapturedAt: now.AddDate(0, 0, -2)},
		{RelPath: "prod/new3.json", CapturedAt: now.AddDate(0, 0, -3)},
		{RelPath: "prod/old1.json", CapturedAt: now.AddDate(0, 0, -40)},
		{RelPath: "prod/old2.json", CapturedAt: now.AddDate(0, 0, -50)},
	}

	plan := buildPlan(planBuildParams{
		Now:         now,
		ObsRoot:     "./observations",
		DefaultTier: "critical",
		TierRules:   []retention.MappingRule{{Pattern: "prod/**", Tier: "critical"}},
		Tiers: map[string]retention.TierConfig{
			"critical": {OlderThan: "30d", KeepMin: 3},
		},
		Files: files,
	})

	if plan.TotalActions != 2 {
		t.Fatalf("TotalActions=%d, want 2 (5 files - keep_min=3 = 2 prunable)", plan.TotalActions)
	}
}

func TestBuildSnapshotPlan_ArchiveMode(t *testing.T) {
	now := time.Date(2026, 2, 23, 0, 0, 0, 0, time.UTC)
	files := []pruner.SnapshotFile{
		{RelPath: "new.json", CapturedAt: now.AddDate(0, 0, -1)},
		{RelPath: "old1.json", CapturedAt: now.AddDate(0, 0, -40)},
		{RelPath: "old2.json", CapturedAt: now.AddDate(0, 0, -50)},
	}

	plan := buildPlan(planBuildParams{
		Now:         now,
		ObsRoot:     "./observations",
		ArchiveDir:  "./observations/archive",
		DefaultTier: "critical",
		Tiers: map[string]retention.TierConfig{
			"critical": {OlderThan: "14d", KeepMin: 1},
		},
		Files: files,
		Apply: true,
		Force: true,
	})

	if plan.Mode != pruneplan.ModeArchive {
		t.Fatalf("Mode=%q, want ARCHIVE", plan.Mode)
	}
	if !plan.Applied {
		t.Fatal("Applied=false, want true")
	}

	archiveCount := 0
	for _, f := range plan.Files {
		if f.Action == pruneplan.ActionArchive {
			archiveCount++
		}
	}
	if archiveCount != 2 {
		t.Fatalf("ARCHIVE count=%d, want 2", archiveCount)
	}
}

func TestBuildSnapshotPlan_DefaultTierForUnmappedFiles(t *testing.T) {
	now := time.Date(2026, 2, 23, 0, 0, 0, 0, time.UTC)
	files := []pruner.SnapshotFile{
		{RelPath: "staging/file.json", CapturedAt: now.AddDate(0, 0, -1)},
	}

	rules := []retention.MappingRule{
		{Pattern: "prod/**", Tier: "critical"},
	}

	plan := buildPlan(planBuildParams{
		Now:         now,
		ObsRoot:     "./observations",
		DefaultTier: "non_critical",
		TierRules:   rules,
		Tiers: map[string]retention.TierConfig{
			"critical":     {OlderThan: "30d", KeepMin: 2},
			"non_critical": {OlderThan: "14d", KeepMin: 2},
		},
		Files: files,
	})

	if len(plan.Files) != 1 {
		t.Fatalf("Files count=%d, want 1", len(plan.Files))
	}
	if plan.Files[0].Tier != "non_critical" {
		t.Fatalf("file tier=%q, want non_critical", plan.Files[0].Tier)
	}
}

func TestBuildSnapshotPlan_NoFiles(t *testing.T) {
	now := time.Date(2026, 2, 23, 0, 0, 0, 0, time.UTC)

	plan := buildPlan(planBuildParams{
		Now:         now,
		ObsRoot:     "./observations",
		DefaultTier: "critical",
		Tiers: map[string]retention.TierConfig{
			"critical": {OlderThan: "30d", KeepMin: 2},
		},
		Files: nil,
	})

	if plan.TotalFiles != 0 {
		t.Fatalf("TotalFiles=%d, want 0", plan.TotalFiles)
	}
	if plan.TotalActions != 0 {
		t.Fatalf("TotalActions=%d, want 0", plan.TotalActions)
	}
	if len(plan.TierSummaries) != 0 {
		t.Fatalf("TierSummaries=%d, want 0", len(plan.TierSummaries))
	}
}

func TestBuildSnapshotPlan_ApplyWithoutForceIsPreview(t *testing.T) {
	now := time.Date(2026, 2, 23, 0, 0, 0, 0, time.UTC)

	plan := buildPlan(planBuildParams{
		Now:         now,
		ObsRoot:     "./observations",
		DefaultTier: "critical",
		Tiers: map[string]retention.TierConfig{
			"critical": {OlderThan: "30d", KeepMin: 2},
		},
		Files: nil,
		Apply: true,
		Force: false,
	})

	if plan.Mode != pruneplan.ModePreview {
		t.Fatalf("Mode=%q, want PREVIEW (--apply without --force)", plan.Mode)
	}
	if plan.Applied {
		t.Fatal("Applied=true, want false")
	}
}

func TestBuildSnapshotPlan_PruneMode(t *testing.T) {
	now := time.Date(2026, 2, 23, 0, 0, 0, 0, time.UTC)
	files := []pruner.SnapshotFile{
		{RelPath: "new.json", CapturedAt: now.AddDate(0, 0, -1)},
		{RelPath: "old.json", CapturedAt: now.AddDate(0, 0, -50)},
	}

	plan := buildPlan(planBuildParams{
		Now:         now,
		ObsRoot:     "./observations",
		DefaultTier: "critical",
		Tiers: map[string]retention.TierConfig{
			"critical": {OlderThan: "14d", KeepMin: 1},
		},
		Files: files,
		Apply: true,
		Force: true,
	})

	if plan.Mode != pruneplan.ModePrune {
		t.Fatalf("Mode=%q, want PRUNE", plan.Mode)
	}

	pruneCount := 0
	for _, f := range plan.Files {
		if f.Action == pruneplan.ActionPrune {
			pruneCount++
		}
	}
	if pruneCount != 1 {
		t.Fatalf("PRUNE count=%d, want 1", pruneCount)
	}
}

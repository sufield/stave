package snapplan

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/retention"
)

var baseTime = time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

func makeFiles(ages ...time.Duration) []File {
	files := make([]File, len(ages))
	for i, age := range ages {
		t := baseTime.Add(-age)
		files[i] = File{
			Path:       "/obs/" + t.Format("20060102") + ".json",
			RelPath:    t.Format("20060102") + ".json",
			Name:       t.Format("20060102") + ".json",
			CapturedAt: t,
		}
	}
	return files
}

func TestBuildPlan_BasicPrune(t *testing.T) {
	files := makeFiles(
		72*time.Hour, // old
		48*time.Hour, // old
		24*time.Hour, // recent
		1*time.Hour,  // recent
	)

	plan, err := BuildPlan(BuildPlanParams{
		Now:              baseTime,
		ObsRoot:          "/obs",
		DefaultTier:      "default",
		Files:            files,
		DefaultOlderThan: 36 * time.Hour,
		DefaultKeepMin:   1,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	if plan.SchemaVersion != kernel.SchemaSnapshotPlan {
		t.Errorf("schema = %q, want %q", plan.SchemaVersion, kernel.SchemaSnapshotPlan)
	}
	if plan.Kind != kernel.KindSnapshotPlan {
		t.Errorf("kind = %q, want %q", plan.Kind, kernel.KindSnapshotPlan)
	}
	if plan.TotalFiles != 4 {
		t.Errorf("TotalFiles = %d, want 4", plan.TotalFiles)
	}
	if plan.Mode != ModePreview {
		t.Errorf("Mode = %q, want PREVIEW", plan.Mode)
	}
	if plan.Applied {
		t.Error("Applied should be false for preview mode")
	}

	// 2 files are older than 36h. Total=4, keepMin=1, so PlanPrune will mark
	// the oldest files beyond the keepMin floor. With 4 files and keepMin=1,
	// all 2 expired files get pruned (4-2=2 >= keepMin).
	if plan.TotalActions != 2 {
		t.Errorf("TotalActions = %d, want 2", plan.TotalActions)
	}

	pruneCount := 0
	for _, f := range plan.Files {
		if f.Action == ActionPrune {
			pruneCount++
		}
	}
	if pruneCount != 2 {
		t.Errorf("prune count = %d, want 2", pruneCount)
	}
}

func TestBuildPlan_ArchiveMode(t *testing.T) {
	files := makeFiles(72*time.Hour, 1*time.Hour)

	plan, err := BuildPlan(BuildPlanParams{
		Now:              baseTime,
		ObsRoot:          "/obs",
		ArchiveDir:       "/archive",
		DefaultTier:      "default",
		Files:            files,
		Apply:            true,
		Force:            true,
		DefaultOlderThan: 36 * time.Hour,
		DefaultKeepMin:   0,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	if plan.Mode != ModeArchive {
		t.Errorf("Mode = %q, want ARCHIVE", plan.Mode)
	}
	if !plan.Applied {
		t.Error("Applied should be true")
	}
	if plan.ArchiveDir != "/archive" {
		t.Errorf("ArchiveDir = %q, want /archive", plan.ArchiveDir)
	}

	archiveCount := 0
	for _, f := range plan.Files {
		if f.Action == ActionArchive {
			archiveCount++
		}
	}
	if archiveCount != 1 {
		t.Errorf("archive count = %d, want 1", archiveCount)
	}
}

func TestBuildPlan_PruneMode(t *testing.T) {
	files := makeFiles(72*time.Hour, 1*time.Hour)

	plan, err := BuildPlan(BuildPlanParams{
		Now:              baseTime,
		ObsRoot:          "/obs",
		DefaultTier:      "default",
		Files:            files,
		Apply:            true,
		Force:            true,
		DefaultOlderThan: 36 * time.Hour,
		DefaultKeepMin:   0,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	if plan.Mode != ModePrune {
		t.Errorf("Mode = %q, want PRUNE", plan.Mode)
	}
	if !plan.Applied {
		t.Error("Applied should be true")
	}
}

func TestBuildPlan_PreviewWhenNotForced(t *testing.T) {
	plan, err := BuildPlan(BuildPlanParams{
		Now:              baseTime,
		ObsRoot:          "/obs",
		DefaultTier:      "default",
		Files:            makeFiles(72 * time.Hour),
		Apply:            true,
		Force:            false,
		DefaultOlderThan: 36 * time.Hour,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}
	if plan.Mode != ModePreview {
		t.Errorf("Mode = %q, want PREVIEW (apply without force)", plan.Mode)
	}
	if plan.Applied {
		t.Error("Applied should be false when force is not set")
	}
}

func TestBuildPlan_ZeroNowDefaultsToNonZero(t *testing.T) {
	plan, err := BuildPlan(BuildPlanParams{
		ObsRoot:          "/obs",
		DefaultTier:      "default",
		Files:            makeFiles(1 * time.Hour),
		DefaultOlderThan: 36 * time.Hour,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}
	if plan.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero when Now defaults")
	}
}

func TestBuildPlan_EmptyFiles(t *testing.T) {
	plan, err := BuildPlan(BuildPlanParams{
		Now:              baseTime,
		ObsRoot:          "/obs",
		DefaultTier:      "default",
		DefaultOlderThan: 36 * time.Hour,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}
	if plan.TotalFiles != 0 {
		t.Errorf("TotalFiles = %d, want 0", plan.TotalFiles)
	}
	if plan.TotalActions != 0 {
		t.Errorf("TotalActions = %d, want 0", plan.TotalActions)
	}
	if len(plan.TierSummaries) != 0 {
		t.Errorf("TierSummaries len = %d, want 0", len(plan.TierSummaries))
	}
}

func TestBuildPlan_MultipleTiers(t *testing.T) {
	files := []File{
		{RelPath: "hot/snap1.json", CapturedAt: baseTime.Add(-72 * time.Hour)},
		{RelPath: "hot/snap2.json", CapturedAt: baseTime.Add(-1 * time.Hour)},
		{RelPath: "cold/snap1.json", CapturedAt: baseTime.Add(-72 * time.Hour)},
	}

	resolver := TierResolverFunc(func(relPath string) string {
		if strings.HasPrefix(relPath, "hot/") {
			return "hot"
		}
		return "cold"
	})

	plan, err := BuildPlan(BuildPlanParams{
		Now:         baseTime,
		ObsRoot:     "/obs",
		DefaultTier: "default",
		Tiers: map[string]retention.Tier{
			"hot":  {OlderThan: "48h", KeepMin: 0},
			"cold": {OlderThan: "24h", KeepMin: 0},
		},
		Files:            files,
		DefaultOlderThan: 36 * time.Hour,
		TierResolver:     resolver,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	if len(plan.TierSummaries) != 2 {
		t.Fatalf("TierSummaries len = %d, want 2", len(plan.TierSummaries))
	}

	// Summaries should be sorted by tier name
	if plan.TierSummaries[0].Tier != "cold" {
		t.Errorf("first tier = %q, want cold", plan.TierSummaries[0].Tier)
	}
	if plan.TierSummaries[1].Tier != "hot" {
		t.Errorf("second tier = %q, want hot", plan.TierSummaries[1].Tier)
	}
}

func TestBuildPlan_InvalidTierDuration(t *testing.T) {
	files := makeFiles(72 * time.Hour)

	_, err := BuildPlan(BuildPlanParams{
		Now:         baseTime,
		ObsRoot:     "/obs",
		DefaultTier: "default",
		Tiers: map[string]retention.Tier{
			"default": {OlderThan: "invalid-duration"},
		},
		Files:            files,
		DefaultOlderThan: 36 * time.Hour,
	})
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
	if !strings.Contains(err.Error(), "invalid duration") {
		t.Errorf("error = %q, want 'invalid duration' substring", err.Error())
	}
}

func TestBuildPlan_TierResolverReturnsEmpty(t *testing.T) {
	files := []File{
		{RelPath: "snap.json", CapturedAt: baseTime.Add(-1 * time.Hour)},
	}

	resolver := TierResolverFunc(func(string) string {
		return "" // empty return should fall back to default tier
	})

	plan, err := BuildPlan(BuildPlanParams{
		Now:              baseTime,
		ObsRoot:          "/obs",
		DefaultTier:      "fallback",
		Files:            files,
		DefaultOlderThan: 36 * time.Hour,
		TierResolver:     resolver,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	if len(plan.TierSummaries) != 1 {
		t.Fatalf("TierSummaries len = %d, want 1", len(plan.TierSummaries))
	}
	if plan.TierSummaries[0].Tier != "fallback" {
		t.Errorf("tier = %q, want fallback", plan.TierSummaries[0].Tier)
	}
}

func TestBuildPlan_KeepMinFloorReason(t *testing.T) {
	// All files are old, but keepMin keeps some
	files := makeFiles(72*time.Hour, 48*time.Hour)

	plan, err := BuildPlan(BuildPlanParams{
		Now:              baseTime,
		ObsRoot:          "/obs",
		DefaultTier:      "default",
		Files:            files,
		DefaultOlderThan: 24 * time.Hour,
		DefaultKeepMin:   1,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	keepFloorFound := false
	for _, f := range plan.Files {
		if f.Action == ActionKeep && f.Reason == "keep-min floor" {
			keepFloorFound = true
		}
	}
	if !keepFloorFound {
		t.Error("expected at least one file with 'keep-min floor' reason")
	}
}

func TestBuildPlan_WithinRetentionReason(t *testing.T) {
	files := makeFiles(1 * time.Hour) // within 36h window

	plan, err := BuildPlan(BuildPlanParams{
		Now:              baseTime,
		ObsRoot:          "/obs",
		DefaultTier:      "default",
		Files:            files,
		DefaultOlderThan: 36 * time.Hour,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	if len(plan.Files) != 1 {
		t.Fatalf("files len = %d, want 1", len(plan.Files))
	}
	if plan.Files[0].Reason != "within retention" {
		t.Errorf("reason = %q, want 'within retention'", plan.Files[0].Reason)
	}
}

// --- resolveMode tests ---

func TestResolveMode(t *testing.T) {
	tests := []struct {
		name       string
		apply      bool
		force      bool
		archiveDir string
		wantMode   Mode
		wantApply  bool
	}{
		{"preview default", false, false, "", ModePreview, false},
		{"apply without force", true, false, "", ModePreview, false},
		{"force without apply", false, true, "", ModePreview, false},
		{"prune", true, true, "", ModePrune, true},
		{"archive", true, true, "/archive", ModeArchive, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, applied := resolveMode(tt.apply, tt.force, tt.archiveDir)
			if mode != tt.wantMode {
				t.Errorf("mode = %q, want %q", mode, tt.wantMode)
			}
			if applied != tt.wantApply {
				t.Errorf("applied = %v, want %v", applied, tt.wantApply)
			}
		})
	}
}

// --- groupFilesByTier tests ---

func TestGroupFilesByTier(t *testing.T) {
	files := []File{
		{RelPath: "a/snap1.json"},
		{RelPath: "b/snap2.json"},
		{RelPath: "c/snap3.json"},
	}

	t.Run("nil resolver uses default", func(t *testing.T) {
		groups := groupFilesByTier(files, "default", nil)
		if len(groups) != 1 {
			t.Fatalf("groups = %d, want 1", len(groups))
		}
		if len(groups["default"]) != 3 {
			t.Errorf("default group = %d files, want 3", len(groups["default"]))
		}
	})

	t.Run("resolver overrides", func(t *testing.T) {
		resolver := TierResolverFunc(func(path string) string {
			if strings.HasPrefix(path, "a/") {
				return "hot"
			}
			return ""
		})
		groups := groupFilesByTier(files, "default", resolver)
		if len(groups["hot"]) != 1 {
			t.Errorf("hot group = %d files, want 1", len(groups["hot"]))
		}
		if len(groups["default"]) != 2 {
			t.Errorf("default group = %d files, want 2", len(groups["default"]))
		}
	})
}

// --- sortedTierNames tests ---

func TestSortedTierNames(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got := sortedTierNames(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("sorted", func(t *testing.T) {
		m := map[string][]File{
			"cold": nil,
			"hot":  nil,
			"warm": nil,
		}
		got := sortedTierNames(m)
		want := []string{"cold", "hot", "warm"}
		if len(got) != len(want) {
			t.Fatalf("len = %d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("index %d = %q, want %q", i, got[i], want[i])
			}
		}
	})
}

// --- TierResolverFunc tests ---

func TestTierResolverFunc(t *testing.T) {
	fn := TierResolverFunc(func(path string) string {
		return "resolved-" + path
	})
	if got := fn.Resolve("test"); got != "resolved-test" {
		t.Errorf("Resolve() = %q, want resolved-test", got)
	}
}

// --- RenderPlanText tests ---

func TestRenderPlanText_Preview(t *testing.T) {
	plan := &PlanOutput{
		GeneratedAt:      baseTime,
		ObservationsRoot: "/obs",
		Mode:             ModePreview,
		DefaultTier:      "default",
		TotalFiles:       2,
		TotalActions:     1,
		TierSummaries: []PlanTierSummary{
			{Tier: "default", OlderThan: "36h0m0s", KeepMin: 1, Total: 2, KeepCount: 1, ActionCount: 1},
		},
		Files: []PlanFile{
			{RelPath: "old.json", CapturedAt: baseTime.Add(-72 * time.Hour), Tier: "default", Action: ActionPrune, Reason: "older than 36h0m0s"},
			{RelPath: "new.json", CapturedAt: baseTime.Add(-1 * time.Hour), Tier: "default", Action: ActionKeep, Reason: "within retention"},
		},
	}

	var buf bytes.Buffer
	if err := RenderPlanText(&buf, plan); err != nil {
		t.Fatalf("RenderPlanText() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Snapshot Retention Plan") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "PREVIEW") {
		t.Error("missing PREVIEW mode")
	}
	if !strings.Contains(out, "--apply --force") {
		t.Error("missing apply hint")
	}
	if !strings.Contains(out, "PRUNE") {
		t.Error("missing PRUNE action")
	}
	if !strings.Contains(out, "KEEP") {
		t.Error("missing KEEP action")
	}
	if !strings.Contains(out, "Total Files:   2") {
		t.Error("missing total files")
	}
}

func TestRenderPlanText_EmptyPlan(t *testing.T) {
	plan := &PlanOutput{
		GeneratedAt:      baseTime,
		ObservationsRoot: "/obs",
		Mode:             ModePreview,
	}

	var buf bytes.Buffer
	if err := RenderPlanText(&buf, plan); err != nil {
		t.Fatalf("RenderPlanText() error: %v", err)
	}

	if !strings.Contains(buf.String(), "No snapshots discovered") {
		t.Error("expected 'No snapshots discovered'")
	}
}

func TestRenderPlanText_ArchiveMode(t *testing.T) {
	plan := &PlanOutput{
		GeneratedAt:      baseTime,
		ObservationsRoot: "/obs",
		ArchiveDir:       "/archive",
		Mode:             ModeArchive,
		Applied:          true,
		TotalFiles:       1,
		TotalActions:     1,
		TierSummaries: []PlanTierSummary{
			{Tier: "default", OlderThan: "36h0m0s", KeepMin: 0, Total: 1, KeepCount: 0, ActionCount: 1},
		},
		Files: []PlanFile{
			{RelPath: "old.json", CapturedAt: baseTime.Add(-72 * time.Hour), Tier: "default", Action: ActionArchive, Reason: "older than 36h0m0s"},
		},
	}

	var buf bytes.Buffer
	if err := RenderPlanText(&buf, plan); err != nil {
		t.Fatalf("RenderPlanText() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Archive:   /archive") {
		t.Error("missing archive dir")
	}
	if !strings.Contains(out, "archived") {
		t.Error("missing 'archived' verb")
	}
}

func TestRenderPlanText_PruneMode(t *testing.T) {
	plan := &PlanOutput{
		GeneratedAt:      baseTime,
		ObservationsRoot: "/obs",
		Mode:             ModePrune,
		Applied:          true,
		TotalFiles:       1,
		TotalActions:     1,
		TierSummaries: []PlanTierSummary{
			{Tier: "default", OlderThan: "36h0m0s", KeepMin: 0, Total: 1, KeepCount: 0, ActionCount: 1},
		},
		Files: []PlanFile{
			{RelPath: "old.json", CapturedAt: baseTime.Add(-72 * time.Hour), Tier: "default", Action: ActionPrune, Reason: "older than 36h0m0s"},
		},
	}

	var buf bytes.Buffer
	if err := RenderPlanText(&buf, plan); err != nil {
		t.Fatalf("RenderPlanText() error: %v", err)
	}

	if !strings.Contains(buf.String(), "pruned") {
		t.Error("missing 'pruned' verb in prune mode")
	}
}

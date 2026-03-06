package asset

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"
)

// --- validation context ---

// validationCtx caches cross-snapshot metadata computed in a single O(N) pass.
// Methods that consume it avoid re-traversing snapshots for time bounds or identity maps.
type validationCtx struct {
	timeline    *snapshotTimeline
	assetCounts map[ID]assetOccurrence
	assetTypes  map[ID]assetTypeSet // asset_id -> set of types
}

// analyze builds the validation context in a single pass over all snapshots.
func (s Snapshots) analyze() *validationCtx {
	if s.IsEmpty() {
		return &validationCtx{
			assetCounts: make(map[ID]assetOccurrence),
			assetTypes:  make(map[ID]assetTypeSet),
		}
	}

	ctx := &validationCtx{
		timeline:    newSnapshotTimeline(s[0].CapturedAt),
		assetCounts: make(map[ID]assetOccurrence),
		assetTypes:  make(map[ID]assetTypeSet),
	}

	timeCounts := make(map[time.Time]int, len(s))
	for _, snap := range s {
		ctx.timeline.observe(snap.CapturedAt)

		timeCounts[snap.CapturedAt]++

		seenInSnap := make(map[ID]struct{})
		for _, r := range snap.Assets {
			assetID := ID(r.ID)
			if _, ok := seenInSnap[assetID]; !ok {
				ctx.assetCounts[assetID]++
				seenInSnap[assetID] = struct{}{}
			}
			types := ctx.assetTypes[assetID]
			if types == nil {
				types = make(assetTypeSet)
				ctx.assetTypes[assetID] = types
			}
			types.add(r.Type)
		}
	}

	ctx.timeline.finalize(timeCounts)
	return ctx
}

// --- validation helper types ---

type assetOccurrence int

func (o assetOccurrence) IsTransient() bool {
	return o == 1
}

type assetTypeSet map[kernel.AssetType]struct{}

func (s assetTypeSet) add(resourceType kernel.AssetType) {
	s[resourceType] = struct{}{}
}

func (s assetTypeSet) IsInconsistent() bool {
	return len(s) > 1
}

func (s assetTypeSet) List() []string {
	out := make([]string, 0, len(s))
	for t := range s {
		out = append(out, string(t))
	}
	slices.Sort(out)
	return out
}

type snapshotTimeline struct {
	earliest       time.Time
	latest         time.Time
	span           time.Duration
	duplicateTimes []time.Time
}

func newSnapshotTimeline(seed time.Time) *snapshotTimeline {
	return &snapshotTimeline{earliest: seed, latest: seed}
}

func (t *snapshotTimeline) observe(capturedAt time.Time) {
	if capturedAt.Before(t.earliest) {
		t.earliest = capturedAt
	}
	if capturedAt.After(t.latest) {
		t.latest = capturedAt
	}
}

func (t *snapshotTimeline) finalize(timeCounts map[time.Time]int) {
	for ts, count := range timeCounts {
		if count > 1 {
			t.duplicateTimes = append(t.duplicateTimes, ts)
		}
	}
	slices.SortFunc(t.duplicateTimes, func(a, b time.Time) int {
		return a.Compare(b)
	})
	t.span = t.latest.Sub(t.earliest)
}

func (t *snapshotTimeline) hasInsufficientSpan(required time.Duration) bool {
	return t.span < required
}

func (t *snapshotTimeline) HasDuplicates() bool {
	return t != nil && len(t.duplicateTimes) > 0
}

func (t *snapshotTimeline) DuplicateTimes() []time.Time {
	if t == nil || len(t.duplicateTimes) == 0 {
		return nil
	}
	out := make([]time.Time, len(t.duplicateTimes))
	copy(out, t.duplicateTimes)
	return out
}

func (t *snapshotTimeline) IsAheadOf(other time.Time) bool {
	if t == nil || other.IsZero() {
		return false
	}
	return t.latest.After(other)
}

// FormatLatest returns the latest captured_at in RFC3339 for reporting.
func (t *snapshotTimeline) FormatLatest() string {
	if t == nil {
		return ""
	}
	return t.latest.Format(time.RFC3339)
}

// ValidateAll runs all snapshot validation checks using a pre-computed context.
func (s Snapshots) ValidateAll(now time.Time, maxUnsafe time.Duration) []diag.Issue {
	if s.IsEmpty() {
		return []diag.Issue{
			diag.New(diag.CodeNoSnapshots).
				Warning().
				Action("Add observation JSON files to the directory").
				Build(),
		}
	}

	ctx := s.analyze()
	var issues []diag.Issue

	issues = append(issues, s.checkStructural()...)
	issues = append(issues, s.checkTagSanity()...)
	issues = append(issues, s.checkTimeSanity(ctx, now)...)
	issues = append(issues, s.checkIdentityConsistency(ctx)...)
	issues = append(issues, s.checkDurationFeasibility(ctx, maxUnsafe)...)

	return issues
}

// checkStructural validates per-snapshot structure (duplicate IDs).
func (s Snapshots) checkStructural() (issues []diag.Issue) {
	if s.IsSingle() {
		issues = append(issues, diag.New(diag.CodeSingleSnapshot).
			Warning().
			Action("Add at least 2 snapshots to enable duration tracking").
			WithMap(map[string]string{
				"snapshot_count": "1",
			}).
			Build())
	}

	for _, snap := range s {
		seen := make(map[string]struct{})
		for _, r := range snap.Assets {
			assetID := r.ID.String()
			if _, exists := seen[assetID]; exists {
				issues = append(issues, diag.New(diag.CodeDuplicateAssetID).
					Warning().
					Action("Ensure each asset has a unique ID within a snapshot").
					WithMap(map[string]string{
						"asset_id":    assetID,
						"snapshot_at": snap.CapturedAt.Format(time.RFC3339),
					}).
					Build())
			}
			seen[assetID] = struct{}{}
		}
	}

	return
}

// checkTagSanity validates case-insensitive key conflicts in asset tags.
func (s Snapshots) checkTagSanity() (issues []diag.Issue) {
	for _, snap := range s {
		for _, r := range snap.Assets {
			tags := r.Tags()
			if !tags.HasConflicts() {
				continue
			}
			issues = append(issues, diag.New(diag.CodeAmbiguousTags).
				Warning().
				Action("Use a single casing per tag key (for example, choose either \"Env\" or \"env\")").
				WithMap(map[string]string{
					"asset_id":      r.ID.String(),
					"snapshot_at":   snap.CapturedAt.Format(time.RFC3339),
					"conflict_keys": strings.Join(tags.Conflicts(), ", "),
				}).
				Build())
		}
	}
	return
}

// checkTimeSanity validates time ordering and uniqueness.
func (s Snapshots) checkTimeSanity(ctx *validationCtx, now time.Time) (issues []diag.Issue) {
	if unsorted, ok := s.FindFirstUnsortedPair(); ok {
		issues = append(issues, diag.New(diag.CodeSnapshotsUnsorted).
			Warning().
			Action("Sort snapshots by captured_at or check for timestamp errors").
			WithMap(unsorted.Evidence()).
			Build())
	}

	if ctx == nil || ctx.timeline == nil {
		return
	}

	if ctx.timeline.HasDuplicates() {
		for _, ts := range ctx.timeline.DuplicateTimes() {
			issues = append(issues, diag.New(diag.CodeDuplicateTimestamp).
				Warning().
				Action("Each snapshot should have a unique captured_at timestamp").
				WithMap(map[string]string{
					"timestamp": ts.Format(time.RFC3339),
				}).
				Build())
		}
	}

	if ctx.timeline.IsAheadOf(now) {
		issues = append(issues, s.createNowPrecedenceError(now, ctx.timeline))
	}

	return
}

func (s Snapshots) createNowPrecedenceError(now time.Time, timeline *snapshotTimeline) diag.Issue {
	latest := timeline.FormatLatest()
	issue := diag.New(diag.CodeNowBeforeSnapshots).
		Error().
		Action("Set --now >= latest snapshot timestamp").
		WithMap(map[string]string{
			"now":             now.Format(time.RFC3339),
			"latest_snapshot": latest,
		}).
		Build()
	issue.Command = fmt.Sprintf("stave validate --now %s", latest)
	return issue
}

// checkIdentityConsistency validates asset identity across snapshots.
func (s Snapshots) checkIdentityConsistency(ctx *validationCtx) (issues []diag.Issue) {
	reusedTypeIDs := make([]ID, 0, len(ctx.assetTypes))
	for id, types := range ctx.assetTypes {
		if types.IsInconsistent() {
			reusedTypeIDs = append(reusedTypeIDs, id)
		}
	}
	slices.SortFunc(reusedTypeIDs, func(a, b ID) int {
		return strings.Compare(a.String(), b.String())
	})
	for _, id := range reusedTypeIDs {
		types := ctx.assetTypes[id]
		issues = append(issues, diag.New(diag.CodeAssetIDReusedTypes).
			Warning().
			Action("Use unique asset IDs for different asset types").
			WithMap(map[string]string{
				"asset_id": id.String(),
				"types":    strings.Join(types.List(), ", "),
			}).
			Build())
	}

	if s.IsMultiSnapshot() {
		singleAppearanceIDs := make([]ID, 0, len(ctx.assetCounts))
		for id, count := range ctx.assetCounts {
			if count.IsTransient() {
				singleAppearanceIDs = append(singleAppearanceIDs, id)
			}
		}
		slices.SortFunc(singleAppearanceIDs, func(a, b ID) int {
			return strings.Compare(a.String(), b.String())
		})
		for _, id := range singleAppearanceIDs {
			issues = append(issues, diag.New(diag.CodeAssetSingleAppearance).
				Warning().
				Action("Duration tracking requires asset to appear in multiple snapshots").
				WithMap(map[string]string{
					"asset_id": id.String(),
				}).
				Build())
		}
	}

	return
}

// checkDurationFeasibility checks if the snapshot span covers the threshold.
func (s Snapshots) checkDurationFeasibility(ctx *validationCtx, maxUnsafe time.Duration) (issues []diag.Issue) {
	if !s.IsMultiSnapshot() || maxUnsafe <= 0 || ctx == nil || ctx.timeline == nil {
		return
	}

	if ctx.timeline.hasInsufficientSpan(maxUnsafe) {
		issue := diag.New(diag.CodeSpanLessThanMaxUnsafe).
			Warning().
			Action("Add older snapshots or reduce --max-unsafe").
			WithMap(map[string]string{
				"span":       kernel.FormatDuration(ctx.timeline.span),
				"max_unsafe": kernel.FormatDuration(maxUnsafe),
			}).
			Build()
		issue.Command = fmt.Sprintf("stave validate --max-unsafe %s", kernel.FormatDuration(ctx.timeline.span))
		issues = append(issues, issue)
	}

	return
}

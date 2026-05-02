package asset

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
)

// --- validation context ---

// validationCtx caches cross-snapshot metadata computed in a single O(N) pass.
// Methods that consume it avoid re-traversing snapshots for time bounds or identity maps.
type validationCtx struct {
	lifecycle   *snapshotLifecycle
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
		lifecycle:   newSnapshotTimeline(s[0].CapturedAt),
		assetCounts: make(map[ID]assetOccurrence),
		assetTypes:  make(map[ID]assetTypeSet),
	}

	timeCounts := make(map[time.Time]int, len(s))
	for _, snap := range s {
		ctx.lifecycle.observe(snap.CapturedAt)

		timeCounts[snap.CapturedAt]++

		seenInSnap := make(map[ID]struct{})
		for _, r := range snap.Assets {
			assetID := r.ID
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

	ctx.lifecycle.finalize(timeCounts)
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

type snapshotLifecycle struct {
	earliest       time.Time
	latest         time.Time
	span           time.Duration
	duplicateTimes []time.Time
}

func newSnapshotTimeline(seed time.Time) *snapshotLifecycle {
	return &snapshotLifecycle{earliest: seed, latest: seed}
}

func (t *snapshotLifecycle) observe(capturedAt time.Time) {
	if capturedAt.Before(t.earliest) {
		t.earliest = capturedAt
	}
	if capturedAt.After(t.latest) {
		t.latest = capturedAt
	}
}

func (t *snapshotLifecycle) finalize(timeCounts map[time.Time]int) {
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

func (t *snapshotLifecycle) hasInsufficientSpan(required time.Duration) bool {
	return t.span < required
}

func (t *snapshotLifecycle) HasDuplicates() bool {
	return t != nil && len(t.duplicateTimes) > 0
}

func (t *snapshotLifecycle) DuplicateTimes() []time.Time {
	if t == nil || len(t.duplicateTimes) == 0 {
		return nil
	}
	out := make([]time.Time, len(t.duplicateTimes))
	copy(out, t.duplicateTimes)
	return out
}

func (t *snapshotLifecycle) IsAheadOf(other time.Time) bool {
	if t == nil || other.IsZero() {
		return false
	}
	return t.latest.After(other)
}

// FormatLatest returns the latest captured_at in RFC3339 for reporting.
func (t *snapshotLifecycle) FormatLatest() string {
	if t == nil {
		return ""
	}
	return t.latest.Format(time.RFC3339)
}

// ValidateAll runs all snapshot validation checks using a pre-computed context.
func (s Snapshots) ValidateAll(now time.Time, maxUnsafe time.Duration) []diag.Finding {
	if s.IsEmpty() {
		return []diag.Finding{
			diag.NewFinding(diag.RuleNoSnapshots).
				Warning().
				Remediation("Add observation JSON files to the directory").
				Build(),
		}
	}

	ctx := s.analyze()
	var issues []diag.Finding

	issues = append(issues, s.checkStructural()...)
	issues = append(issues, s.checkTagSanity()...)
	issues = append(issues, s.checkTimeSanity(ctx, now)...)
	issues = append(issues, s.checkIdentityConsistency(ctx)...)
	issues = append(issues, s.checkDurationFeasibility(ctx, maxUnsafe)...)

	return issues
}

// checkStructural validates per-snapshot structure (duplicate IDs).
func (s Snapshots) checkStructural() (issues []diag.Finding) {
	if s.IsSingle() {
		issues = append(issues, diag.NewFinding(diag.RuleSingleSnapshot).
			Warning().
			Remediation("Add at least 2 snapshots to enable duration tracking").
			Attributes(map[string]string{
				"snapshot_count": "1",
			}).
			Build())
	}

	for _, snap := range s {
		seen := make(map[string]struct{})
		for _, r := range snap.Assets {
			assetID := r.ID.String()
			if _, exists := seen[assetID]; exists {
				issues = append(issues, diag.NewFinding(diag.RuleDuplicateAssetID).
					Warning().
					Remediation("Ensure each asset has a unique ID within a snapshot").
					Attributes(map[string]string{
						"asset_id":    assetID,
						"snapshot_at": snap.CapturedAt.Format(time.RFC3339),
					}).
					Build())
			}
			seen[assetID] = struct{}{}
		}
	}

	return issues
}

// checkTagSanity validates case-insensitive key conflicts in asset tags.
func (s Snapshots) checkTagSanity() (issues []diag.Finding) {
	for _, snap := range s {
		for _, r := range snap.Assets {
			tags := r.Tags()
			if !tags.HasConflicts() {
				continue
			}
			for _, c := range tags.Conflicts() {
				issues = append(issues, diag.NewFinding(diag.RuleAmbiguousTags).
					Warning().
					Remediation(fmt.Sprintf("Use a single casing for tag key %q (kept %q, discarded %s)",
						c.Key, c.Kept, formatQuoted(c.Discarded))).
					Attributes(map[string]string{
						"asset_id":    r.ID.String(),
						"snapshot_at": snap.CapturedAt.Format(time.RFC3339),
						"conflict":    c.String(),
					}).
					Build())
			}
		}
	}
	return issues
}

// checkTimeSanity validates time ordering and uniqueness.
func (s Snapshots) checkTimeSanity(ctx *validationCtx, now time.Time) (issues []diag.Finding) {
	if unsorted, ok := s.FindFirstUnsortedPair(); ok {
		issues = append(issues, diag.NewFinding(diag.RuleSnapshotsUnsorted).
			Warning().
			Remediation("Sort snapshots by captured_at or check for timestamp errors").
			Attributes(unsorted.Evidence()).
			Build())
	}

	if ctx == nil || ctx.lifecycle == nil {
		return issues
	}

	if ctx.lifecycle.HasDuplicates() {
		for _, ts := range ctx.lifecycle.DuplicateTimes() {
			issues = append(issues, diag.NewFinding(diag.RuleDuplicateTimestamp).
				Warning().
				Remediation("Each snapshot should have a unique captured_at timestamp").
				Attributes(map[string]string{
					"timestamp": ts.Format(time.RFC3339),
				}).
				Build())
		}
	}

	if ctx.lifecycle.IsAheadOf(now.UTC()) {
		issues = append(issues, s.createNowPrecedenceError(now, ctx.lifecycle))
	}

	return issues
}

func (s Snapshots) createNowPrecedenceError(now time.Time, lifecycle *snapshotLifecycle) diag.Finding {
	latest := lifecycle.FormatLatest()
	issue := diag.NewFinding(diag.RuleNowBeforeSnapshots).
		Error().
		Remediation("Set --now >= latest snapshot timestamp").
		Attributes(map[string]string{
			"now":             now.Format(time.RFC3339),
			"latest_snapshot": latest,
		}).
		Build()
	issue.FixCommand = "stave validate --now " + latest
	return issue
}

// checkIdentityConsistency validates asset identity across snapshots.
func (s Snapshots) checkIdentityConsistency(ctx *validationCtx) (issues []diag.Finding) {
	var reusedTypeIDs []ID
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
		issues = append(issues, diag.NewFinding(diag.RuleAssetIDReusedTypes).
			Warning().
			Remediation("Use unique asset IDs for different asset types").
			Attributes(map[string]string{
				"asset_id": id.String(),
				"types":    strings.Join(types.List(), ", "),
			}).
			Build())
	}

	if s.IsMultiSnapshot() {
		var singleAppearanceIDs []ID
		for id, count := range ctx.assetCounts {
			if count.IsTransient() {
				singleAppearanceIDs = append(singleAppearanceIDs, id)
			}
		}
		slices.SortFunc(singleAppearanceIDs, func(a, b ID) int {
			return strings.Compare(a.String(), b.String())
		})
		for _, id := range singleAppearanceIDs {
			issues = append(issues, diag.NewFinding(diag.RuleAssetSingleAppearance).
				Warning().
				Remediation("Duration tracking requires asset to appear in multiple snapshots").
				Attributes(map[string]string{
					"asset_id": id.String(),
				}).
				Build())
		}
	}

	return issues
}

// checkDurationFeasibility checks if the snapshot span covers the threshold.
func (s Snapshots) checkDurationFeasibility(ctx *validationCtx, maxUnsafe time.Duration) (issues []diag.Finding) {
	if !s.IsMultiSnapshot() || maxUnsafe <= 0 || ctx == nil || ctx.lifecycle == nil {
		return issues
	}

	if ctx.lifecycle.hasInsufficientSpan(maxUnsafe) {
		issue := diag.NewFinding(diag.RuleSpanLessThanMaxUnsafe).
			Warning().
			Remediation("Add older snapshots or reduce --max-unsafe").
			Attributes(map[string]string{
				"span":       kernel.FormatDuration(ctx.lifecycle.span),
				"max_unsafe": kernel.FormatDuration(maxUnsafe),
			}).
			Build()
		issue.FixCommand = "stave validate --max-unsafe " + kernel.FormatDuration(ctx.lifecycle.span)
		issues = append(issues, issue)
	}

	return issues
}

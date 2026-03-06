package upcoming

import (
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
)

func newUpcomingFilter(criteria UpcomingFilterCriteria) (upcomingFilter, error) {
	filter := upcomingFilter{
		controlIDs:    map[kernel.ControlID]struct{}{},
		assetTypes: map[kernel.AssetType]struct{}{},
		statuses:      map[string]struct{}{},
		dueWithin:     criteria.DueWithin,
	}
	for _, id := range criteria.ControlIDs {
		if id == "" {
			continue
		}
		filter.controlIDs[id] = struct{}{}
	}
	for _, rt := range criteria.AssetTypes {
		if rt == "" {
			continue
		}
		filter.assetTypes[rt] = struct{}{}
	}
	for _, st := range criteria.Statuses {
		normalized := strings.ToUpper(strings.TrimSpace(st))
		if normalized == "" {
			continue
		}
		if !risk.ValidStatus(risk.Status(normalized)) {
			return upcomingFilter{}, fmt.Errorf("invalid --status %q (use: OVERDUE, DUE_NOW, UPCOMING)", st)
		}
		filter.statuses[normalized] = struct{}{}
	}
	return filter, nil
}

func applyUpcomingFilter(items []upcomingItem, now time.Time, filter upcomingFilter) []upcomingItem {
	if len(items) == 0 {
		return nil
	}
	out := make([]upcomingItem, 0, len(items))
	for _, item := range items {
		if includeUpcomingItem(item, now, filter) {
			out = append(out, item)
		}
	}
	return out
}

func includeUpcomingItem(item upcomingItem, now time.Time, filter upcomingFilter) bool {
	return matchesUpcomingControl(item, filter) &&
		matchesUpcomingResourceType(item, filter) &&
		matchesUpcomingStatus(item, filter) &&
		matchesUpcomingDueWindow(item, now, filter)
}

func matchesUpcomingControl(item upcomingItem, filter upcomingFilter) bool {
	if len(filter.controlIDs) == 0 {
		return true
	}
	_, ok := filter.controlIDs[kernel.ControlID(item.ControlID)]
	return ok
}

func matchesUpcomingResourceType(item upcomingItem, filter upcomingFilter) bool {
	if len(filter.assetTypes) == 0 {
		return true
	}
	_, ok := filter.assetTypes[kernel.AssetType(item.AssetType)]
	return ok
}

func matchesUpcomingStatus(item upcomingItem, filter upcomingFilter) bool {
	if len(filter.statuses) == 0 {
		return true
	}
	_, ok := filter.statuses[item.Status]
	return ok
}

func matchesUpcomingDueWindow(item upcomingItem, now time.Time, filter upcomingFilter) bool {
	if filter.dueWithin == nil {
		return true
	}
	return item.DueAt.Sub(now) <= *filter.dueWithin
}

package upcoming

import (
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/pkg/fp"
)

func newUpcomingFilter(criteria UpcomingFilterCriteria) (risk.FilterCriteria, error) {
	// Validate statuses before building filter.
	statuses := make(map[risk.Status]struct{}, len(criteria.Statuses))
	for _, st := range criteria.Statuses {
		normalized := risk.Status(strings.ToUpper(strings.TrimSpace(st)))
		if normalized == "" {
			continue
		}
		if !risk.ValidStatus(normalized) {
			return risk.FilterCriteria{}, fmt.Errorf("invalid --status %q (use: OVERDUE, DUE_NOW, UPCOMING)", st)
		}
		statuses[normalized] = struct{}{}
	}
	var maxRemaining = derefDuration(criteria.DueWithin)
	return risk.FilterCriteria{
		ControlIDs:   fp.ToSet(criteria.ControlIDs),
		AssetTypes:   fp.ToSet(criteria.AssetTypes),
		Statuses:     statuses,
		MaxRemaining: maxRemaining,
	}, nil
}

func derefDuration(d *time.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return *d
}

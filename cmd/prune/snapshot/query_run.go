package snapshot

import (
	"fmt"

	"github.com/sufield/stave/internal/app/snapshotquery"
)

// queryResult is the union of the two shapes `stave snapshot query`
// can return. Exactly one of HealthReport or Listing is populated,
// selected by whether --health was set. Using a single result type
// keeps the runner's signature flat and lets rendering choose the
// branch without needing a second path into run logic.
type queryResult struct {
	IsHealth     bool
	HealthReport *snapshotquery.HealthReport
	Listing      []snapshotquery.SnapshotInfo
}

// runQuery executes the snapshot query using the resolved options
// from Normalize. Returns a typed result; rendering is a separate
// concern in query_output.go.
func runQuery(opts queryOptions) (queryResult, error) {
	if opts.Health {
		report, err := snapshotquery.Health(opts.Dir, opts.Now)
		if err != nil {
			return queryResult{}, fmt.Errorf("snapshot health: %w", err)
		}
		return queryResult{IsHealth: true, HealthReport: report}, nil
	}

	f := snapshotquery.Filter{Now: opts.Now}
	if opts.HasOlderThan {
		f.OlderThan = opts.OlderThanDur
	}
	if opts.HasNewerThan {
		f.NewerThan = opts.NewerThanDur
	}

	results, err := snapshotquery.Query(opts.Dir, f)
	if err != nil {
		return queryResult{}, fmt.Errorf("snapshot query: %w", err)
	}
	return queryResult{Listing: results}, nil
}

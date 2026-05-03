package snapshot

import (
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/sufield/stave/internal/app/snapshotquery"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// Render writes the result in the requested format. Replaces the
// renderQuery free function and its double IsHealth check by
// hanging the dispatch off the result type that owns the
// IsHealth flag.
func (result queryResult) Render(w io.Writer, format string) error {
	payload := result.payload()
	if format == "json" {
		return jsonutil.WriteIndented(w, payload)
	}
	if result.IsHealth {
		return renderHealthText(w, result.HealthReport)
	}
	return renderListingText(w, result.Listing)
}

// payload returns the JSON-shaped struct for the result's active
// branch. Keeping the JSON dispatch on the type lets renderJSON
// stop branching on IsHealth in two places.
func (result queryResult) payload() any {
	if result.IsHealth {
		return result.HealthReport
	}
	return result.Listing
}

func renderHealthText(w io.Writer, r *snapshotquery.HealthReport) error {
	if _, err := fmt.Fprintf(w, "Total: %d  Valid: %d  Malformed: %d\n",
		r.Total, r.SchemaValid, len(r.Malformed)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "Age: <30d=%d  30-90d=%d  >90d=%d\n",
		r.ByAge.Under30, r.ByAge.From30To90, r.ByAge.Over90)
	return err
}

func renderListingText(w io.Writer, listing []snapshotquery.SnapshotInfo) error {
	if len(listing) == 0 {
		_, err := fmt.Fprintln(w, "No matching snapshots found.")
		return err
	}
	for _, s := range listing {
		if _, err := fmt.Fprintf(w, "%-40s  %s  %.0fd  %d assets\n",
			filepath.Base(s.Path), s.CapturedAt.Format(time.RFC3339), s.AgeDays, s.AssetCount); err != nil {
			return err
		}
	}
	return nil
}

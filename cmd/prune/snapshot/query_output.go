package snapshot

import (
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/sufield/stave/internal/app/snapshotquery"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// renderQuery writes the query result in the requested format to w.
// Takes no *cobra.Command — the caller resolves the writer at the
// RunE boundary.
func renderQuery(w io.Writer, result queryResult, format string) error {
	if format == "json" {
		if result.IsHealth {
			return jsonutil.WriteIndented(w, result.HealthReport)
		}
		return jsonutil.WriteIndented(w, result.Listing)
	}
	if result.IsHealth {
		return renderHealthText(w, result.HealthReport)
	}
	return renderListingText(w, result.Listing)
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

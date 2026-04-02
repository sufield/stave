package hygiene

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	outtext "github.com/sufield/stave/internal/adapters/output/text"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	hygieneapp "github.com/sufield/stave/internal/app/hygiene"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// loadSnapshotsIfDirExists retrieves snapshots from a directory only if it exists.
func loadSnapshotsIfDirExists(
	ctx context.Context,
	loader appcontracts.ObservationRepository,
	dir string,
) ([]asset.Snapshot, error) {
	if dir == "" {
		return nil, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%q must be a directory", dir)
	}
	result, err := loader.LoadSnapshots(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("loading snapshots from %q: %w", dir, err)
	}
	return result.Snapshots, nil
}

// filterSnapshotsBefore returns snapshots captured on or before cutoff, sorted chronologically.
func filterSnapshotsBefore(snapshots []asset.Snapshot, cutoff time.Time) []asset.Snapshot {
	filtered := make([]asset.Snapshot, 0, len(snapshots))
	for _, snap := range snapshots {
		if !snap.CapturedAt.After(cutoff) {
			filtered = append(filtered, snap)
		}
	}
	slices.SortFunc(filtered, func(a, b asset.Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})
	return filtered
}

// writeHygieneOutput dispatches the report to the correct presenter based on format.
func writeHygieneOutput(format appcontracts.OutputFormat, report appcontracts.ReportRequest, jsonOut hygieneapp.Output, w io.Writer) error {
	if format.IsJSON() {
		if err := jsonutil.WriteIndented(w, jsonOut); err != nil {
			return fmt.Errorf("writing hygiene JSON: %w", err)
		}
		return nil
	}
	if err := outtext.WriteHygieneReport(w, report); err != nil {
		return fmt.Errorf("rendering hygiene markdown: %w", err)
	}
	return nil
}

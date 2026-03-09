package hygiene

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	outtext "github.com/sufield/stave/internal/adapters/output/text"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	hygieneapp "github.com/sufield/stave/internal/app/hygiene"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

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
		return nil, fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s must be a directory", dir)
	}
	result, err := loader.LoadSnapshots(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("load archive observations: %w", err)
	}
	return result.Snapshots, nil
}

func filterSnapshotsBefore(snapshots []asset.Snapshot, cutoff time.Time) []asset.Snapshot {
	filtered := make([]asset.Snapshot, 0, len(snapshots))
	for _, snap := range snapshots {
		if !snap.CapturedAt.After(cutoff) {
			filtered = append(filtered, snap)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CapturedAt.Before(filtered[j].CapturedAt)
	})
	return filtered
}

func writeHygieneOutput(format ui.OutputFormat, report hygieneapp.ReportRequest, jsonOut hygieneapp.Output, w io.Writer) error {
	if format.IsJSON() {
		if err := jsonutil.WriteIndented(w, jsonOut); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		return nil
	}
	if err := outtext.WriteHygieneReport(w, report); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

package stave

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/adapters/observations"
	catalogdiff "github.com/sufield/stave/internal/app/catalogdiff"
	"github.com/sufield/stave/internal/app/snapshotdiff"
	"github.com/sufield/stave/internal/core/diff"
)

// DiffCatalogs compares two control-catalog directories and renders the
// delta — new/removed controls and severity changes — in the requested
// format ("json" or "table"/""). Loading either directory wraps
// [ErrInvalidInput]. It is the library entry point behind
// `stave diff --catalogs`.
func DiffCatalogs(ctx context.Context, beforeDir, afterDir, format string) ([]byte, error) {
	before, err := loadControlsFromDir(ctx, beforeDir)
	if err != nil {
		return nil, fmt.Errorf("load before catalog: %w: %w", err, ErrInvalidInput)
	}
	after, err := loadControlsFromDir(ctx, afterDir)
	if err != nil {
		return nil, fmt.Errorf("load after catalog: %w: %w", err, ErrInvalidInput)
	}

	delta := catalogdiff.Compute(before, after)

	var buf bytes.Buffer
	if format == "json" {
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(delta); err != nil {
			return nil, fmt.Errorf("render catalog diff: %w", err)
		}
	} else {
		if _, err := fmt.Fprint(&buf, catalogdiff.FormatTable(delta)); err != nil {
			return nil, fmt.Errorf("render catalog diff: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// DiffSnapshotBundles compares the latest snapshot in each of two
// observation bundle files (by bundle order) and renders the structured
// diff — per-property changes plus added/removed assets — in the
// requested format ("json" or "text"/""). A load failure or an empty
// bundle wraps [ErrInvalidInput]. It is the library entry point behind
// `stave diff` (snapshot mode).
func DiffSnapshotBundles(beforePath, afterPath, format string) ([]byte, error) {
	beforeSnaps, err := observations.LoadBundle(beforePath)
	if err != nil {
		return nil, fmt.Errorf("load before snapshot: %w: %w", err, ErrInvalidInput)
	}
	if len(beforeSnaps) == 0 {
		return nil, fmt.Errorf("before snapshot %s has no snapshots: %w", beforePath, ErrInvalidInput)
	}

	afterSnaps, err := observations.LoadBundle(afterPath)
	if err != nil {
		return nil, fmt.Errorf("load after snapshot: %w: %w", err, ErrInvalidInput)
	}
	if len(afterSnaps) == 0 {
		return nil, fmt.Errorf("after snapshot %s has no snapshots: %w", afterPath, ErrInvalidInput)
	}

	// Use the latest snapshot from each bundle.
	before := beforeSnaps[len(beforeSnaps)-1]
	after := afterSnaps[len(afterSnaps)-1]

	result := snapshotdiff.Diff(before, after)

	var buf bytes.Buffer
	if format == "json" {
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return nil, fmt.Errorf("render snapshot diff: %w", err)
		}
	} else {
		writeSnapshotDiffText(&buf, result)
	}
	return buf.Bytes(), nil
}

// writeSnapshotDiffText writes the human-readable snapshot diff summary.
func writeSnapshotDiffText(w io.Writer, r *snapshotdiff.DiffResult) {
	fmt.Fprintln(w, "SNAPSHOT DIFF")
	fmt.Fprintf(w, "Before: %s  (%d assets)\n",
		r.BeforeTime.Format("2006-01-02T15:04:05Z"), r.BeforeAssets)
	fmt.Fprintf(w, "After:  %s  (%d assets)\n\n",
		r.AfterTime.Format("2006-01-02T15:04:05Z"), r.AfterAssets)

	if len(r.PropertyChanges) > 0 {
		fmt.Fprintf(w, "PROPERTY CHANGES (%d)\n", len(r.PropertyChanges))
		fmt.Fprintln(w, strings.Repeat("─", 55))

		currentAsset := ""
		for i := range r.PropertyChanges {
			c := &r.PropertyChanges[i]
			if string(c.AssetID) != currentAsset {
				currentAsset = string(c.AssetID)
				fmt.Fprintf(w, "  %s\n", c.AssetID)
			}
			riskTag := ""
			switch c.RiskDirection {
			case diff.RiskIncreasing:
				riskTag = " [RISK+]"
			case diff.RiskDecreasing:
				riskTag = " [RISK-]"
			}
			fmt.Fprintf(w, "    %s:%s\n", c.Property, riskTag)
			fmt.Fprintf(w, "      before: %v\n", c.Before)
			fmt.Fprintf(w, "      after:  %v\n", c.After)
		}
		fmt.Fprintln(w)
	}

	if len(r.NewAssets) > 0 {
		fmt.Fprintf(w, "NEW ASSETS (%d)\n", len(r.NewAssets))
		for i := range r.NewAssets {
			a := &r.NewAssets[i]
			fmt.Fprintf(w, "  %s\n", a.AssetID)
			fmt.Fprintf(w, "    asset_type: %s\n", a.AssetType)
		}
		fmt.Fprintln(w)
	}

	if len(r.RemovedAssets) > 0 {
		fmt.Fprintf(w, "REMOVED ASSETS (%d)\n", len(r.RemovedAssets))
		for i := range r.RemovedAssets {
			a := &r.RemovedAssets[i]
			fmt.Fprintf(w, "  %s  (%s)\n", a.AssetID, a.AssetType)
		}
		fmt.Fprintln(w)
	}

	if len(r.PropertyChanges) == 0 && len(r.NewAssets) == 0 && len(r.RemovedAssets) == 0 {
		fmt.Fprintln(w, "No differences found.")
		return
	}

	// Risk summary.
	if r.RiskSummary.Increasing > 0 || r.RiskSummary.Decreasing > 0 {
		fmt.Fprintln(w, "RISK SUMMARY")
		fmt.Fprintln(w, strings.Repeat("─", 55))
		fmt.Fprintf(w, "  Risk-increasing changes: %d\n", r.RiskSummary.Increasing)
		fmt.Fprintf(w, "  Risk-decreasing changes: %d\n", r.RiskSummary.Decreasing)
		fmt.Fprintf(w, "  Neutral changes:         %d\n", r.RiskSummary.Neutral)
		fmt.Fprintln(w)
	}
}

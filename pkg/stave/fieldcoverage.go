package stave

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/app/fieldcov"
)

// AnalyzeFieldCoverage loads an observation snapshot bundle and the
// control catalog, classifies each control by whether the snapshot
// supplies every field its predicates read (EVALUABLE / INCOMPLETE /
// SILENT_RISK / NO_ASSETS), and renders the report as "table"/"" or
// "json". now stamps the report. It returns the rendered bytes and
// whether any control is SILENT_RISK (the caller maps that to exit 3 —
// the report is still rendered). A snapshot load failure or empty bundle
// wraps [ErrInvalidInput] (exit 2); a control-loader failure stays plain
// (exit 4). It is the library entry point behind `stave coverage`.
func AnalyzeFieldCoverage(ctx context.Context, snapshotPath, controlsDir, format string, now time.Time) ([]byte, bool, error) {
	snapshots, err := observations.LoadBundle(snapshotPath)
	if err != nil {
		return nil, false, fmt.Errorf("load snapshot: %w: %w", err, ErrInvalidInput)
	}
	if len(snapshots) == 0 {
		return nil, false, fmt.Errorf("no snapshots in %s: %w", snapshotPath, ErrInvalidInput)
	}

	controls, err := loadControlsFromDir(ctx, controlsDir)
	if err != nil {
		return nil, false, err
	}

	report := fieldcov.Analyze(fieldcov.AnalyzeInput{
		SnapshotPath: snapshotPath,
		GeneratedAt:  now.Format(time.RFC3339),
		Controls:     controls,
		Snapshots:    snapshots,
	})

	out, err := renderFieldCoverage(report, format)
	if err != nil {
		return nil, false, err
	}
	return out, report.Summary.SilentRisk > 0, nil
}

// renderFieldCoverage renders the coverage report as JSON or the
// human-readable table. Split out so it is unit-testable without I/O.
func renderFieldCoverage(report *fieldcov.Report, format string) ([]byte, error) {
	var buf bytes.Buffer
	if format == "json" {
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return nil, fmt.Errorf("encode json: %w", err)
		}
	} else {
		fieldcov.WriteTable(&buf, report)
	}
	return buf.Bytes(), nil
}

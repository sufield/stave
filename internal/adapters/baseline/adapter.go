// Package baseline provides adapters for loading and writing baseline
// artifacts used in CI drift detection.
package baseline

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/reporting"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// FileOpener opens a file for writing at the given path.
// The concrete implementation is injected from the cmd layer at construction.
type FileOpener func(path string) (*os.File, error)

// EvaluationLoader loads a persisted evaluation artifact.
type EvaluationLoader struct{}

// LoadFindings loads an evaluation artifact and extracts baseline-level findings.
//
// Constructed via NewLoader().WithStrictSchema() so the loader runs
// JSON-schema validation on the artifact before unmarshal — baseline
// drift detection is a trust-boundary read (a tampered or malformed
// envelope must fail loud, not produce a "clean" empty diff). The
// earlier shape used &evaljson.Loader{} which left strictSchema=false
// and silently accepted hand-crafted envelopes that could drive
// false-pass verdicts in CI gates.
func (l *EvaluationLoader) LoadFindings(ctx context.Context, path string) ([]reporting.BaselineFinding, error) {
	loader := evaljson.NewLoader().WithStrictSchema()
	eval, err := loader.LoadEnvelopeFromFile(ctx, fsutil.CleanUserPath(path))
	if err != nil {
		return nil, err
	}
	entries := remediation.BaselineEntriesFromFindings(eval.Findings)
	return entriesToDomain(entries), nil
}

// Loader loads a persisted baseline artifact.
type Loader struct{}

// LoadBaseline loads a saved baseline artifact.
//
// Strict-schema for the same reason as LoadFindings: the baseline is
// the reference state that drift detection compares against; silently
// accepting a malformed file lets a hand-crafted "empty baseline"
// pass every diff and report no drift even when assets violate.
func (l *Loader) LoadBaseline(ctx context.Context, path string) ([]reporting.BaselineFinding, error) {
	loader := evaljson.NewLoader().WithStrictSchema()
	base, err := loader.LoadBaselineFromFile(ctx, fsutil.CleanUserPath(path), kernel.KindBaseline)
	if err != nil {
		return nil, err
	}
	return entriesToDomain(base.Findings), nil
}

// Writer persists a baseline artifact to disk.
type Writer struct {
	openFile FileOpener
}

// NewWriter constructs a Writer. opener must be non-nil.
func NewWriter(opener FileOpener) (*Writer, error) {
	if opener == nil {
		return nil, errors.New("baseline.NewWriter: opener is nil")
	}
	return &Writer{openFile: opener}, nil
}

// WriteBaseline writes a baseline snapshot to disk atomically: the
// payload is staged to a temp file in the destination directory and
// renamed into place only after a successful Close. A bare
// `defer f.Close()` previously swallowed flush errors, so a torn
// write (e.g. ENOSPC at flush time) could leave the on-disk baseline
// partially written and silently desynchronized from what the
// caller believed it persisted. Atomic rename + close-error capture
// makes either the new or the previous baseline visible, never a
// half-written hybrid.
func (w *Writer) WriteBaseline(ctx context.Context, path string, findings []reporting.BaselineFinding, createdAt time.Time, sourcePath string) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := domainToEntries(findings)
	if err != nil {
		return fmt.Errorf("convert baseline findings: %w", err)
	}

	baseline := evaluation.Baseline{
		SchemaVersion:    kernel.SchemaBaseline,
		Kind:             kernel.KindBaseline,
		CreatedAt:        createdAt,
		SourceEvaluation: sourcePath,
		Findings:         entries,
	}

	cleanPath := fsutil.CleanUserPath(path)
	f, err := w.openFile(cleanPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	tmpPath := f.Name()
	// Track whether we still want the on-disk file when this function
	// exits — on any error we remove it to avoid leaving a partial.
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	// Re-check the context before the write phase: a long-running
	// caller (CI gate, signal-driven shutdown) may have cancelled
	// while the temp file was being created. The committed=false
	// defer cleans up the partial temp.
	if err := ctx.Err(); err != nil {
		_ = f.Close()
		return err
	}

	if writeErr := jsonutil.WriteIndented(f, baseline); writeErr != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, writeErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		return fmt.Errorf("close %s: %w", path, closeErr)
	}

	// Rename only when the temp path differs from the destination.
	// Callers that pass a FileOpener which already opens the final
	// path (legacy behavior, used by some tests) skip the rename
	// step — the close-error capture above is the meaningful fix
	// for that path.
	if tmpPath != cleanPath {
		if renameErr := os.Rename(tmpPath, cleanPath); renameErr != nil {
			return fmt.Errorf("rename %s -> %s: %w", tmpPath, cleanPath, renameErr)
		}
	}
	committed = true
	return nil
}

func entriesToDomain(entries []evaluation.BaselineEntry) []reporting.BaselineFinding {
	out := make([]reporting.BaselineFinding, len(entries))
	for i, e := range entries {
		out[i] = reporting.BaselineFinding{
			ControlID:   string(e.ControlID),
			ControlName: e.ControlName,
			AssetID:     string(e.AssetID),
			AssetType:   string(e.AssetType),
		}
	}
	return out
}

func domainToEntries(findings []reporting.BaselineFinding) ([]evaluation.BaselineEntry, error) {
	out := make([]evaluation.BaselineEntry, len(findings))
	for i, f := range findings {
		ctlID, err := kernel.NewControlID(f.ControlID)
		if err != nil {
			return nil, fmt.Errorf("invalid control ID at baseline entry %d: %w", i, err)
		}
		out[i] = evaluation.BaselineEntry{
			ControlID:   ctlID,
			ControlName: f.ControlName,
			AssetID:     asset.ID(f.AssetID),
			AssetType:   kernel.NewAssetType(f.AssetType),
		}
	}
	return out, nil
}

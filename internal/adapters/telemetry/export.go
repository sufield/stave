package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sufield/stave/internal/core/trace"
)

// WriteTraceFile writes a LogicTrace to a JSON file at the given path.
// Uses atomic write (temp file + rename) to prevent partial output.
// Air-gap safe — no network calls.
func WriteTraceFile(lt *trace.LogicTrace, path string) error {
	data, err := json.MarshalIndent(lt, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal logic trace: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".audit_trace_*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file for trace: %w", err)
	}
	tmpName := tmp.Name()

	if _, writeErr := tmp.Write(data); writeErr != nil {
		_ = tmp.Close()        //nolint:gosec // best-effort cleanup after write failure
		_ = os.Remove(tmpName) //nolint:gosec // best-effort cleanup
		return fmt.Errorf("write trace data: %w", writeErr)
	}
	// Sync before Close: matches fsutil.WriteFileAtomic. A close
	// without a prior fsync can return success while the data sits
	// in the page cache, so a crash after Close-then-Rename can
	// produce a present-but-zero-byte trace file.
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()        //nolint:gosec // best-effort cleanup after sync failure
		_ = os.Remove(tmpName) //nolint:gosec // best-effort cleanup
		return fmt.Errorf("sync trace temp file: %w", syncErr)
	}
	if closeErr := tmp.Close(); closeErr != nil {
		_ = os.Remove(tmpName) //nolint:gosec // best-effort cleanup after close failure
		return fmt.Errorf("close trace temp file: %w", closeErr)
	}
	if renameErr := os.Rename(tmpName, path); renameErr != nil {
		_ = os.Remove(tmpName) //nolint:gosec // best-effort cleanup after rename failure
		return fmt.Errorf("rename trace file: %w", renameErr)
	}
	return nil
}

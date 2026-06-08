package stave

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	infradoctor "github.com/sufield/stave/internal/adapters/doctor"
	"github.com/sufield/stave/internal/core/setup"
)

// RunDoctor checks local environment readiness for Stave workflows —
// required tools, file permissions, project structure — relative to cwd
// and the running binary at binaryPath, and renders the report as "json"
// or "text"/"". It returns the rendered bytes and whether every required
// check passed (the caller maps a failure to exit 3 — the report is still
// rendered). All failures stay plain (exit 4). It is the library entry
// point behind `stave doctor`.
func RunDoctor(ctx context.Context, cwd, binaryPath, format string) ([]byte, bool, error) {
	resp, err := setup.Doctor(ctx, setup.DoctorRequest{
		Cwd:        cwd,
		BinaryPath: binaryPath,
		Format:     format,
	}, setup.DoctorDeps{
		Runner: &infradoctor.CheckRunner{},
	})
	if err != nil {
		return nil, false, fmt.Errorf("run doctor checks: %w", err)
	}

	out, err := renderDoctor(resp, format)
	if err != nil {
		return nil, false, err
	}
	return out, resp.AllPassed, nil
}

// renderDoctor renders the doctor report as JSON or human-readable text.
// Split out so it is unit-testable without running the checks.
func renderDoctor(resp setup.DoctorResponse, format string) ([]byte, error) {
	var buf bytes.Buffer
	switch format {
	case "json":
		payload := struct {
			Ready  bool                `json:"ready"`
			Checks []setup.DoctorCheck `json:"checks"`
		}{
			Ready:  resp.AllPassed,
			Checks: resp.Checks,
		}
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			return nil, fmt.Errorf("encode doctor report JSON: %w", err)
		}
	case "text", "":
		for _, c := range resp.Checks {
			if _, err := fmt.Fprintf(&buf, "[%s] %s: %s\n", c.Status, c.Name, c.Message); err != nil {
				return nil, fmt.Errorf("write doctor check status: %w", err)
			}
			if c.Fix != "" {
				if _, err := fmt.Fprintf(&buf, "      Fix: %s\n", c.Fix); err != nil {
					return nil, fmt.Errorf("write doctor check fix: %w", err)
				}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
	}
	return buf.Bytes(), nil
}

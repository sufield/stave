// Package driftdiff computes the drift between the latest two observation
// snapshots in a directory and renders it as text or JSON. It is the engine
// behind pkg/stave.DiffObservationDrift and the `stave snapshot diff`
// command; the command keeps only flag wiring, the progress span, and the
// quiet/output handling.
package driftdiff

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/sanitize"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// InputError marks a user-input failure (invalid change-type filter, unknown
// output format). The pkg/stave facade unwraps it and re-wraps the message
// with stave.ErrInvalidInput so the CLI exits 2; loading/compute failures
// stay plain (exit 4).
type InputError struct{ Err error }

// Error implements error.
func (e *InputError) Error() string { return e.Err.Error() }

// Unwrap exposes the wrapped cause.
func (e *InputError) Unwrap() error { return e.Err }

// Config parameterizes [Run]. It mirrors the `stave snapshot diff` flags
// plus the global --sanitize / --path-mode settings.
type Config struct {
	ObservationsDir string
	Format          string // text | json
	ChangeTypes     []string
	AssetTypes      []string
	AssetID         string
	SanitizeIDs     bool   // global --sanitize
	PathMode        string // global --path-mode ("" base, "full")
}

// ChangeTypeNames returns the valid --change-type filter values, for shell
// completion.
func ChangeTypeNames() []string { return asset.AllDriftTypes() }

// Run loads the latest two snapshots in cfg.ObservationsDir, computes the
// asset-level drift, applies the requested filter, sanitizes identifiers,
// and renders the delta in the requested format.
func Run(ctx context.Context, cfg Config) ([]byte, error) {
	switch cfg.Format {
	case "text", "json":
	default:
		return nil, &InputError{fmt.Errorf("unsupported format %q (expected: text | json)", cfg.Format)}
	}

	filter, err := buildFilter(cfg.ChangeTypes, cfg.AssetTypes, cfg.AssetID)
	if err != nil {
		return nil, err
	}

	delta, err := computeDelta(ctx, cfg.ObservationsDir, filter)
	if err != nil {
		return nil, err
	}

	sanitizer := sanitize.Policy{SanitizeIDs: cfg.SanitizeIDs, PathMode: sanitize.PathMode(cfg.PathMode)}.NewSanitizer()
	delta = output.SanitizeObservationDelta(sanitizer, delta)

	return render(cfg.Format, delta)
}

func computeDelta(ctx context.Context, dir string, filter asset.FilterOptions) (asset.InfrastructureDrift, error) {
	res, err := observations.NewObservationLoader().LoadSnapshots(ctx, dir)
	if err != nil {
		return asset.InfrastructureDrift{}, fmt.Errorf("loading snapshots: %w", err)
	}
	snapshots := res.Snapshots
	if len(snapshots) < 2 {
		return asset.InfrastructureDrift{}, fmt.Errorf("need at least 2 snapshots in %s for diff", dir)
	}

	prev, curr, err := asset.GetStateTransition(snapshots)
	if err != nil {
		return asset.InfrastructureDrift{}, fmt.Errorf("select latest snapshots: %w", err)
	}
	drift, err := asset.ComputeDrift(prev, curr)
	if err != nil {
		return asset.InfrastructureDrift{}, fmt.Errorf("compute drift: %w", err)
	}
	return drift.ApplyFilter(filter), nil
}

// buildFilter parses the raw flag values into an asset.FilterOptions. An
// invalid change-type wraps [InputError] (exit 2).
func buildFilter(changeTypes, assetTypes []string, assetID string) (asset.FilterOptions, error) {
	parsed, err := parseChangeTypes(changeTypes)
	if err != nil {
		return asset.FilterOptions{}, err
	}
	return asset.FilterOptions{
		ChangeTypes: parsed,
		AssetTypes:  toAssetTypes(assetTypes),
		AssetID:     strings.TrimSpace(assetID),
	}, nil
}

// parseChangeTypes validates and converts raw strings to asset.DriftType
// values. Empty entries are dropped; an unrecognised value is an input error.
func parseChangeTypes(raw []string) ([]asset.DriftType, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]asset.DriftType, 0, len(raw))
	for _, s := range raw {
		val := strings.ToUpper(strings.TrimSpace(s))
		if val == "" {
			continue
		}
		ct := asset.DriftType(val)
		if !ct.IsValid() {
			return nil, &InputError{fmt.Errorf("invalid --change-type %q (supported: PROVISIONED, DECOMMISSIONED, RECONFIGURED)", s)}
		}
		out = append(out, ct)
	}
	return out, nil
}

// toAssetTypes converts raw strings to kernel.AssetType, dropping empties.
func toAssetTypes(raw []string) []kernel.AssetType {
	if len(raw) == 0 {
		return nil
	}
	out := make([]kernel.AssetType, 0, len(raw))
	for _, s := range raw {
		val := kernel.NewAssetType(s)
		if val != "" {
			out = append(out, val)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// render dispatches the delta to the format-specific renderer and returns
// the rendered bytes.
func render(format string, delta asset.InfrastructureDrift) ([]byte, error) {
	var buf strings.Builder
	switch format {
	case "json":
		if err := jsonutil.WriteIndented(&buf, delta); err != nil {
			return nil, fmt.Errorf("render diff output: %w", err)
		}
	case "text":
		if err := renderText(&buf, delta); err != nil {
			return nil, fmt.Errorf("render diff output: %w", err)
		}
	}
	return []byte(buf.String()), nil
}

// renderText generates a human-readable summary of asset changes.
//
// NOTE: when there are no changes it returns without flushing the bufio
// writer, so the buffered header is not emitted. This is preserved verbatim
// from the original command (locked by TestRenderText_EmptyChanges) to keep
// output byte-identical across the facade migration.
func renderText(w io.Writer, out asset.InfrastructureDrift) error {
	bw := bufio.NewWriter(w)

	var firstErr error
	printf := func(format string, args ...any) {
		if firstErr != nil {
			return
		}
		_, firstErr = fmt.Fprintf(bw, format, args...)
	}

	printf("Observation delta: %s -> %s\n",
		out.StartTime.Format(time.RFC3339),
		out.EndTime.Format(time.RFC3339))
	printf("Summary: added=%d removed=%d modified=%d total=%d\n\n",
		out.Summary.Provisioned(), out.Summary.Decommissioned(), out.Summary.Reconfigured(), out.Summary.Total())
	if firstErr != nil {
		return firstErr
	}

	if len(out.Changes) == 0 {
		printf("No asset changes detected.\n")
		return firstErr
	}

	for _, c := range out.Changes {
		if firstErr != nil {
			break
		}
		printf("- %s [%s]\n", c.AssetID, c.Action)
		for _, p := range c.Drifts {
			printf("  * %s: %v -> %v\n", p.Attribute, p.OldValue, p.NewValue)
		}
	}
	if err := bw.Flush(); err != nil && firstErr == nil {
		return err
	}
	return firstErr
}

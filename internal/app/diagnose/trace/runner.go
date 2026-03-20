package trace

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

// Config defines the parameters for tracing a predicate evaluation.
type Config struct {
	// Pre-loaded data.
	Control  policy.ControlDefinition
	Snapshot *asset.Snapshot

	// Parameters.
	AssetID         string
	ObservationPath string // used in error messages
	Format          ui.OutputFormat
	Quiet           bool
	Stdout          io.Writer
}

// Runner orchestrates evaluation trace generation for a specific asset.
type Runner struct{}

// NewRunner creates a new trace runner.
func NewRunner() *Runner {
	return &Runner{}
}

// Run executes the trace workflow.
func (r *Runner) Run(_ context.Context, cfg Config) error {
	if cfg.Quiet {
		return nil
	}

	found, err := FindAsset(cfg.Snapshot, asset.ID(cfg.AssetID), cfg.ObservationPath)
	if err != nil {
		return err
	}

	result := stavecel.BuildTrace(&cfg.Control, found, cfg.Snapshot)
	if result == nil {
		return fmt.Errorf("trace: no result produced")
	}

	if cfg.Format.IsJSON() {
		return result.RenderJSON(cfg.Stdout)
	}
	return result.RenderText(cfg.Stdout)
}

// FindAsset locates an asset by ID in a snapshot.
// The path parameter is used only in error messages.
func FindAsset(snapshot *asset.Snapshot, assetID asset.ID, path string) (*asset.Asset, error) {
	for i := range snapshot.Assets {
		if snapshot.Assets[i].ID == assetID {
			return &snapshot.Assets[i], nil
		}
	}
	available := make([]string, 0, len(snapshot.Assets))
	for _, a := range snapshot.Assets {
		available = append(available, a.ID.String())
	}
	slices.Sort(available)
	return nil, fmt.Errorf("asset %q not found in %s\nAvailable assets: %s",
		assetID, path, strings.Join(available, ", "))
}

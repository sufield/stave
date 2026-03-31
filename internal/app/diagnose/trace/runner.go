package trace

import (
	"fmt"
	"slices"
	"strings"

	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// Config defines the parameters for tracing a predicate evaluation.
type Config struct {
	// Pre-loaded data.
	Control  policy.ControlDefinition
	Snapshot *asset.Snapshot

	// Parameters.
	AssetID         string
	ObservationPath string // used in error messages
}

// Runner orchestrates evaluation trace generation for a specific asset.
type Runner struct{}

// Run executes the trace workflow and returns the result for rendering by the caller.
func (r *Runner) Run(cfg Config) (*stavecel.TraceResult, error) {
	found, err := FindAsset(cfg.Snapshot, asset.ID(cfg.AssetID), cfg.ObservationPath)
	if err != nil {
		return nil, err
	}

	result := stavecel.BuildTrace(&cfg.Control, found, cfg.Snapshot)
	if result == nil {
		return nil, fmt.Errorf("trace: no result produced")
	}
	return result, nil
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

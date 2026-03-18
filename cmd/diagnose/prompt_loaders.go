package diagnose

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

func (r *PromptRunner) loadControlsMap(ctx context.Context, dir string) (map[kernel.ControlID]*policy.ControlDefinition, error) {
	repo, err := r.Provider.NewControlRepo()
	if err != nil {
		return nil, err
	}
	controls, err := repo.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("loading controls: %w", err)
	}

	ctlByID := make(map[kernel.ControlID]*policy.ControlDefinition, len(controls))
	for i := range controls {
		ctlByID[controls[i].ID] = &controls[i]
	}
	return ctlByID, nil
}

func (r *PromptRunner) loadAssetProperties(ctx context.Context, dir string, assetID asset.ID) (string, error) {
	snapshots, err := r.Provider.LoadSnapshots(ctx, dir)
	if err != nil {
		return "", err
	}
	if len(snapshots) == 0 {
		return "", nil
	}

	latest := asset.LatestSnapshot(snapshots)
	for _, a := range latest.Assets {
		if a.ID == assetID {
			propsJSON, marshalErr := json.MarshalIndent(a.Properties, "", "  ")
			if marshalErr != nil {
				return "", fmt.Errorf("marshal asset properties: %w", marshalErr)
			}
			return string(propsJSON), nil
		}
	}
	return "", nil
}

package compose

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/evaluation"
)

// LoadSLAPolicy resolves an SLAProvider from the factory and loads the
// configured policy. Both inputs empty returns (nil, nil) — the absence of
// SLA configuration is a valid state.
//
// The file path takes precedence over the profile name when both are set.
// This rule is enforced inside the SLAProvider so cmd/apply, cmd/report, and
// any future caller share a single resolution path.
func LoadSLAPolicy(ctx context.Context, newLoader SLALoaderFactory, profileID, filePath string) (*evaluation.SLAConfig, error) {
	loader, err := newLoader()
	if err != nil {
		return nil, fmt.Errorf("create sla loader: %w", err)
	}
	cfg, loadErr := loader.LoadSLAConfig(ctx, profileID, filePath)
	if loadErr != nil {
		return nil, fmt.Errorf("load sla config: %w", loadErr)
	}
	return cfg, nil
}

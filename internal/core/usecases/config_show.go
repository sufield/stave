package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// ConfigResolverPort resolves effective project configuration.
type ConfigResolverPort interface {
	ResolveEffectiveConfig(ctx context.Context) (any, error)
}

// ConfigShowDeps groups the port interfaces for the config show use case.
type ConfigShowDeps struct {
	Resolver ConfigResolverPort
}

// ConfigShow resolves and returns the effective project configuration.
func ConfigShow(
	ctx context.Context,
	req domain.ConfigShowRequest,
	deps ConfigShowDeps,
) (domain.ConfigShowResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.ConfigShowResponse{}, fmt.Errorf("config_show: %w", err)
	}

	data, err := deps.Resolver.ResolveEffectiveConfig(ctx)
	if err != nil {
		return domain.ConfigShowResponse{}, fmt.Errorf("config_show: %w", err)
	}

	return domain.ConfigShowResponse{ConfigData: data}, nil
}

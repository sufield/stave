package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// AliasRegistryPort lists predicate aliases from the built-in registry.
type AliasRegistryPort interface {
	ListAliases(ctx context.Context, category string) (domain.InspectAliasesResponse, error)
}

// InspectAliasesDeps groups the port interfaces for the inspect-aliases use case.
type InspectAliasesDeps struct {
	Registry AliasRegistryPort
}

// InspectAliases lists registered predicate aliases with metadata.
func InspectAliases(
	ctx context.Context,
	req domain.InspectAliasesRequest,
	deps InspectAliasesDeps,
) (domain.InspectAliasesResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.InspectAliasesResponse{}, fmt.Errorf("inspect-aliases: %w", err)
	}

	resp, err := deps.Registry.ListAliases(ctx, req.Category)
	if err != nil {
		return domain.InspectAliasesResponse{}, fmt.Errorf("inspect-aliases: %w", err)
	}

	return resp, nil
}

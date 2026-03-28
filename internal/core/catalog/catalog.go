package catalog

import (
	"context"
	"fmt"
)

// PackRegistryPort provides access to built-in control packs.
type PackRegistryPort interface {
	ListPacks(ctx context.Context) ([]PackEntry, error)
	ShowPack(ctx context.Context, name string) (PacksShowResponse, error)
}

type PacksDeps struct {
	Registry PackRegistryPort
}

// PacksList lists all built-in control packs.
func PacksList(ctx context.Context, req PacksListRequest, deps PacksDeps) (PacksListResponse, error) {
	if err := ctx.Err(); err != nil {
		return PacksListResponse{}, fmt.Errorf("packs-list: %w", err)
	}
	_ = req
	packs, err := deps.Registry.ListPacks(ctx)
	if err != nil {
		return PacksListResponse{}, fmt.Errorf("packs-list: %w", err)
	}
	return PacksListResponse{Packs: packs}, nil
}

// PacksShow shows details of a single built-in control pack.
func PacksShow(ctx context.Context, req PacksShowRequest, deps PacksDeps) (PacksShowResponse, error) {
	if err := ctx.Err(); err != nil {
		return PacksShowResponse{}, fmt.Errorf("packs-show: %w", err)
	}
	if req.Name == "" {
		return PacksShowResponse{}, fmt.Errorf("packs-show: pack name is required")
	}
	resp, err := deps.Registry.ShowPack(ctx, req.Name)
	if err != nil {
		return PacksShowResponse{}, fmt.Errorf("packs-show: %w", err)
	}
	return resp, nil
}

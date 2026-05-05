package setup

import (
	"context"
	"fmt"
)

// EnvListerPort lists supported environment variables.
type EnvListerPort interface {
	ListEnvVars(ctx context.Context) (EnvListResponse, error)
}

// EnvListDeps groups the port interfaces for the env-list use case.
type EnvListDeps struct {
	Lister EnvListerPort
}

// EnvList retrieves all supported STAVE_* environment variables.
func EnvList(ctx context.Context, req EnvListRequest, deps EnvListDeps) (EnvListResponse, error) {
	if err := ctx.Err(); err != nil {
		return EnvListResponse{}, fmt.Errorf("env-list: %w", err)
	}

	// req carries no filter or selector — EnvList returns the full
	// catalogue. The parameter exists for shape symmetry with the
	// rest of the use-case API (every Use Case takes a typed
	// request) so a future filter can be added without breaking the
	// call site.
	_ = req

	resp, err := deps.Lister.ListEnvVars(ctx)
	if err != nil {
		return EnvListResponse{}, fmt.Errorf("env-list: %w", err)
	}

	return resp, nil
}

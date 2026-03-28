package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// ControlsListerPort lists controls from a directory or built-in catalog.
type ControlsListerPort interface {
	ListControls(ctx context.Context, controlsDir string, builtIn bool, filter []string) ([]domain.ControlRow, error)
}

// ControlsListDeps groups the port interfaces for the controls list use case.
type ControlsListDeps struct {
	Lister ControlsListerPort
}

// ControlsList loads and returns a listing of controls.
func ControlsList(
	ctx context.Context,
	req domain.ControlsListRequest,
	deps ControlsListDeps,
) (domain.ControlsListResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.ControlsListResponse{}, fmt.Errorf("controls_list: %w", err)
	}

	rows, err := deps.Lister.ListControls(ctx, req.ControlsDir, req.BuiltIn, req.Filter)
	if err != nil {
		return domain.ControlsListResponse{}, fmt.Errorf("controls_list: %w", err)
	}

	return domain.ControlsListResponse{Controls: rows}, nil
}

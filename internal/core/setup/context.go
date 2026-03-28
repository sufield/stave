package setup

import (
	"context"
	"fmt"
)

// ContextStorePort manages named project contexts in user configuration.
type ContextStorePort interface {
	CreateContext(ctx context.Context, req ContextCreateRequest) error
	ListContexts(ctx context.Context) ([]ContextEntry, error)
	UseContext(ctx context.Context, name string) error
	ShowContext(ctx context.Context) (ContextShowResponse, error)
	DeleteContext(ctx context.Context, name string) error
}

// ContextDeps groups the port interfaces for the context use cases.
type ContextDeps struct {
	Store ContextStorePort
}

// ContextCreate creates or updates a named project context.
func ContextCreate(ctx context.Context, req ContextCreateRequest, deps ContextDeps) (ContextCreateResponse, error) {
	if err := ctx.Err(); err != nil {
		return ContextCreateResponse{}, fmt.Errorf("context-create: %w", err)
	}

	if req.Name == "" {
		return ContextCreateResponse{}, fmt.Errorf("context-create: name is required")
	}

	if err := deps.Store.CreateContext(ctx, req); err != nil {
		return ContextCreateResponse{}, fmt.Errorf("context-create: %w", err)
	}

	return ContextCreateResponse{Name: req.Name}, nil
}

// ContextList retrieves all named contexts.
func ContextList(ctx context.Context, req ContextListRequest, deps ContextDeps) (ContextListResponse, error) {
	if err := ctx.Err(); err != nil {
		return ContextListResponse{}, fmt.Errorf("context-list: %w", err)
	}

	_ = req

	entries, err := deps.Store.ListContexts(ctx)
	if err != nil {
		return ContextListResponse{}, fmt.Errorf("context-list: %w", err)
	}

	return ContextListResponse{Entries: entries}, nil
}

// ContextUse activates a named context.
func ContextUse(ctx context.Context, req ContextUseRequest, deps ContextDeps) (ContextUseResponse, error) {
	if err := ctx.Err(); err != nil {
		return ContextUseResponse{}, fmt.Errorf("context-use: %w", err)
	}

	if req.Name == "" {
		return ContextUseResponse{}, fmt.Errorf("context-use: name is required")
	}

	if err := deps.Store.UseContext(ctx, req.Name); err != nil {
		return ContextUseResponse{}, fmt.Errorf("context-use: %w", err)
	}

	return ContextUseResponse(req), nil
}

// ContextShow displays the currently active context.
func ContextShow(ctx context.Context, req ContextShowRequest, deps ContextDeps) (ContextShowResponse, error) {
	if err := ctx.Err(); err != nil {
		return ContextShowResponse{}, fmt.Errorf("context-show: %w", err)
	}

	_ = req

	resp, err := deps.Store.ShowContext(ctx)
	if err != nil {
		return ContextShowResponse{}, fmt.Errorf("context-show: %w", err)
	}

	return resp, nil
}

// ContextDelete removes a named context.
func ContextDelete(ctx context.Context, req ContextDeleteRequest, deps ContextDeps) (ContextDeleteResponse, error) {
	if err := ctx.Err(); err != nil {
		return ContextDeleteResponse{}, fmt.Errorf("context-delete: %w", err)
	}

	if req.Name == "" {
		return ContextDeleteResponse{}, fmt.Errorf("context-delete: name is required")
	}

	if err := deps.Store.DeleteContext(ctx, req.Name); err != nil {
		return ContextDeleteResponse{}, fmt.Errorf("context-delete: %w", err)
	}

	return ContextDeleteResponse(req), nil
}

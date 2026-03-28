package setup

import (
	"context"
	"fmt"
	"regexp"
)

var aliasNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// AliasStorePort manages command aliases in user configuration.
type AliasStorePort interface {
	SetAlias(ctx context.Context, name, command string) error
	ListAliases(ctx context.Context) ([]AliasEntry, error)
	DeleteAlias(ctx context.Context, name string) error
}

// AliasDeps groups the port interfaces for the alias use cases.
type AliasDeps struct {
	Store AliasStorePort
}

// AliasSet creates or updates a command alias.
func AliasSet(ctx context.Context, req AliasSetRequest, deps AliasDeps) (AliasSetResponse, error) {
	if err := ctx.Err(); err != nil {
		return AliasSetResponse{}, fmt.Errorf("alias-set: %w", err)
	}

	if !aliasNamePattern.MatchString(req.Name) {
		return AliasSetResponse{}, fmt.Errorf("alias-set: invalid name %q: must match [a-zA-Z0-9_-]+", req.Name)
	}
	if req.Command == "" {
		return AliasSetResponse{}, fmt.Errorf("alias-set: command cannot be empty")
	}

	if err := deps.Store.SetAlias(ctx, req.Name, req.Command); err != nil {
		return AliasSetResponse{}, fmt.Errorf("alias-set: %w", err)
	}

	return AliasSetResponse(req), nil
}

// AliasList retrieves all defined aliases.
func AliasList(ctx context.Context, req AliasListRequest, deps AliasDeps) (AliasListResponse, error) {
	if err := ctx.Err(); err != nil {
		return AliasListResponse{}, fmt.Errorf("alias-list: %w", err)
	}

	_ = req

	entries, err := deps.Store.ListAliases(ctx)
	if err != nil {
		return AliasListResponse{}, fmt.Errorf("alias-list: %w", err)
	}

	return AliasListResponse{Entries: entries}, nil
}

// AliasDelete removes an existing alias.
func AliasDelete(ctx context.Context, req AliasDeleteRequest, deps AliasDeps) (AliasDeleteResponse, error) {
	if err := ctx.Err(); err != nil {
		return AliasDeleteResponse{}, fmt.Errorf("alias-delete: %w", err)
	}

	if req.Name == "" {
		return AliasDeleteResponse{}, fmt.Errorf("alias-delete: alias name is required")
	}

	if err := deps.Store.DeleteAlias(ctx, req.Name); err != nil {
		return AliasDeleteResponse{}, fmt.Errorf("alias-delete: %w", err)
	}

	return AliasDeleteResponse(req), nil
}

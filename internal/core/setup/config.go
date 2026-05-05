package setup

import (
	"context"
	"errors"
	"fmt"
)

// ConfigResolverPort resolves effective project configuration.
type ConfigResolverPort interface {
	ResolveEffectiveConfig(ctx context.Context) (any, error)
}

// ConfigReaderPort reads a config value by key.
type ConfigReaderPort interface {
	GetConfig(ctx context.Context, key string) (ConfigGetResponse, error)
}

// ConfigWriterPort writes and deletes config values.
type ConfigWriterPort interface {
	SetConfig(ctx context.Context, key, value string) error
	DeleteConfig(ctx context.Context, key string) error
}

// ConfigShowDeps groups the port interfaces for the config show use case.
type ConfigShowDeps struct {
	Resolver ConfigResolverPort
}

// ConfigShow resolves and returns the effective project configuration.
func ConfigShow(ctx context.Context, req ConfigShowRequest, deps ConfigShowDeps) (ConfigShowResponse, error) {
	if err := ctx.Err(); err != nil {
		return ConfigShowResponse{}, fmt.Errorf("config_show: %w", err)
	}

	// req carries no key or scope filter — ConfigShow returns the
	// resolver's full effective view. The parameter is kept for
	// API-shape symmetry with the rest of the use-case package.
	_ = req

	data, err := deps.Resolver.ResolveEffectiveConfig(ctx)
	if err != nil {
		return ConfigShowResponse{}, fmt.Errorf("config_show: %w", err)
	}

	return ConfigShowResponse{ConfigData: data}, nil
}

// ConfigGetDeps groups the port interfaces for the config-get use case.
type ConfigGetDeps struct {
	Reader ConfigReaderPort
}

// ConfigGet retrieves a project config value.
func ConfigGet(ctx context.Context, req ConfigGetRequest, deps ConfigGetDeps) (ConfigGetResponse, error) {
	if err := ctx.Err(); err != nil {
		return ConfigGetResponse{}, fmt.Errorf("config-get: %w", err)
	}

	if req.Key == "" {
		return ConfigGetResponse{}, errors.New("config-get: key is required")
	}

	resp, err := deps.Reader.GetConfig(ctx, req.Key)
	if err != nil {
		return ConfigGetResponse{}, fmt.Errorf("config-get: %w", err)
	}

	return resp, nil
}

// ConfigSetDeps groups the port interfaces for the config-set use case.
type ConfigSetDeps struct {
	Writer ConfigWriterPort
}

// ConfigSet updates a project config value.
func ConfigSet(ctx context.Context, req ConfigSetRequest, deps ConfigSetDeps) (ConfigSetResponse, error) {
	if err := ctx.Err(); err != nil {
		return ConfigSetResponse{}, fmt.Errorf("config-set: %w", err)
	}

	if req.Key == "" {
		return ConfigSetResponse{}, errors.New("config-set: key is required")
	}
	if req.Value == "" {
		return ConfigSetResponse{}, errors.New("config-set: value is required")
	}

	if err := deps.Writer.SetConfig(ctx, req.Key, req.Value); err != nil {
		return ConfigSetResponse{}, fmt.Errorf("config-set: %w", err)
	}

	return ConfigSetResponse(req), nil
}

// ConfigDeleteDeps groups the port interfaces for the config-delete use case.
type ConfigDeleteDeps struct {
	Writer ConfigWriterPort
}

// ConfigDelete removes a project config key, reverting to the default.
func ConfigDelete(ctx context.Context, req ConfigDeleteRequest, deps ConfigDeleteDeps) (ConfigDeleteResponse, error) {
	if err := ctx.Err(); err != nil {
		return ConfigDeleteResponse{}, fmt.Errorf("config-delete: %w", err)
	}

	if req.Key == "" {
		return ConfigDeleteResponse{}, errors.New("config-delete: key is required")
	}

	if err := deps.Writer.DeleteConfig(ctx, req.Key); err != nil {
		return ConfigDeleteResponse{}, fmt.Errorf("config-delete: %w", err)
	}

	return ConfigDeleteResponse(req), nil
}

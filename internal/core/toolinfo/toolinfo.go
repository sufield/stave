package toolinfo

import (
	"context"
	"fmt"
)

// VersionProviderPort retrieves version and build metadata.
type VersionProviderPort interface {
	GetVersion(ctx context.Context, verbose bool) (VersionResponse, error)
}

type VersionDeps struct{ Provider VersionProviderPort }

func Version(ctx context.Context, req VersionRequest, deps VersionDeps) (VersionResponse, error) {
	if err := ctx.Err(); err != nil {
		return VersionResponse{}, fmt.Errorf("version: %w", err)
	}
	resp, err := deps.Provider.GetVersion(ctx, req.Verbose)
	if err != nil {
		return VersionResponse{}, fmt.Errorf("version: %w", err)
	}
	return resp, nil
}

// CapabilitiesProviderPort retrieves runtime capabilities.
type CapabilitiesProviderPort interface {
	GetCapabilities(ctx context.Context) (CapabilitiesResponse, error)
}

type CapabilitiesDeps struct{ Provider CapabilitiesProviderPort }

func Capabilities(ctx context.Context, req CapabilitiesRequest, deps CapabilitiesDeps) (CapabilitiesResponse, error) {
	if err := ctx.Err(); err != nil {
		return CapabilitiesResponse{}, fmt.Errorf("capabilities: %w", err)
	}
	_ = req
	resp, err := deps.Provider.GetCapabilities(ctx)
	if err != nil {
		return CapabilitiesResponse{}, fmt.Errorf("capabilities: %w", err)
	}
	return resp, nil
}

// SchemasProviderPort lists all contract schemas.
type SchemasProviderPort interface {
	GetSchemas(ctx context.Context) (SchemasResponse, error)
}

type SchemasDeps struct{ Provider SchemasProviderPort }

func Schemas(ctx context.Context, req SchemasRequest, deps SchemasDeps) (SchemasResponse, error) {
	if err := ctx.Err(); err != nil {
		return SchemasResponse{}, fmt.Errorf("schemas: %w", err)
	}
	_ = req
	resp, err := deps.Provider.GetSchemas(ctx)
	if err != nil {
		return SchemasResponse{}, fmt.Errorf("schemas: %w", err)
	}
	return resp, nil
}

// BundleGeneratorPort generates a sanitized diagnostic bundle.
type BundleGeneratorPort interface {
	GenerateBundle(ctx context.Context, req BugReportRequest) (BugReportResponse, error)
}

type BugReportDeps struct{ Generator BundleGeneratorPort }

func BugReport(ctx context.Context, req BugReportRequest, deps BugReportDeps) (BugReportResponse, error) {
	if err := ctx.Err(); err != nil {
		return BugReportResponse{}, fmt.Errorf("bug-report: %w", err)
	}
	if req.TailLines < 0 {
		return BugReportResponse{}, fmt.Errorf("bug-report: invalid tail-lines %d: must be >= 0", req.TailLines)
	}
	resp, err := deps.Generator.GenerateBundle(ctx, req)
	if err != nil {
		return BugReportResponse{}, fmt.Errorf("bug-report: %w", err)
	}
	return resp, nil
}

// BundleInspectorPort inspects a diagnostic bundle zip.
type BundleInspectorPort interface {
	InspectBundle(ctx context.Context, bundlePath string) (BugReportInspectResponse, error)
}

type BugReportInspectDeps struct{ Inspector BundleInspectorPort }

func BugReportInspect(ctx context.Context, req BugReportInspectRequest, deps BugReportInspectDeps) (BugReportInspectResponse, error) {
	if err := ctx.Err(); err != nil {
		return BugReportInspectResponse{}, fmt.Errorf("bug-report-inspect: %w", err)
	}
	if req.BundlePath == "" {
		return BugReportInspectResponse{}, fmt.Errorf("bug-report-inspect: bundle path is required")
	}
	resp, err := deps.Inspector.InspectBundle(ctx, req.BundlePath)
	if err != nil {
		return BugReportInspectResponse{}, fmt.Errorf("bug-report-inspect: %w", err)
	}
	return resp, nil
}

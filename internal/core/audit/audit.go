package audit

import (
	"context"
	"fmt"
)

// --- Security Audit ---

// SecurityAuditRunnerPort runs a full security posture audit.
type SecurityAuditRunnerPort interface {
	RunAudit(ctx context.Context, req SecurityAuditRequest) (SecurityAuditResponse, error)
}

type SecurityAuditDeps struct {
	Runner SecurityAuditRunnerPort
}

func SecurityAudit(ctx context.Context, req SecurityAuditRequest, deps SecurityAuditDeps) (SecurityAuditResponse, error) {
	if err := ctx.Err(); err != nil {
		return SecurityAuditResponse{}, fmt.Errorf("security-audit: %w", err)
	}
	resp, err := deps.Runner.RunAudit(ctx, req)
	if err != nil {
		return SecurityAuditResponse{}, fmt.Errorf("security-audit: %w", err)
	}
	return resp, nil
}

// --- Controls List ---

// ControlsListerPort lists controls from a directory or built-in registry.
type ControlsListerPort interface {
	ListControls(ctx context.Context, controlsDir string, builtIn bool, filter []string) ([]ControlRow, error)
}

type ControlsListDeps struct {
	Lister ControlsListerPort
}

func ControlsList(ctx context.Context, req ControlsListRequest, deps ControlsListDeps) (ControlsListResponse, error) {
	if err := ctx.Err(); err != nil {
		return ControlsListResponse{}, fmt.Errorf("controls_list: %w", err)
	}
	rows, err := deps.Lister.ListControls(ctx, req.ControlsDir, req.BuiltIn, req.Filter)
	if err != nil {
		return ControlsListResponse{}, fmt.Errorf("controls_list: %w", err)
	}
	return ControlsListResponse{Controls: rows}, nil
}

// --- Graph Coverage ---

// GraphCoverageComputerPort computes control coverage across observations.
type GraphCoverageComputerPort interface {
	ComputeCoverage(ctx context.Context, controlsDir, observationsDir string) (any, error)
}

type GraphCoverageDeps struct {
	Computer GraphCoverageComputerPort
}

func GraphCoverage(ctx context.Context, req GraphCoverageRequest, deps GraphCoverageDeps) (GraphCoverageResponse, error) {
	if err := ctx.Err(); err != nil {
		return GraphCoverageResponse{}, fmt.Errorf("graph_coverage: %w", err)
	}
	data, err := deps.Computer.ComputeCoverage(ctx, req.ControlsDir, req.ObservationsDir)
	if err != nil {
		return GraphCoverageResponse{}, fmt.Errorf("graph_coverage: %w", err)
	}
	return GraphCoverageResponse{GraphData: data}, nil
}

// --- Explain ---

// ExplainControlFinderPort loads and explains a control definition.
type ExplainControlFinderPort interface {
	ExplainControl(ctx context.Context, controlID, controlsDir string) (ExplainResponse, error)
}

type ExplainDeps struct {
	Finder ExplainControlFinderPort
}

func Explain(ctx context.Context, req ExplainRequest, deps ExplainDeps) (ExplainResponse, error) {
	if err := ctx.Err(); err != nil {
		return ExplainResponse{}, fmt.Errorf("explain: %w", err)
	}
	if req.ControlID == "" {
		return ExplainResponse{}, fmt.Errorf("explain: control ID is required")
	}
	resp, err := deps.Finder.ExplainControl(ctx, req.ControlID, req.ControlsDir)
	if err != nil {
		return ExplainResponse{}, fmt.Errorf("explain: %w", err)
	}
	return resp, nil
}

// --- Controls Aliases ---

// PredicateAliasListerPort lists built-in semantic predicate alias names.
type PredicateAliasListerPort interface {
	ListPredicateAliases(ctx context.Context, category string) ([]string, error)
}

// PredicateAliasResolverPort expands a semantic alias to its predicate tree.
type PredicateAliasResolverPort interface {
	ResolveAlias(ctx context.Context, alias string) (any, error)
}

type ControlsAliasesDeps struct {
	Lister PredicateAliasListerPort
}

func ControlsAliases(ctx context.Context, req ControlsAliasesRequest, deps ControlsAliasesDeps) (ControlsAliasesResponse, error) {
	if err := ctx.Err(); err != nil {
		return ControlsAliasesResponse{}, fmt.Errorf("controls-aliases: %w", err)
	}
	names, err := deps.Lister.ListPredicateAliases(ctx, req.Category)
	if err != nil {
		return ControlsAliasesResponse{}, fmt.Errorf("controls-aliases: %w", err)
	}
	return ControlsAliasesResponse{Names: names}, nil
}

type ControlsAliasExplainDeps struct {
	Resolver PredicateAliasResolverPort
}

func ControlsAliasExplain(ctx context.Context, req ControlsAliasExplainRequest, deps ControlsAliasExplainDeps) (ControlsAliasExplainResponse, error) {
	if err := ctx.Err(); err != nil {
		return ControlsAliasExplainResponse{}, fmt.Errorf("controls-alias-explain: %w", err)
	}
	if req.Alias == "" {
		return ControlsAliasExplainResponse{}, fmt.Errorf("controls-alias-explain: alias name is required")
	}
	expanded, err := deps.Resolver.ResolveAlias(ctx, req.Alias)
	if err != nil {
		return ControlsAliasExplainResponse{}, fmt.Errorf("controls-alias-explain: %w", err)
	}
	return ControlsAliasExplainResponse{Alias: req.Alias, Expanded: expanded}, nil
}

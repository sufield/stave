package policy

import (
	"context"
	"fmt"
)

// --- Shared port for file-based inspect commands ---

// InputReaderPort reads input from a file path.
type InputReaderPort interface {
	ReadInput(ctx context.Context, filePath string) ([]byte, error)
}

// --- Inspect Policy ---

// PolicyAnalyzerPort analyzes an S3 bucket policy document.
type PolicyAnalyzerPort interface {
	AnalyzePolicy(ctx context.Context, policyJSON []byte) (InspectPolicyResponse, error)
}

type InspectPolicyDeps struct {
	Analyzer PolicyAnalyzerPort
	Reader   InputReaderPort
}

func InspectPolicy(ctx context.Context, req InspectPolicyRequest, deps InspectPolicyDeps) (InspectPolicyResponse, error) {
	input, err := resolveInput(ctx, req.FilePath, req.InputData, deps.Reader, "inspect-policy")
	if err != nil {
		return InspectPolicyResponse{}, err
	}

	resp, err := deps.Analyzer.AnalyzePolicy(ctx, input)
	if err != nil {
		return InspectPolicyResponse{}, fmt.Errorf("inspect-policy: %w", err)
	}
	return resp, nil
}

// --- Inspect ACL ---

// ACLAnalyzerPort analyzes S3 ACL grants.
type ACLAnalyzerPort interface {
	AnalyzeACL(ctx context.Context, grantsJSON []byte) (InspectACLResponse, error)
}

type InspectACLDeps struct {
	Analyzer ACLAnalyzerPort
	Reader   InputReaderPort
}

func InspectACL(ctx context.Context, req InspectACLRequest, deps InspectACLDeps) (InspectACLResponse, error) {
	input, err := resolveInput(ctx, req.FilePath, req.InputData, deps.Reader, "inspect-acl")
	if err != nil {
		return InspectACLResponse{}, err
	}

	resp, err := deps.Analyzer.AnalyzeACL(ctx, input)
	if err != nil {
		return InspectACLResponse{}, fmt.Errorf("inspect-acl: %w", err)
	}
	return resp, nil
}

// --- Inspect Exposure ---

// ExposureClassifierPort classifies resource exposure vectors.
type ExposureClassifierPort interface {
	ClassifyExposure(ctx context.Context, inputJSON []byte) (InspectExposureResponse, error)
}

type InspectExposureDeps struct {
	Classifier ExposureClassifierPort
	Reader     InputReaderPort
}

func InspectExposure(ctx context.Context, req InspectExposureRequest, deps InspectExposureDeps) (InspectExposureResponse, error) {
	input, err := resolveInput(ctx, req.FilePath, req.InputData, deps.Reader, "inspect-exposure")
	if err != nil {
		return InspectExposureResponse{}, err
	}

	resp, err := deps.Classifier.ClassifyExposure(ctx, input)
	if err != nil {
		return InspectExposureResponse{}, fmt.Errorf("inspect-exposure: %w", err)
	}
	return resp, nil
}

// --- Inspect Risk ---

// RiskScorerPort scores risk from a policy statement context.
type RiskScorerPort interface {
	ScoreRisk(ctx context.Context, inputJSON []byte) (InspectRiskResponse, error)
}

type InspectRiskDeps struct {
	Scorer RiskScorerPort
	Reader InputReaderPort
}

func InspectRisk(ctx context.Context, req InspectRiskRequest, deps InspectRiskDeps) (InspectRiskResponse, error) {
	input, err := resolveInput(ctx, req.FilePath, req.InputData, deps.Reader, "inspect-risk")
	if err != nil {
		return InspectRiskResponse{}, err
	}

	resp, err := deps.Scorer.ScoreRisk(ctx, input)
	if err != nil {
		return InspectRiskResponse{}, fmt.Errorf("inspect-risk: %w", err)
	}
	return resp, nil
}

// --- Inspect Compliance ---

// ComplianceResolverPort resolves a compliance framework crosswalk.
type ComplianceResolverPort interface {
	ResolveCrosswalk(ctx context.Context, raw []byte, frameworks, checkIDs []string) (InspectComplianceResponse, error)
}

type InspectComplianceDeps struct {
	Resolver ComplianceResolverPort
	Reader   InputReaderPort
}

func InspectCompliance(ctx context.Context, req InspectComplianceRequest, deps InspectComplianceDeps) (InspectComplianceResponse, error) {
	input, err := resolveInput(ctx, req.FilePath, req.InputData, deps.Reader, "inspect-compliance")
	if err != nil {
		return InspectComplianceResponse{}, err
	}

	resp, err := deps.Resolver.ResolveCrosswalk(ctx, input, req.Frameworks, req.CheckIDs)
	if err != nil {
		return InspectComplianceResponse{}, fmt.Errorf("inspect-compliance: %w", err)
	}
	return resp, nil
}

// --- Inspect Aliases ---

// AliasRegistryPort lists predicate aliases from the built-in registry.
type AliasRegistryPort interface {
	ListAliases(ctx context.Context, category string) (InspectAliasesResponse, error)
}

type InspectAliasesDeps struct {
	Registry AliasRegistryPort
}

func InspectAliases(ctx context.Context, req InspectAliasesRequest, deps InspectAliasesDeps) (InspectAliasesResponse, error) {
	if err := ctx.Err(); err != nil {
		return InspectAliasesResponse{}, fmt.Errorf("inspect-aliases: %w", err)
	}

	resp, err := deps.Registry.ListAliases(ctx, req.Category)
	if err != nil {
		return InspectAliasesResponse{}, fmt.Errorf("inspect-aliases: %w", err)
	}
	return resp, nil
}

// --- Private helper ---

// resolveInput handles the file-or-stdin input pattern shared by all
// file-based inspect commands.
func resolveInput(ctx context.Context, filePath string, inputData []byte, reader InputReaderPort, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	if filePath != "" {
		data, err := reader.ReadInput(ctx, filePath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return data, nil
	}
	if len(inputData) > 0 {
		return inputData, nil
	}
	return nil, fmt.Errorf("%s: no input provided (use --file or stdin)", name)
}

package stave

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/app/chainforge"
	"github.com/sufield/stave/internal/core/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	forgecmd "github.com/sufield/stave/pkg/stave/internal/forgecmd"
)

// CatalogValidateOptions parameterizes [CatalogValidate].
type CatalogValidateOptions struct {
	ControlsDir string
	ChainsDir   string
	Semantic    bool
	Strict      bool
}

// CatalogValidateResult holds the combined validation output.
type CatalogValidateResult struct {
	ControlLint    CatalogValidateSection `json:"control_lint"`
	ChainLint      CatalogValidateSection `json:"chain_lint"`
	CrossReference CatalogValidateSection `json:"cross_reference"`
	TotalErrors    int                    `json:"total_errors"`
	TotalWarnings  int                    `json:"total_warnings"`
}

// HasErrors reports whether any catalog validation errors were found.
func (r *CatalogValidateResult) HasErrors() bool {
	return r != nil && r.TotalErrors > 0
}

// HasWarnings reports whether any catalog validation warnings were found.
func (r *CatalogValidateResult) HasWarnings() bool {
	return r != nil && r.TotalWarnings > 0
}

// IsValid reports whether the catalog validation passed without errors (or warnings if strict).
func (r *CatalogValidateResult) IsValid(strict bool) bool {
	if r == nil {
		return false
	}
	if r.HasErrors() {
		return false
	}
	if strict && r.HasWarnings() {
		return false
	}
	return true
}

// CatalogValidateSection holds results from one validation phase.
type CatalogValidateSection struct {
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// IsEmpty reports whether the section has no errors and no warnings.
func (s CatalogValidateSection) IsEmpty() bool {
	return len(s.Errors) == 0 && len(s.Warnings) == 0
}

// HasIssues reports whether the section has any errors or warnings.
func (s CatalogValidateSection) HasIssues() bool {
	return len(s.Errors) > 0 || len(s.Warnings) > 0
}

// CatalogValidate runs combined control lint, chain lint, and
// cross-reference validation on the catalog. It is the library entry
// point behind `stave catalog validate`.
func CatalogValidate(ctx context.Context, opts CatalogValidateOptions) (*CatalogValidateResult, error) {
	result := &CatalogValidateResult{}

	// Phase 1: Control lint.
	_, ctlErr := forgecmd.Lint(opts.ControlsDir, opts.Semantic, false)
	if ctlErr != nil {
		result.ControlLint.Errors = append(result.ControlLint.Errors,
			fmt.Sprintf("control lint: %v", ctlErr))
	}

	// Phase 2: Load controls + chains for cross-reference.
	controls, loadErr := loadControlsFromDir(ctx, opts.ControlsDir)
	if loadErr != nil {
		result.ControlLint.Errors = append(result.ControlLint.Errors,
			fmt.Sprintf("load controls: %v", loadErr))
		result.TotalErrors = countErrors(result)
		result.TotalWarnings = countWarnings(result)
		return result, nil
	}

	registry := capabilities.Builtin()
	chains, chainLoadErr := loadChainsOptional(opts.ChainsDir)
	if chainLoadErr != nil {
		result.ChainLint.Errors = append(result.ChainLint.Errors,
			fmt.Sprintf("load chains: %v", chainLoadErr))
		result.TotalErrors = countErrors(result)
		result.TotalWarnings = countWarnings(result)
		return result, nil
	}

	// Phase 3: Chain lint.
	controlIDs := make(map[kernel.ControlID]struct{}, len(controls))
	for i := range controls {
		controlIDs[controls[i].ID] = struct{}{}
	}
	for i := range chains {
		lr := chainforge.LintChain(&chains[i], controlIDs, registry)
		for _, e := range lr.Errors {
			result.ChainLint.Errors = append(result.ChainLint.Errors,
				fmt.Sprintf("%s: %s", lr.ChainID, e))
		}
		for _, w := range lr.Warnings {
			result.ChainLint.Warnings = append(result.ChainLint.Warnings,
				fmt.Sprintf("%s: %s", lr.ChainID, w))
		}
	}

	// Phase 4: Cross-reference — chain ControlIDs against catalog.
	issues := policy.ValidateChainRefs(chains, controls)
	for _, issue := range issues {
		for _, missing := range issue.MissingControl {
			result.CrossReference.Errors = append(result.CrossReference.Errors,
				fmt.Sprintf("chain %s references non-existent control %s", issue.ChainID, missing))
		}
	}

	result.TotalErrors = countErrors(result)
	result.TotalWarnings = countWarnings(result)
	return result, nil
}

func countErrors(r *CatalogValidateResult) int {
	return len(r.ControlLint.Errors) + len(r.ChainLint.Errors) + len(r.CrossReference.Errors)
}

func countWarnings(r *CatalogValidateResult) int {
	return len(r.ControlLint.Warnings) + len(r.ChainLint.Warnings) + len(r.CrossReference.Warnings)
}

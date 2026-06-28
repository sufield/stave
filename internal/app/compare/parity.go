package compare

import (
	"cmp"
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// ParityVerdict classifies a control across environments.
type ParityVerdict string

const (
	ConsistentPass ParityVerdict = "CONSISTENT_PASS"
	ConsistentFail ParityVerdict = "CONSISTENT_FAIL"
	ProdRegression ParityVerdict = "PROD_REGRESSION"
	EnvHardening   ParityVerdict = "ENV_HARDENING"
	Mixed          ParityVerdict = "MIXED"
)

// ParityItem is a control with its verdict per environment.
type ParityItem struct {
	ControlID string            `json:"control_id"`
	Severity  string            `json:"severity,omitempty"`
	Verdict   ParityVerdict     `json:"verdict"`
	PerEnv    map[string]string `json:"per_env"` // env → "PASS" | "FAIL"
}

// ParityResult holds the full parity analysis.
type ParityResult struct {
	GeneratedAt    string       `json:"generated_at"`
	Environments   []string     `json:"environments"`
	ConsistentPass int          `json:"consistent_pass"`
	ConsistentFail []ParityItem `json:"consistent_fail"`
	ProdRegression []ParityItem `json:"prod_regression"`
	EnvHardening   []ParityItem `json:"env_hardening"`
	MixedItems     []ParityItem `json:"mixed,omitempty"`
}

// ParityInput holds data for parity analysis.
type ParityInput struct {
	GeneratedAt  string
	Environments map[string][]remediation.Finding // env name → findings
	EnvOrder     []string                         // first = production
	AllControls  []string                         // Optional: list of all evaluated control IDs
}

// AnalyzeParity compares findings across environments.
func AnalyzeParity(input ParityInput) *ParityResult {
	if len(input.EnvOrder) < 2 {
		return &ParityResult{GeneratedAt: input.GeneratedAt}
	}

	prodEnv := input.EnvOrder[0]

	// Build per-control per-env verdict map.
	failingByEnv := make(map[string]map[kernel.ControlID]struct{}, len(input.EnvOrder))
	allControls := make(map[kernel.ControlID]string) // control → severity

	for _, env := range input.EnvOrder {
		failingByEnv[env] = make(map[kernel.ControlID]struct{}, len(input.Environments[env]))
		for i := range input.Environments[env] {
			f := &input.Environments[env][i]
			failingByEnv[env][f.ControlID] = struct{}{}
			if _, ok := allControls[f.ControlID]; !ok {
				allControls[f.ControlID] = f.SeverityLabel()
			}
		}
	}

	var consistentFail, prodRegression, envHardening, mixed []ParityItem
	consistentPassCount := 0

	// Calculate consistent passes from the total evaluated controls set.
	for _, cidStr := range input.AllControls {
		cid := kernel.ControlID(cidStr)
		if _, ok := allControls[cid]; !ok {
			consistentPassCount++
		}
	}

	sevOrder := policy.SeverityOrderOf

	for cid, sev := range allControls {
		perEnv := make(map[string]string, len(input.EnvOrder))
		failCount := 0
		prodFails := false
		lowerFails := 0

		for _, env := range input.EnvOrder {
			if _, ok := failingByEnv[env][cid]; ok {
				perEnv[env] = "FAIL"
				failCount++
				if env == prodEnv {
					prodFails = true
				} else {
					lowerFails++
				}
			} else {
				perEnv[env] = "PASS"
			}
		}

		item := ParityItem{
			ControlID: string(cid),
			Severity:  sev,
			PerEnv:    perEnv,
		}

		switch {
		case failCount == len(input.EnvOrder):
			item.Verdict = ConsistentFail
			consistentFail = append(consistentFail, item)
		case failCount == 0:
			consistentPassCount++
		case prodFails && lowerFails == 0:
			item.Verdict = ProdRegression
			prodRegression = append(prodRegression, item)
		case !prodFails && lowerFails > 0:
			item.Verdict = EnvHardening
			envHardening = append(envHardening, item)
		default:
			item.Verdict = Mixed
			mixed = append(mixed, item)
		}
	}

	// Sort by severity.
	sortBySev := func(items []ParityItem) {
		slices.SortFunc(items, func(a, b ParityItem) int {
			sa := sevOrder(a.Severity)
			sb := sevOrder(b.Severity)
			if sa != sb {
				return cmp.Compare(sa, sb)
			}
			return cmp.Compare(a.ControlID, b.ControlID)
		})
	}
	sortBySev(consistentFail)
	sortBySev(prodRegression)
	sortBySev(envHardening)

	return &ParityResult{
		GeneratedAt:    input.GeneratedAt,
		Environments:   input.EnvOrder,
		ConsistentPass: consistentPassCount,
		ConsistentFail: consistentFail,
		ProdRegression: prodRegression,
		EnvHardening:   envHardening,
		MixedItems:     mixed,
	}
}

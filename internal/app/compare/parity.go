package compare

import (
	"sort"
	"strings"

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
}

// AnalyzeParity compares findings across environments.
func AnalyzeParity(input ParityInput) *ParityResult {
	if len(input.EnvOrder) < 2 {
		return &ParityResult{GeneratedAt: input.GeneratedAt}
	}

	prodEnv := input.EnvOrder[0]

	// Build per-control per-env verdict map.
	failingByEnv := make(map[string]map[kernel.ControlID]bool)
	allControls := make(map[kernel.ControlID]string) // control → severity

	for _, env := range input.EnvOrder {
		failingByEnv[env] = make(map[kernel.ControlID]bool)
		for i := range input.Environments[env] {
			f := &input.Environments[env][i]
			failingByEnv[env][f.ControlID] = true
			if _, ok := allControls[f.ControlID]; !ok {
				allControls[f.ControlID] = f.ControlSeverity.String()
			}
		}
	}

	var consistentFail, prodRegression, envHardening, mixed []ParityItem
	consistentPassCount := 0

	sevOrder := kernel.SeverityOrder

	for cid, sev := range allControls {
		perEnv := make(map[string]string)
		failCount := 0
		prodFails := false
		lowerFails := 0

		for _, env := range input.EnvOrder {
			if failingByEnv[env][cid] {
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
		sort.Slice(items, func(i, j int) bool {
			si := sevOrder[strings.ToLower(items[i].Severity)]
			sj := sevOrder[strings.ToLower(items[j].Severity)]
			if si != sj {
				return si < sj
			}
			return items[i].ControlID < items[j].ControlID
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

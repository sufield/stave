package architecture_test

import (
	"testing"

	archgo "github.com/arch-go/arch-go/api"
	"github.com/arch-go/arch-go/api/configuration"
)

func intPtr(v int) *int { return &v }

func TestArchitecture(t *testing.T) {
	moduleInfo := configuration.Load("github.com/sufield/stave")

	cfg := configuration.Config{
		// === DEPENDENCY RULES ===
		DependenciesRules: dependencyRules(),

		// === FUNCTION RULES ===
		FunctionsRules: functionRules(),

		// === CONTENT RULES ===
		// TODO: ports contains structs (RealClock, FixedClock, EffectivePermission,
		// FinalizeArgs) — enable after extracting value types to a separate package.
		// ContentRules: []*configuration.ContentsRule{
		// 	{Package: "**.core.ports", ShouldOnlyContainInterfaces: true},
		// },
	}

	result := archgo.CheckArchitecture(moduleInfo, cfg)
	if result.Pass {
		return
	}

	reportDeps(t, result)
	reportFuncs(t, result)
	reportContents(t, result)
	t.Fatal("architecture checks failed — run 'arch-go describe' for full rule set")
}

func reportDeps(t *testing.T, result *archgo.Result) {
	t.Helper()
	dr := result.DependenciesRuleResult
	if dr == nil || dr.Passes {
		return
	}
	for _, r := range dr.Results {
		if r.Passes {
			continue
		}
		t.Errorf("dependency: %s", r.Description)
		for _, v := range r.Verifications {
			if v.Passes {
				continue
			}
			for _, d := range v.Details {
				t.Logf("  %s: %s", v.Package, d)
			}
		}
	}
}

func reportFuncs(t *testing.T, result *archgo.Result) {
	t.Helper()
	fr := result.FunctionsRuleResult
	if fr == nil || fr.Passes {
		return
	}
	for _, r := range fr.Results {
		if r.Passes {
			continue
		}
		t.Errorf("function: %s", r.Description)
		for _, v := range r.Verifications {
			if v.Passes {
				continue
			}
			for _, d := range v.Details {
				t.Logf("  %s: %s", v.Package, d)
			}
		}
	}
}

func reportContents(t *testing.T, result *archgo.Result) {
	t.Helper()
	cr := result.ContentsRuleResult
	if cr == nil || cr.Passes {
		return
	}
	for _, r := range cr.Results {
		if r.Passes {
			continue
		}
		t.Errorf("content: %s", r.Description)
	}
}

// dependencyRules encodes the hexagonal architecture boundaries.
//
// Measurements taken 2026-09-13 against 328 packages:
//   - core imports: only core/** and util/sets
//   - app imports: core, compliance, contracts, controldata, env, platform/fsutil, util, version
//   - adapters imports: core, platform, cli/ui, contracts, controldata, doctor, env, util
//   - platform imports: core, env, sanitize, util
func dependencyRules() []*configuration.DependenciesRule {
	return []*configuration.DependenciesRule{
		// Engine: only core deps (load-bearing assertion).
		{
			Package: "**.core.evaluation.engine.**",
			ShouldOnlyDependsOn: &configuration.Dependencies{
				Internal: []string{"**.core.**"},
			},
		},
		// Core: hexagonal center — no outward deps.
		{
			Package: "**.core.**",
			ShouldNotDependsOn: &configuration.Dependencies{
				Internal: []string{
					"**.adapters.**",
					"**.app.**",
					"**.cmd.**",
					"**.platform.**",
				},
			},
		},
		// App: no adapters or cmd.
		{
			Package: "**.app.**",
			ShouldNotDependsOn: &configuration.Dependencies{
				Internal: []string{
					"**.adapters.**",
					"**.cmd.**",
				},
			},
		},
		// Adapters: no app or cmd.
		{
			Package: "**.adapters.**",
			ShouldNotDependsOn: &configuration.Dependencies{
				Internal: []string{
					"**.app.**",
					"**.cmd.**",
				},
			},
		},
		// Platform: no adapters, app, or cmd.
		{
			Package: "**.platform.**",
			ShouldNotDependsOn: &configuration.Dependencies{
				Internal: []string{
					"**.adapters.**",
					"**.app.**",
					"**.cmd.**",
				},
			},
		},
		// cmd/gaps: facade-only — only pkg/stave and cmd utilities.
		{
			Package: "**.cmd.gaps",
			ShouldNotDependsOn: &configuration.Dependencies{
				Internal: []string{"**.internal.**"},
			},
		},
		// cmd/readiness: facade-only — only pkg/stave and cmd utilities.
		{
			Package: "**.cmd.readiness",
			ShouldNotDependsOn: &configuration.Dependencies{
				Internal: []string{"**.internal.**"},
			},
		},
	}
}

// functionRules bounds evaluator complexity.
//
// Measured 2026-09-13 from internal/core/evaluation/engine/:
//   - max lines: 126 (applyControl in assessor.go)
//   - max params: 3 (not counting receiver)
//   - max return values: 2
//   - max public functions/file: 12 (assessor.go)
func functionRules() []*configuration.FunctionsRule {
	return []*configuration.FunctionsRule{
		{
			Package:                  "**.core.evaluation.engine.**",
			MaxLines:                 intPtr(130),
			MaxParameters:            intPtr(5),
			MaxReturnValues:          intPtr(3),
			MaxPublicFunctionPerFile: intPtr(15),
		},
	}
}

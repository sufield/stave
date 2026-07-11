package template

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"

	"github.com/sufield/stave/pkg/stave/snapshot"
)

// Recommendation is a template that matched the snapshot summary.
type Recommendation struct {
	Template     Template
	MatchedFacts []string
}

// Recommend evaluates all templates against the snapshot summary and
// returns matching templates sorted by priority (highest first).
func Recommend(templates []Template, summary snapshot.Summary) ([]Recommendation, error) {
	env, err := newRecommendEnv()
	if err != nil {
		return nil, err
	}

	activation := summaryToMap(summary)
	var results []Recommendation

	for i := range templates {
		if templates[i].RecommendWhen.Predicate == "" {
			continue
		}

		matched, facts, err := evalPredicate(env, templates[i].RecommendWhen.Predicate, activation)
		if err != nil {
			return nil, fmt.Errorf("evaluate template %q: %w", templates[i].Metadata.Name, err)
		}
		if matched {
			results = append(results, Recommendation{
				Template:     templates[i],
				MatchedFacts: facts,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Template.RecommendWhen.Priority > results[j].Template.RecommendWhen.Priority
	})

	return results, nil
}

// newRecommendEnv creates a CEL environment for recommend_when predicates.
// Registers "summary" as the root variable — a map<string, dyn>.
func newRecommendEnv() (*cel.Env, error) {
	env, err := cel.NewEnv(
		cel.Variable("summary", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("create recommend CEL environment: %w", err)
	}
	return env, nil
}

// evalPredicate compiles and evaluates a CEL predicate against the summary.
// Returns whether the predicate is true and which top-level conjuncts matched.
func evalPredicate(env *cel.Env, predicate string, activation map[string]any) (bool, []string, error) {
	ast, issues := env.Compile(predicate)
	if issues != nil && issues.Err() != nil {
		return false, nil, fmt.Errorf("compile predicate: %w", issues.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return false, nil, fmt.Errorf("program predicate: %w", err)
	}

	out, _, evalErr := prg.Eval(activation)
	if evalErr != nil {
		// CEL runtime error (missing field, type mismatch) = predicate does not match.
		return false, nil, nil //nolint:nilerr // intentional: eval failure means no match
	}

	matched, ok := out.Value().(bool)
	if !ok || !matched {
		return false, nil, nil
	}

	facts := extractMatchedFacts(env, predicate, activation)
	return true, facts, nil
}

// extractMatchedFacts splits the predicate on top-level && and reports
// which conjuncts evaluated to true.
func extractMatchedFacts(env *cel.Env, predicate string, activation map[string]any) []string {
	conjuncts := splitConjuncts(predicate)
	var facts []string

	for _, c := range conjuncts {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}

		ast, issues := env.Compile(c)
		if issues != nil && issues.Err() != nil {
			continue
		}

		prg, err := env.Program(ast)
		if err != nil {
			continue
		}

		out, _, err := prg.Eval(activation)
		if err != nil {
			continue
		}

		if v, ok := out.Value().(bool); ok && v {
			facts = append(facts, c)
		}
	}

	return facts
}

// splitConjuncts splits a predicate on top-level && operators.
// Does not attempt full AST parsing — handles the common case where
// recommend_when is a conjunction of conditions.
func splitConjuncts(predicate string) []string {
	var parts []string
	depth := 0
	start := 0

	for i := 0; i < len(predicate); i++ {
		switch predicate[i] {
		case '(':
			depth++
		case ')':
			depth--
		case '&':
			if depth == 0 && i+1 < len(predicate) && predicate[i+1] == '&' {
				parts = append(parts, predicate[start:i])
				i++ // skip second &
				start = i + 1
			}
		}
	}
	parts = append(parts, predicate[start:])
	return parts
}

// summaryToMap converts a Summary to the CEL activation map.
func summaryToMap(s snapshot.Summary) map[string]any {
	sm := map[string]any{
		"services":        s.Services,
		"account_count":   int64(s.AccountCount),
		"account_ids":     s.AccountIDs,
		"region_count":    int64(s.RegionCount),
		"regions":         s.Regions,
		"resource_count":  int64(s.ResourceCount),
		"has_org_root":    s.HasOrgRoot,
		"has_scps":        s.HasSCPs,
		"has_cloudtrail":  s.HasCloudTrail,
		"has_guardduty":   s.HasGuardDuty,
		"has_flow_logs":   s.HasFlowLogs,
		"has_firehose":    s.HasFirehose,
		"has_replication": s.HasReplication,
		"s3_bucket_count": int64(s.S3BucketCount),
		"iam_role_count":  int64(s.IAMRoleCount),
		"eval_time_set":   s.EvalTimeSet,
		"service_counts":  s.ServiceCounts,
		"service_count":   int64(len(s.Services)),
	}
	return map[string]any{"summary": sm}
}

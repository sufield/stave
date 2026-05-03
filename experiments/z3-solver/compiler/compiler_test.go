package compiler_test

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sufield/stave/experiments/z3-solver/compiler"
	"github.com/sufield/stave/experiments/z3-solver/loader"
	"github.com/sufield/stave/experiments/z3-solver/queries"
)

// fixtureDir resolves a path under testdata/known_answers/ relative
// to this test file. Using runtime.Caller keeps the resolution
// stable regardless of which working directory `go test` runs in.
func fixtureDir(t *testing.T, name string) string {
	t.Helper()
	_, this, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(this), "..", "testdata", "known_answers", name, "observations")
}

// TestKnownAnswers exercises the compiler + queries against
// hand-crafted observation fixtures whose correct Z3 verdict is
// known. Each entry pins one piece of the AWS IAM evaluation
// model:
//
//   - iam_deny_overrides_allow: a single bucket whose policy
//     contains an Allow and a Deny for the same (principal,
//     action, resource). The IAM evaluator's Deny-first ordering
//     must produce UNSAT.
//
// Add fixtures here as the model grows; every new piece of IAM
// semantics earns its own pinned-answer test before it ships.
func TestKnownAnswers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		fixture   string
		query     string
		principal string
		action    string
		resource  string
		want      string
	}{
		{
			name:      "iam_deny_overrides_allow",
			fixture:   "iam_deny_overrides_allow",
			query:     "compatibility",
			principal: "arn:aws:iam::111122223333:role/ServiceB",
			action:    "s3:GetObject",
			resource:  "arn:aws:s3:::deny-test-bucket/*",
			want:      "unsatisfiable",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			exports, err := loader.LoadFromObservations(ctx, fixtureDir(t, tc.fixture))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			model, err := compiler.Compile(exports)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			var got *queries.QueryResult
			switch tc.query {
			case "compatibility":
				got = queries.QueryCompatibility(model, tc.principal, tc.action, tc.resource)
			default:
				t.Fatalf("unknown query in test case: %s", tc.query)
			}
			if got.Result != tc.want {
				t.Errorf("query=%s want=%s got=%s\nInterpretation: %s",
					tc.query, tc.want, got.Result, got.Interpretation)
			}
		})
	}
}

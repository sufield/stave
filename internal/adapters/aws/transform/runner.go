// Package transform converts raw AWS CLI snapshots (e.g. `aws iam list-roles`
// output) into obs.v0.1 observations using jq filters run in-process via gojq.
//
// This is an AWS adapter: it lives under internal/adapters/aws and never imports
// internal/core. Collection (calling AWS) stays the user's job; this package only
// reshapes already-captured JSON, matching the discover→collect→transform→apply
// workflow.
//
// Iteration 0 seeds the gojq primitive (runJQ) and its test. The detector,
// scrubber, obs.v0.1 envelope, schema validation, and the .jq filter files
// (extracted from scripts/aws-snapshot.sh — the single source of truth for the
// mappings) land in Iteration 1.
package transform

import (
	"encoding/json"
	"fmt"

	"github.com/itchyny/gojq"
)

// runJQ compiles a jq program and runs it over a single decoded JSON document,
// returning every emitted value as raw JSON. A jq runtime error (e.g. indexing a
// string) surfaces as an error rather than a partial result — fail loud.
func runJQ(program string, input any) ([]json.RawMessage, error) {
	return runJQWithArgs(program, input, nil)
}

// runJQWithArgs is runJQ with named jq variables ($name) bound from args — used
// for capture-time parameters that aren't in the raw AWS output (e.g. the account
// ID, which aws-snapshot.sh supplies at capture time). Keys are bare names; the
// filter references them as $name.
func runJQWithArgs(program string, input any, args map[string]any) ([]json.RawMessage, error) {
	names := make([]string, 0, len(args))
	values := make([]any, 0, len(args))
	for k, v := range args {
		names = append(names, "$"+k)
		values = append(values, v)
	}

	query, err := gojq.Parse(program)
	if err != nil {
		return nil, fmt.Errorf("parse jq filter: %w", err)
	}
	code, err := gojq.Compile(query, gojq.WithVariables(names))
	if err != nil {
		return nil, fmt.Errorf("compile jq filter: %w", err)
	}

	var out []json.RawMessage
	iter := code.Run(input, values...)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if e, isErr := v.(error); isErr {
			return nil, fmt.Errorf("run jq filter: %w", e)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal jq output: %w", err)
		}
		out = append(out, b)
	}
	return out, nil
}

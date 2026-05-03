// Command stave-z3 drives the Z3 experiment from the command
// line. It loads the three Stave exports against the supplied
// observation directory, compiles them into a Z3 model, and runs
// one of the implemented queries.
//
// Output is always JSON on stdout (or to --output) — the rendered
// QueryResult is the only contract this binary exposes.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sufield/stave/experiments/z3-solver/compiler"
	"github.com/sufield/stave/experiments/z3-solver/loader"
	"github.com/sufield/stave/experiments/z3-solver/queries"
	"github.com/sufield/stave/experiments/z3-solver/shadow"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "stave-z3: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		observationsDir = flag.String("observations", "", "path to observations directory (required)")
		query           = flag.String("query", "", "query: compatibility|reachability|conflict|choke-point|invariant|shadow")
		principal       = flag.String("principal", "", "principal ARN (compatibility, reachability, choke-point)")
		action          = flag.String("action", "", "action (compatibility)")
		resource        = flag.String("resource", "", "resource ARN (compatibility, reachability, choke-point)")
		invariantID     = flag.String("invariant", "", "invariant control ID (invariant query)")
		outPath         = flag.String("output", "", "output file (defaults to stdout)")
	)
	flag.Parse()

	if *observationsDir == "" || *query == "" {
		flag.Usage()
		return fmt.Errorf("--observations and --query are required")
	}

	ctx := context.Background()
	exports, err := loader.LoadFromObservations(ctx, *observationsDir)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	model, err := compiler.Compile(exports)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	w, closer, err := openWriter(*outPath)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}

	switch *query {
	case "compatibility":
		return writeJSON(w, queries.QueryCompatibility(model, *principal, *action, *resource))
	case "reachability":
		return writeJSON(w, queries.QueryReachability(model, *principal, *resource))
	case "conflict":
		return writeJSON(w, queries.QueryConflict(model))
	case "choke-point":
		reach := queries.QueryReachability(model, *principal, *resource)
		return writeJSON(w, queries.QueryChokePoint(model, reach))
	case "invariant":
		return writeJSON(w, queries.QueryInvariantVerify(model, *invariantID))
	case "shadow":
		return writeJSON(w, shadow.Compare(model, exports, *observationsDir))
	}
	return fmt.Errorf("unknown query: %s", *query)
}

func openWriter(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, nil, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("create %s: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

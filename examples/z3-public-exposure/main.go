//go:build z3example

// Command z3-public-exposure demonstrates how a Go program can
// use Stave's library API to load an observation snapshot, then
// encode a small property in Z3 (via a Go binding to libz3) and
// let the solver verify it.
//
// The example is intentionally tiny — it reasons over two
// boolean facts per S3 bucket and asks "is there any way for
// public access to be possible?" The point is the SHAPE of the
// pipeline, not feature parity with Stave's own evaluator:
//
//	observations dir
//	  -> Stave loader (library API)
//	  -> []asset.Snapshot
//	  -> per-bucket Z3 model
//	  -> Z3 solver SAT/UNSAT verdict
//
// Stave's main binary is built with CGO_ENABLED=0; this example
// is the only Go program in the repo that links libz3. Build it
// with:
//
//	apt install libz3-dev pkg-config
//	CGO_ENABLED=1 go build -o z3-example ./examples/z3-public-exposure
//
// Run it against any directory of obs.v0.1 snapshot files:
//
//	z3-example examples/public-bucket/observations
//
// The Z3 binding used here is github.com/aclements/go-z3. Other
// Go bindings to libz3 work the same way; the encoding logic
// would only need to follow the new package's API conventions.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"

	"github.com/aclements/go-z3/z3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: z3-public-exposure <observations-dir>")
		os.Exit(2)
	}
	obsDir := os.Args[1]

	// Use the Stave library to load and parse the snapshot
	// directory. The loader handles file walking, JSON
	// validation, and error reporting consistently with the
	// rest of Stave.
	loader := observations.NewObservationLoader()
	res, err := loader.LoadSnapshots(context.Background(), obsDir)
	if err != nil {
		log.Fatalf("load snapshots: %v", err)
	}

	// Build a Z3 context shared across all buckets we examine.
	// One context can host many independent solver instances;
	// we use a fresh solver per bucket so assertions don't
	// leak between checks.
	ctx := z3.NewContext(nil)

	for _, snap := range res.Snapshots {
		for i := range snap.Assets {
			a := &snap.Assets[i]
			if string(a.Type) != "aws_s3_bucket" {
				continue
			}
			verdict := checkBucket(ctx, a)
			fmt.Println(verdict)
		}
	}
}

// checkBucket encodes a tiny S3 public-exposure model and asks
// Z3 whether the unsafe predicate is satisfiable for the given
// bucket. The model has two boolean facts read from
// asset.Properties:
//
//	policy_allows_public_read     — bucket policy admits Principal:*
//	public_access_block_enabled   — PAB blocks public access
//
// Unsafe predicate: policy_allows_public_read AND NOT pab.
// SAT  → public read is reachable; print UNSAFE.
// UNSAT → not reachable in this model; print SAFE.
//
// A real solver would parse the full bucket-policy JSON and
// encode condition operators; this example abstracts that work
// into two booleans so the Z3 mechanics stay legible.
func checkBucket(ctx *z3.Context, a *asset.Asset) string {
	policyPublic, _ := a.Properties["policy_allows_public_read"].(bool)
	pabBlocks, _ := a.Properties["public_access_block_enabled"].(bool)

	policyVar := ctx.FromBool(policyPublic)
	pabVar := ctx.FromBool(pabBlocks)
	unsafe := policyVar.And(pabVar.Not())

	s := z3.NewSolver(ctx)
	s.Assert(unsafe)
	sat, err := s.Check()
	if err != nil {
		return fmt.Sprintf("ERROR  %s — z3 check failed: %v", a.ID, err)
	}
	if sat {
		return fmt.Sprintf("UNSAFE %s — public read is provably possible (policy_public=%v, pab=%v)",
			a.ID, policyPublic, pabBlocks)
	}
	return fmt.Sprintf("SAFE   %s — public read is provably impossible under this model", a.ID)
}

// Package stave is the programmatic entry point for running Stave's
// control evaluation. It exposes the apply command — the same
// evaluation the ./stave CLI performs — as a typed Go API.
//
// # When to use
//
// Use this package when a Go program needs the output of `stave apply`
// without shelling out and parsing JSON. Consumers get typed
// [Finding], [Issue], [Assessment], [ControlID], [AssetID],
// [Classification], and [Severity] values; they do not marshal or
// unmarshal anything.
//
// # When not to use
//
// Shell users want the `./stave apply` CLI. Non-Go consumers
// (scripts, other languages) want the CLI's JSON output over stdout.
// This package is Go-only.
//
// # Basic usage
//
//	cfg := stave.Config{
//		SnapshotsDir: "./observations",
//		// ControlsDir empty → use the embedded builtin catalog.
//		// MaxUnsafe zero → project default.
//		// Now zero → real current time.
//	}
//	a, err := stave.Apply(context.Background(), cfg)
//	if err != nil {
//		return err
//	}
//	for _, f := range a.Findings {
//		if f.Classification == stave.StateAssertion {
//			fmt.Println(f.ControlID, f.AssetID, f.Severity)
//		}
//	}
//
// # Scope
//
// This package currently exposes Apply only. Additional operations
// (Gate, Fix, Verify, Trace, Diagnose, SnapshotDiff) will be added
// when concrete consumer needs justify them.
//
// # Relationship to the CLI
//
// ./stave apply and stave.Apply share the evaluation engine but not
// the adapter layer. The CLI writes to stdout, supports SARIF and
// text formatting, handles SLA overlays, team manifests, and other
// workflow concerns. The library returns typed values and leaves
// rendering and reporting to the caller. ./stave apply's output is
// byte-identical before and after this package was introduced.
package stave

// Package stave is the programmatic entry point for running Stave's
// control evaluation. It exposes the canonical use cases — Apply,
// Score, Gate — as typed Go APIs that the ./stave CLI is itself a
// thin wrapper over.
//
// # When to use
//
// Use this package when a Go program needs the output of `stave apply`,
// `stave score`, or `stave ci gate` without shelling out and parsing
// JSON. Consumers get typed [Finding], [Issue], [Assessment],
// [ControlID], [AssetID], [Classification], [Severity], [ScoreResult],
// and [GateResult] values; they do not marshal or unmarshal anything.
//
// # When not to use
//
// Shell users want the `./stave ...` CLI. Non-Go consumers (scripts,
// other languages) want the CLI's JSON output over stdout. This
// package is Go-only.
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
//	// Score the assessment.
//	sr, _ := stave.Score(ctx, stave.ScoreConfig{Assessment: a})
//	fmt.Printf("posture %.0f/100 (%s)\n", sr.Score, sr.RubricBand)
//
//	// Gate a CI pipeline against the artifact.
//	g, _ := stave.Gate(ctx, stave.GateConfig{
//		Policy:         stave.GateFailOnAnyViolation,
//		EvaluationPath: "out/evaluation.json",
//	})
//	if !g.Passed {
//		os.Exit(3)
//	}
//
// # Library is the source of truth
//
// The ./stave CLI is a thin wrapper over this package. New use cases
// land here first; the CLI invokes them with flag-derived Config
// structs and renders the typed Result back to stdout. This means a
// behavior change ships in one place — anything the CLI does that
// the library can't is a gap that should be closed, not a feature.
//
// # The standard pattern
//
// Every use case in this package follows the same shape:
//
//  1. A Config struct (Apply: [Config]; Score: [ScoreConfig]; Gate:
//     [GateConfig]) carries the inputs. Required fields are
//     documented; zero values default sensibly. CLI flags map 1:1
//     to Config fields where possible.
//
//  2. A Result struct (Apply: [Assessment]; Score: [ScoreResult];
//     Gate: [GateResult]) carries the outputs. Domain types are
//     re-aliased from internal packages where the wire format is
//     stable; otherwise the result is mirrored to keep the public
//     API independent of engine refactors.
//
//  3. The function is `Verb(ctx, cfg) (*Result, error)`. Adapters
//     are wired internally — the library is responsible for
//     instantiating loaders, evaluators, and any other ports
//     usecase.Verb requires.
//
//  4. Pure operations (no I/O) take only a Config and return the
//     Result; orchestration operations (with I/O) accept a context
//     for cancellation. Score is pure; Apply and Gate orchestrate.
//
// New use cases should land here in this order:
//
//   - Verify — re-evaluate a snapshot bundle against an existing
//     evaluation artifact. Port: [usecase.Verify] (planned). App
//     orchestration: [internal/app/eval]. Config carries
//     EvaluationPath, BundlePath, and ControlsDir.
//
//   - Trace — produce a per-control / per-asset audit trail of which
//     predicate clauses fired. Port: planned around the existing
//     internal trace tooling. Config carries InputPath and a control
//     filter.
//
//   - Fix — generate the canonical remediation diff for a finding
//     set. Port: [usecase.Fix] over the existing remediation
//     enricher. App orchestration: [internal/app/remediation].
//     Config carries Findings (the *Assessment) and an OutputDir.
//
//   - Bisect — narrow the snapshot range that introduced a finding.
//     Port: planned. Config carries HistoryDir, FindingID, and a
//     time range.
//
//   - Compare — diff two assessments. Port: planned. Config carries
//     two artifact paths.
//
//   - Diagnose — render the diagnostic side of evaluation (control
//     loading errors, schema rejections, snapshot validation).
//     Port: [usecase.Diagnose] (planned). Config carries the same
//     directories as Apply but never errors on partial load.
//
//   - Monitor — long-running watch over an evaluation directory.
//     Port: planned. Config carries Dir and an event handler.
//
// Every entry follows the same `Verb(ctx, cfg) (*Result, error)`
// shape — consumer code that knows one knows them all.
package stave

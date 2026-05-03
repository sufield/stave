package engine

// EvalVersion identifies the evaluation semantics the engine
// fingerprints under. Increment when evaluation behaviour changes
// (e.g. new operators, changed missing-field handling, coercion
// rules) — even if predicate syntax stays the same.
//
// The constant lives with the engine (not with the CEL adapter)
// because the engine emits it in FingerprintPolicy. Adapters
// implement controldef.PredicateEval with semantics that match
// this version; if a future adapter implements different semantics
// it would need its own version constant in its own fingerprint
// contribution.
//
// The value retains the historical "stave-cel/" prefix so
// existing fingerprint goldens stay stable — the migration is
// import-path-only.
const EvalVersion = "stave-cel/1.0"

// Package derive computes synthetic observation fields from the join of
// raw observations across asset kinds. It sits between observation
// loading and control evaluation: raw snapshots in, enriched snapshots
// out.
//
// Each derivation is a named, deterministic function so a finding that
// depends on a derived field traces back to
//
//	(raw observation A) + (raw observation B) + (explicit join rule) →
//	(derived field) → (control predicate).
//
// The package is intentionally concrete — one join function per real
// requirement, no Joiner interface or DSL — until a second derivation
// surfaces the shared shape. Premature abstraction here would bury the
// actual join logic.
//
// Invariants:
//   - Raw input snapshots are never mutated. Any asset that receives a
//     derived field is returned with a cloned Properties map.
//   - Derivations are idempotent: re-running the pipeline produces the
//     same output.
//   - Derivations are single-snapshot: a bucket in snapshot t1 joins
//     with Access Points in snapshot t1, not t0. Cross-snapshot joins
//     are a separate design question.
package derive

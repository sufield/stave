// Package cel provides a CEL-based predicate evaluator that serves as a
// parallel implementation alongside the existing predicate evaluation logic.
//
// The compiler translates ctrl.v1 UnsafePredicate structures into compiled
// CEL programs. The evaluator executes these programs against asset properties.
//
// This package is designed to run in parallel with the existing evaluator
// during migration, allowing result comparison before the old code is removed.
package cel

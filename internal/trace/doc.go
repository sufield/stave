// Package trace implements predicate evaluation tracing for debugging control
// matching.
//
// The tracing engine walks unsafe_predicate clause trees, recording each
// operator evaluation and its result. Output can be formatted as structured
// JSON or human-readable text via the respective formatters.
package trace

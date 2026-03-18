// Package trace defines the trace model (Node types, Result) and the
// tracing engine that walks unsafe_predicate clause trees against an
// EvalContext. Formatters in this package render traces as human-readable
// text or structured JSON via type-switch walkers — the Node interface
// is presentation-agnostic.
//
// App-layer orchestration (asset lookup, EvalContext wiring) lives in
// internal/app/trace.
package trace

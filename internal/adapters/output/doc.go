// Package output provides output adapters that format evaluation results for
// different consumers.
//
// The root package handles result enrichment and batch sanitization.
// Subpackages implement specific output formats: json (machine-readable),
// text (human-readable), sarif (SARIF 2.1.0 for CI integration),
// report (evaluation rendering), and enforcement (policy output).
package output

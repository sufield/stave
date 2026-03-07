// Package eval orchestrates the evaluation use case — the primary workflow
// that loads controls and observation snapshots, runs the domain evaluation
// engine, and writes findings to the configured output.
//
// [Run] is the main entry point. The package handles configuration assembly,
// pipeline step sequencing, control/asset filtering, dependency injection
// setup, and post-evaluation cleanup.
package eval

// Package cmd implements the Stave command-line interface using [cobra.Command].
//
// The production binary (stave) includes commands organized into four groups:
//
// Getting Started: init, generate
//
// Control Engine: validate, apply (--dry-run), diagnose, explain, verify
//
// Workflow & CI: ci (baseline/gate/fix-loop/diff/fix), snapshot, status
//
// Data & Artifacts: ingest, enforce, report
//
// Settings: config (get/set/show/delete/explain/context/env)
//
// The dev binary (stave-dev) adds a Developer Tools group:
//
// Developer Tools: doctor, bug-report, extractor, prompt, trace, controls,
// packs, graph, lint, fmt, docs, alias, schemas, capabilities, security-audit,
// version
//
// # Exit Codes
//
//   - 0: Success
//   - 1: Security-audit gating failure
//   - 2: Input error (invalid flags, parse failure)
//   - 3: Violations detected (apply command)
//   - 4: Internal error
//   - 130: Interrupted (SIGINT)
package cmd

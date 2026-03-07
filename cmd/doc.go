// Package cmd implements the Stave command-line interface using [cobra.Command].
//
// Commands are organized into five groups:
//
// Getting Started: doctor, demo, init, quickstart, generate
//
// Control Engine: validate, lint, fmt, apply, diagnose, verify, explain, trace
//
// Workflow & CI: snapshot, ci, plan, context, status, security-audit
//
// Data & Artifacts: ingest, controls, packs, enforce, extractor, graph, report
//
// Utilities & Help: docs, bug-report, capabilities, config, alias, prompt, fix, version, env, schemas
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

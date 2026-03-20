// Package cmd implements the Stave command-line interface using [cobra.Command].
//
// All commands ship in a single binary. [WireCommands] registers the full
// command tree organized into groups:
//
// Getting Started: init, generate
//
// Control Engine: validate, apply (--dry-run), diagnose, explain, trace, verify
//
// Remediation: prompt from-finding
//
// Workflow & CI: ci (baseline/gate/fix-loop/diff/fix), snapshot, status
//
// Data & Artifacts: enforce, report, controls, packs, lint, fmt
//
// Introspection: inspect (policy/acl/exposure/risk/compliance/aliases)
//
// Supportability: doctor, bug-report, graph, capabilities, schemas, version, docs
//
// Settings: config, alias, completion
//
// The dev edition binary (stave-dev) has identical commands but sets a
// different edition label, which activates the production guard when
// STAVE_ENV=production is detected.
//
// # Exit Codes
//
//   - 0: Success
//   - 2: Input error (invalid flags, parse failure)
//   - 3: Violations detected (apply command)
//   - 4: Internal error
//   - 130: Interrupted (SIGINT)
package cmd

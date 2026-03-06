// Package cmd implements the Stave command-line interface using Cobra.
//
// This package provides the CLI commands for Stave, handling argument parsing,
// validation, and orchestrating calls to the application layer.
//
// # Commands
//
// The package provides the following commands:
//
//   - [evaluateCmd]: Evaluate configuration snapshots for safety violations
//   - [capabilitiesCmd]: Print supported input types and version constraints
//   - [diagnoseCmd]: Diagnose evaluation inputs and results
//
// # Usage
//
//	stave apply [flags]
//
//	Flags:
//	  --controls string        Path to control definitions (default "controls/s3")
//	  --observations string      Path to observation snapshots (default "observations")
//	  --max-unsafe string        Maximum unsafe duration (default "168h")
//	  --now string               Override current time (RFC3339)
//	  --allow-unknown-input      Allow unknown source types
//
//	stave capabilities
//
//	stave diagnose [flags]
//
//	Flags:
//	  --controls string        Path to control definitions (default "controls/s3")
//	  --observations string      Path to observation snapshots (default "observations")
//	  --out string               Path to existing evaluate output JSON
//	  --max-unsafe string        Maximum unsafe duration (default "168h")
//	  --now string               Override current time (RFC3339)
//	  --format string            Output format: text or json
//
// # Exit Codes
//
// The CLI uses the following exit codes:
//
//   - 0: Success (no violations found)
//   - 2: Input error (invalid input, parse error, etc.)
//   - 3: Violations detected (evaluate command only)
//   - 4: Internal error
//   - 130: Interrupted (SIGINT)
//
// Use [ExitCode] to convert errors to appropriate exit codes.
package cmd

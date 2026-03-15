package cmd

const rootLongHelp = `Stave detects infrastructure assets that have remained unsafe for too long,
using only configuration snapshots-no cloud credentials required.
Output is deterministic when --now is set (required for reproducible CI/CD runs).

Getting Started:
  1. init       - Create a starter project layout
  2. status     - See what to run next in the workflow

Operational Workflow:
  1. validate   - Check inputs are well-formed (run first)
  2. apply      - Run control evaluation and produce findings
                  Use --dry-run to verify readiness first
  3. diagnose   - Understand unexpected results

Input Formats:
  --controls      Directory with YAML control definitions (ctrl.v1)
  --observations  Directory with JSON observation snapshots (obs.v0.1)

Output Formats:
  --format json   Machine-readable JSON on commands that support format selection
  --format text   Human-readable summary on commands that support format selection
  --output ...    Global fallback mode (prefer per-command --format)

Logging:
  -v              Increase verbosity (INFO level)
  -vv             Debug verbosity (DEBUG level)
  --log-level     Explicit level: debug|info|warn|error
  --log-format    Format: text|json (default: text)
  --log-file      Write logs to file instead of stderr
  --log-timestamps  Include timestamps (breaks determinism)
  --log-timings   Include timing information (breaks determinism)

Sharing:
  --sanitize     Sanitize infrastructure identifiers from output
  --path-mode    Path rendering: base (default, basenames only) or full (absolute paths)

Exit Codes:
  0   Success, no issues
  1   Security-audit gating failure
  2   Invalid input or validation failure
  3   Violations found (apply) or diagnostics found (diagnose)
  4   Unexpected internal error
  130 Interrupted (SIGINT/Ctrl+C)

Examples:
  # Step 1: Validate inputs
  stave validate --controls ./controls --observations ./obs

  # Step 2: Dry-run readiness checks
  stave apply --dry-run --controls ./controls --observations ./obs

  # Step 3: Apply with 7-day threshold
  stave apply --controls ./controls --observations ./obs --max-unsafe 7d

  # Step 4: Diagnose unexpected results
  stave diagnose --controls ./controls --observations ./obs

  # Verbose mode (INFO level logs to stderr)
  stave apply --controls ./controls --observations ./obs -v

  # Debug mode
  stave apply --controls ./controls --observations ./obs -vv

  # JSON logs to file
  stave apply --controls ./controls --observations ./obs --log-format json --log-file run.log

  # Sanitize identifiers for safe sharing
  stave apply --controls ./controls --observations ./obs --sanitize

Documentation: See docs/user-docs.md for detailed usage.`

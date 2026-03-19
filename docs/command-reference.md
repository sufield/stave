# Command Reference

Every command in the production (`stave`) and developer (`stave-dev`) binaries.

## Production Commands

### Setup

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `init` | Scaffold a new Stave project | Working directory | `controls/`, `observations/`, `stave.yaml`, `.gitignore` | Once, at the start of a new project |
| `generate` | Create starter control or observation files | `--type control\|observation` | YAML control or JSON observation file | When authoring a new control or creating test data |
| `status` | Show project state and next recommended command | `stave.yaml`, session state | Text summary with next command hint | After any command, to see what to do next |

### Data Preparation

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `validate` | Check that controls and observations are well-formed | `--controls` dir, `--observations` dir | Validation report (text or JSON) | Before `apply`, especially with extractor-produced observations |

> **Note:** Extraction is external to Stave. Use an extractor (any language) to produce `obs.v0.1` JSON from your data source. See [Building an Extractor](extractor-prompt.md).

### Evaluation

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `apply` | Run control evaluation against observations | `--controls` dir, `--observations` dir, `--max-unsafe` duration | Findings JSON, text, or SARIF (exit 0=clean, 3=violations) | Core command — every evaluation run |
| `apply --dry-run` | Check readiness without running evaluation | Same as `apply` | JSON readiness report (`ready: true/false`) | Before `apply` to verify inputs are complete |
| `apply --profile aws-s3` | Evaluate using bundled S3 controls | `--input` observations bundle file | Same as `apply` | When using built-in controls with a single observation file |
| `diagnose` | Root-cause guidance for unexpected results | `--controls` dir, `--observations` dir | Diagnostic report with signals and actions | After `apply` produces unexpected findings (or no findings) |
| `explain` | Show how a specific control evaluates | `--controls` dir | Control description, fields needed, evaluation logic | When understanding why a control matched |
| `verify` | Confirm a remediation resolved findings | `--before` eval JSON, `--after` eval JSON | Resolved/new/unchanged summary | After fixing infrastructure and re-running `apply` |

### CI/CD

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `ci baseline save` | Save current findings as accepted baseline | `--in` evaluation JSON | Baseline JSON file | When accepting the current posture as the starting point |
| `ci baseline check` | Check if new findings exist vs baseline | `--in` evaluation JSON, `--baseline` JSON | Pass/fail (exit 0 or 3) | In CI to check for new findings |
| `ci gate` | Pass/fail gate for pipelines | `--in` evaluation JSON, `--policy` | Pass/fail with policy details (exit 0 or 3) | In CI as a merge/deploy gate |
| `ci diff` | Compare two evaluations for regressions | `--before` JSON, `--after` JSON | New, resolved, unchanged findings | In CI to report posture changes |
| `ci fix` | Machine-readable fix plan for a finding | `--input` evaluation JSON, `--finding` ID | Fix plan with field changes and remediation | After `apply` to get actionable fix instructions |
| `ci fix-loop` | Apply-before, apply-after, verify in one command | `--before` dir, `--after` dir, `--controls` dir | Combined evaluation + verification | In CI for automated remediation verification |

### Remediation Artifacts

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `enforce` | Generate remediation templates from findings | `--input` evaluation JSON, `--mode terraform\|scp` | Terraform HCL or SCP JSON files | After `apply` to generate infrastructure fix code |
| `report` | Plain-text summary for stakeholders | `--in` evaluation JSON | Human-readable report | For auditors, management, or compliance documentation |

### Snapshot Lifecycle

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `snapshot plan` | Preview retention actions | `--observations-root` dir | Tier assignments and planned keep/prune/archive actions | Before pruning or archiving to review what will happen |
| `snapshot quality` | Check snapshot health | `--observations` dir | Staleness, cadence gaps, missing fields report | Regularly, to ensure observation data is fresh |
| `snapshot upcoming` | Snapshots approaching retention deadlines | `--controls` dir, `--observations` dir | Action items for at-risk snapshots | Weekly, to stay ahead of retention deadlines |
| `snapshot archive` | Move aged snapshots to cold storage | `--observations` dir, `--archive-dir` path | Moved files (dry-run by default) | Periodically, to keep observation directories fast |
| `snapshot hygiene` | Orphaned files and naming inconsistencies | `--controls` dir, `--observations` dir | Markdown hygiene report | During maintenance windows |
| `snapshot diff` | Compare two snapshots for drift | `--observations` dir (or `--before`/`--after` files) | Changed, added, removed fields per asset | When investigating configuration drift |
| `snapshot manifest` | Generate and sign integrity manifests | `--observations` dir | Manifest JSON with SHA-256 hashes | Before sharing snapshots or for audit chains |

### Settings

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `config show` | Show all effective config values and sources | `stave.yaml`, env vars, user config | Config table with value sources | To understand what config is active |
| `config get` | Read a single config key | Key name | Value | In scripts or to check a setting |
| `config set` | Update a project config value | Key name, value | Updated `stave.yaml` | When changing project defaults |
| `config delete` | Remove a config key (revert to default) | Key name | Updated `stave.yaml` | When reverting a setting |
| `config explain` | Explain resolution chain for all values | `stave.yaml`, env vars, user config | Same as `config show` (alias) | Same as `config show` |
| `config context create` | Create a named project context | `--dir`, optional `--controls`/`--observations` | Updated contexts store | When setting up multi-project workflows |
| `config context list` | Show all contexts | Contexts store | Context list with active marker | To see available contexts |
| `config context use` | Switch active context | Context name | Updated active context | When switching between projects |
| `config context show` | Show active context details | Contexts store | Context details | To verify which context is active |
| `config context delete` | Remove a context | Context name | Updated contexts store | When cleaning up unused contexts |
| `config env list` | List STAVE_* environment variables | Process environment | Variable table with values | To discover available env overrides |
| `completion` | Generate shell completion scripts | `bash\|zsh\|fish\|powershell` | Completion script to stdout | Once per shell setup |

## Developer Commands (stave-dev only)

### Control Authoring

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `controls list` | List control definitions | `--controls` dir or `--built-in` | Table of control IDs, names, types | When exploring available controls |
| `controls explain` | Show full control details | Control ID, `--controls` dir | Description, severity, compliance mappings, remediation | When understanding a control's logic |
| `controls aliases` | List semantic predicate aliases | None | Alias names | When authoring controls with predicate aliases |
| `controls alias-explain` | Explain what a predicate alias expands to | Alias name | Expanded predicate structure | When debugging alias-based controls |
| `packs list` | List available control packs | None | Pack names and versions | When choosing which packs to enable |
| `packs show` | Show pack metadata and controls | Pack name | Control count, version, paths | When inspecting a pack's contents |
| `lint` | Lint control YAML for design quality | `--controls` dir | Lint warnings and errors | During control authoring, in pre-commit hooks |
| `fmt` | Format controls deterministically | `--controls` dir | Formatted files (or `--check` for diff) | Before committing control changes |
| `graph` | Visualize control-to-asset relationships | `--controls` dir, `--observations` dir | Graph output (text, JSON, or DOT) | When analyzing control coverage |

### Debugging

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `trace` | Step-by-step predicate evaluation | `--controls` dir, `--control` ID, `--observation` file, `--asset-id` | Clause-by-clause PASS/FAIL tree | When a control produces unexpected results for one asset |
| `prompt` | Generate LLM prompt from evaluation results | Evaluation inputs | Markdown prompt with context | When using LLMs to analyze findings |

### Extractor Development

> Extraction is external to Stave. To build a custom extractor, see [Building an Extractor](extractor-prompt.md).

### Introspection

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `doctor` | Check local environment readiness | Local environment | PASS/WARN checks for tools, permissions, connectivity | After install, before first run, when troubleshooting |
| `schemas` | List all wire-format contract schemas | None | Schema catalog (data, diagnostic, command output, artifact) | When integrating Stave with external tools |
| `capabilities` | Show supported schemas, source types, packs | None | JSON with version constraints and capabilities | When checking what this build supports |
| `version` | Print version with optional verbose details | `--verbose` for schemas and lockfile | Version string, edition, schemas, project root | When filing issues or checking the installed build |

### Security Posture

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `security-audit` | Generate SBOM, vuln scan, compliance matrix | `--format`, `--fail-on`, `--out` | Security report JSON, SBOM, vulnerability scan | Quarterly audits, compliance evidence generation |
| `bug-report` | Collect sanitized diagnostic bundle | `--out` path | ZIP bundle with version, config, logs (sanitized) | When filing issues or requesting support |

### Productivity

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `alias set` | Create a command shortcut | Alias name, command string | Updated user config | When frequently running the same command |
| `alias list` | Show all defined aliases | User config | Alias table | To see available shortcuts |
| `alias delete` | Remove an alias | Alias name | Updated user config | When cleaning up unused aliases |
| `docs search` | Full-text search across local docs | Search query | Matching doc files with excerpts | When looking for documentation on a topic |
| `docs open` | Open a docs page by topic | Topic name | File path and summary | When navigating to a specific doc |

### Destructive Maintenance

| Command | Purpose | Input | Output | When to use |
|---|---|---|---|---|
| `snapshot prune` | Permanently delete old snapshots | `--observations` dir, `--older-than` duration | Deleted file list (dry-run by default, `--force` to delete) | Only in dev/sandbox environments with manual oversight |

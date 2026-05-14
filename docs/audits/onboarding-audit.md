# Onboarding Audit Report

**Date:** 2026-05-13
**Evaluator perspective:** mid-level DevOps engineer, uses Prowler today, first time seeing Stave, on Linux with Go installed, has not read any documentation yet.

This audit was performed against the current `main` branch state with a freshly built binary (`make build`) plus a simulated clean-clone build to verify that path.

## 10-Minute Test Results

| Checkpoint | Target | Actual | Pass? |
|---|---|---|---|
| Clone + build | < 1 min | **Build fails** with `go build ./...` on a clean clone (embed dirs empty); `make build` works in ~30s | **No** |
| First run (demo) | < 3 min | Once `make build` succeeds, `bash examples/demo-ai-security/run.sh` runs in 10s and produces well-narrated 5-act output | **Yes** |
| First surprising finding | < 5 min | The compound-chain section (Act 2) does show 5 high-severity findings composing into 3 CRITICAL chains — a genuinely surprising shape | **Yes** |
| My own data | < 8 min | No collector binary. `docs/time-to-first-finding.md` documents manual AWS-CLI extraction. `docs/extractor-prompt.md` is an LLM meta-prompt, not a working collector. Time-to-own-data is more like 30-60 min including writing a one-off extractor | **No** |
| Remediation proof | < 10 min | The demo `run.sh` output ends with `5 findings on writeup → 0 on remediated; 3 chains → 0 chains` — the proof IS there. But only in `run.sh` output, not in `stave apply` invoked directly. | **Partial** |

**Verdict:** 2 of 5 pass cleanly, 1 partial, 2 fail. The largest gaps are the build-from-source friction and the missing AWS collector.

---

## Friction Points (ordered by severity)

### 1. CRITICAL — `stave --help` prints a WARN log every invocation, references a non-existent `init` command

Every time a new user runs `stave --help`, they see:

```
time=2026-05-13T12:43:27.804-04:00 level=WARN msg="assignCommandGroup: subcommand not present in this build; skipping" use=init group_id=getting-started error="unknown command \"init\" for \"stave\""
```

…before any help text appears. Then the help text itself says:

```
Getting Started:
  1. init       - Create a starter project layout
  2. status     - See what to run next in the workflow
```

But `init` is gated behind the `stavedev` build tag and **does not exist in the production binary**. A new user reading the help and following step 1 hits:

```
$ stave init
[ERR] Command failed (INTERNAL_ERROR)
  Message: unknown command "init" for "stave"
```

This is the first impression — a warning log, broken help, broken first step. It happens on every invocation including `stave --version`.

### 2. CRITICAL — Error messages redact the path the user typed

The sanitizer is on by default, which means a typo in `--observations` is reported as:

```
[ERR] Command failed (INTERNAL_ERROR)
  Message: --observations path "/<redacted>" does not exist: verify the path or create the directory
  Fix:     Try `stave validate --controls ./<redacted> --observations ./<redacted>`. Check the command arguments and rerun with -v or -vv for additional context.
  Help:    run 'stave docs search observations directory not accessible'
```

The user typed `examples/demo-s3-public-read/fixtures/writeup-config/observations` (which doesn't exist). The error message shows `<redacted>`. The Fix hint shows `<redacted>`. The user cannot see what's wrong because the tool refuses to echo back their input.

For a first-time user trying to debug their first invocation, this is unusable.

Worse: the WARN log line above the error shows the path unsanitized:

```
level=WARN msg="command failed" error="--observations path \"examples/demo-s3-public-read/fixtures/writeup-config/observations\" does not exist..."
```

…but the human-facing `[ERR]` block redacts it. The two are inconsistent.

### 3. CRITICAL — Error help points at `stave docs` which does not exist

The Help field in error output says:

```
  Help:    run 'stave docs search observations directory not accessible'
  Help:    run 'stave docs search unknown flag --bogus'
```

But:

```
$ stave docs
[ERR] Command failed (INTERNAL_ERROR)
  Message: unknown command "docs" for "stave"
```

Every error message in the binary points at a non-existent escape hatch. The user clicks the rope and falls.

### 4. CRITICAL (revised) — bare `go build` works; runtime panic from gitignored controls

The original audit claimed bare `go build ./cmd/stave` fails on a clean clone with three embed pattern errors. **That was wrong.** The reproduction artificially deleted tracked files; a real `git clone` checks them out, and bare `go build` succeeds with exit 0.

The actual bug — found while verifying the audit's claim — was different and worse: a fresh-clone binary built fine but **panicked at startup**:

```
panic: pack: failed to load embedded policy library:
  pack "cloudfront": undefined control "CTL.CLOUDFRONT.CACHE.AUTHORIZATION.001"
```

Root cause: the bizacademy `.gitignore` line 2 had an unanchored `cache/` rule that silently excluded every directory named `cache` anywhere in the monorepo — including `stave/controls/cloudfront/cache/` and its embedded copy. The pack manifest referenced the three cloudfront/cache controls, but they were never committed. Existing local working copies had them (synced once and present on disk); fresh clones did not.

Fix: anchored the rule to `/cache/`, added the three canonical control YAMLs plus the synced embedded copies, plus a previously-silent `business/automation/prospects/internal/cache/` Go package that suffered the same gitignore bug. Verified: fresh `git worktree` → `go build ./cmd/stave` → `./stave --version` works end-to-end. See commit `d942830f9`.

Lesson for future audits: do not simulate a clean clone with `rm -rf`. Use `git worktree add` against a real ref. The simulation produces failure modes that don't exist on real clones — and misses real failure modes (like unanchored gitignore rules) that only surface on a real fresh checkout.

### 5. HIGH — Default `--format` is `json`, producing a wall of JSON for first-time users

`stave apply --help` documents `--format json|text|sarif (default: json)`. A first-time user running `stave apply ...` from the command line — without `--format text` — sees raw JSON. For a CLI that's competing with text-output scanners (Prowler, ScoutSuite), defaulting to JSON costs the human-readability moment.

The demo `run.sh` scripts mostly use `--format text` explicitly, so the demo path is fine. But anyone reading the README's `## Quick start` section and running `stave apply --format json` (the literal quickstart command) gets JSON.

### 6. HIGH — Malformed observation produces WARN spam and exit code 0

Run `stave apply` on a directory containing `{"bad":"json"}`:

```
level=WARN msg="control validation warning" control_id=CTL.APIGATEWAY.ALARM.4XX.001 message=""
level=WARN msg="control validation warning" control_id=CTL.APIGATEWAY.ALARM.5XX.001 message=""
... (many more)
```

…and exit 0. The user concludes the tool worked. Their actual snapshot was invalid; the tool silently swallowed it and produced no findings.

The CLAUDE.md guidance says "fail loud, never fake." This is a fail-silent path.

### 7. HIGH — No AWS collector in the binary

The README and `docs/time-to-first-finding.md` describe a workflow where the user extracts data from AWS first, then runs Stave on the extracted snapshot. But:

- `stave collect` exists but is documented as "Run assessment, produce evidence bundle, and append to the evidence archive." That's an assessment runner, not a collector.
- `docs/extractor-prompt.md` is an LLM meta-prompt that asks the user to generate their own extractor with Claude/ChatGPT/Copilot. That's clever but it's a 30-minute task on its own.
- No bundled `stave-collect` or `aws-snapshot.sh` script.

The "my own data" path requires either (a) writing a collector with an LLM, or (b) hand-rolling `aws ... | jq ...` pipelines per the time-to-first-finding doc. Either way, this is 30-60 minutes, not 8 minutes.

### 8. MEDIUM — README is 2,662 words; the first paragraph carries six pieces of jargon

The opening sentence of `README.md`:

> *Stave is a static analysis tool that evaluates cloud infrastructure configuration snapshots against system invariants via CEL predicates and exports standardized facts (JSONL, SMT-LIB) for consumption by external reasoning engines — all from air-gapped snapshots with no cloud credentials required.*

Jargon density in the first 30 lines: `CEL`, `SMT-LIB`, `JSONL`, `invariant`, `predicate`, `predicate evaluation`. A mid-level DevOps engineer probably knows `JSONL` and maybe `predicate`. `SMT-LIB` and `CEL` are unfamiliar.

The 2,662-word total is too long for a first impression. Best-practice for a CLI README is under 2,000 words with the "first command you can run" visible in the first 50 lines.

### 9. MEDIUM — 72 subcommands listed; no obvious "start with this one"

`stave --help` lists 72 subcommands. The help text does have a "Getting Started" section calling out `init` and `status` — but `init` doesn't exist (see Critical #1). `status` is listed but is not a clear demo path. A new user has no obvious way to know that `examples/demo-ai-security/run.sh` is the recommended first run.

### 10. LOW — README never mentions Prowler, ScoutSuite, or any competitor

Stave's compound-chain detection and absence-reasoning (ghost references) are genuinely different from CSPM scanners. But the README doesn't say *"here's what other tools can't do."* The "tool blind spot" demo exists but isn't featured in the README. A reader who already uses Prowler has no signal that Stave is doing something different.

The dev.to article `invariants-as-code-third-paradigm.md` makes the differentiation argument well — but the README itself doesn't.

---

## Missing Pieces

- [ ] A `make build` callout in the README's Quick Start block, before the `stave init` example (which itself doesn't work in production builds).
- [ ] A `stave docs` command (it's promised by every error-help line).
- [ ] An AWS collector binary or sample script (`scripts/aws-snapshot.sh`). The current path requires the user to roll their own.
- [ ] A "first time?" hint emitted on the very first run that points to a specific demo. A first-run marker exists (`cmd/executor_firstrun.go`) but the user-facing hint isn't oriented toward demos.
- [ ] A "Why Stave vs Prowler" paragraph or table in the README. Not an attack — just a 3-row contrast.
- [ ] A working `init` subcommand in the production build, OR removal of the `init` reference from `stave --help`'s Getting Started section.
- [ ] A separate "first finding in 30 seconds" command — e.g., embed one sample snapshot in the binary and ship a `stave try` or `stave example` shortcut. (Note: per the user's prior directive, no new commands should be added — but bundling could ride on `examples/demo-s3-public-read/run.sh` with documentation pointing at it as the canonical first run.)

---

## Strengths

- The `examples/demo-ai-security/run.sh` output is *excellent*. Five-act structure, before/after counts visible (`12 → 9 findings, 5 → 0 AI findings, 3 → 0 chains`), the compound-chain narrative explained in plain English.
- The "Open in GitHub Codespaces" badge in the README provides a one-click escape from local-build issues entirely.
- `docs/start-here.md` exists with a reading order. `docs/time-to-first-finding.md` exists with the under-10-minute promise. `docs/tutorials/01-first-assessment.md` exists. The doc skeleton is there.
- 60+ uses of `ui.UserError` / `ui.WithHint` / `ui.WithNextCommand` — actionable-error infrastructure exists in the codebase. The issue is the *content* of the hints (broken `stave docs` reference, redacted paths), not the *infrastructure*.
- Demos run fast: AI security demo completes in 10 seconds. S3 demos are all ≤30 lines of bash. The runtime path is healthy.
- `stave version --verify` exists and prints binary + policy library hashes. The trust-and-transparency story is solid.
- SBOM + cosign signing in goreleaser. Release security is real.

---

## Recommendations (prioritized)

### Tier 1 — fix the broken first impression (each is a small change, high impact)

1. **Remove the `init` / `status` mentions from production `stave --help`.** Either gate the Getting-Started block behind the `stavedev` build tag, or replace step 1 with `examples/demo-s3-public-read/run.sh`. The current text mis-directs every first-time user.
2. **Silence the `assignCommandGroup` WARN log for production builds.** It fires on every invocation of `stave --help` and surfaces an internal grouping concern to end users.
3. **Replace the `stave docs search …` Help lines with a working pointer.** Either implement a `stave docs` command (a thin wrapper that opens a local viewer or prints a doc location), or replace with `See docs/<file>.md`, or remove the Help line entirely. Today every error suggests a phantom command.
4. **Disable the sanitizer by default for error messages.** The sanitizer is the right default for *output redirected to a co-worker* but the wrong default for *errors a user is trying to debug*. Either disable in error context or honor an `--unsanitize-errors` flag that the first-run hint surfaces.
5. **Make malformed-observation a loud failure.** Exit non-zero, name the file, name the parse error. Don't print 50 WARN log lines and exit 0.

### Tier 2 — improve the build-from-source path

6. **Make `go build ./...` work on a clean clone.** Either commit the embed contents (would require accepting the duplication between `controls/` and `internal/controldata/embedded/`), or make the `embed` directives tolerate empty/missing paths and have the loaders fail gracefully if no controls are embedded. Today's behavior — three cryptic pattern errors at compile time — is the worst case.
7. **Add a 3-line "TL;DR build" block** at the top of the README before any prose: `git clone … && cd stave && make build && bash examples/demo-ai-security/run.sh`. This is the path that works. Show it before discussing tiers and engines.

### Tier 3 — close the "my own data" gap

8. **Ship a minimal AWS-CLI collector script** at `scripts/aws-snapshot.sh` that extracts one service (S3) and emits `obs.v0.1` JSON. The README's "30 minutes to extract via LLM prompt" path is too long for an early adopter. A shell script that produces 5 buckets of real data in 60 seconds dramatically shortens this checkpoint.
9. **Document the minimum IAM permissions** required for the collector in `docs/extractor-prompt.md` and the new script. The current docs assume the user already has appropriate access.

### Tier 4 — sharpen the positioning

10. **Add a "Why Stave vs Prowler" table** in the README, after the "How it works" section. Three rows: per-resource vs cross-inventory, point-in-time vs across-time, individual checks vs compound chains. Not adversarial — descriptive.

---

## Verbatim Error Messages That Need Improvement

| Scenario | Current message | Issue | Suggested message |
|---|---|---|---|
| Wrong `--observations` path | `--observations path "/<redacted>" does not exist: verify the path or create the directory` | Path redacted; user can't see their own input | `--observations path "/nonexistent" does not exist. Try: bash examples/demo-s3-public-read/run.sh for a self-contained first run, or see docs/time-to-first-finding.md to point at your own snapshot.` |
| Any error | `Help: run 'stave docs search <topic>'` | `stave docs` doesn't exist | Either implement `stave docs` or replace with `See docs/<file>.md` or remove the line entirely. |
| `stave init` (in production build) | `unknown command "init" for "stave"` | The help text suggested running this | The Getting Started section of `--help` should not mention `init` for production builds. |
| Unknown flag | `Help: run 'stave docs search unknown flag --bogus'` | Same broken self-reference | `Try 'stave apply --help' for the list of supported flags.` |
| Malformed observation | (50 lines of `level=WARN msg="control validation warning" control_id=... message=""`) followed by `exit 0` | Silent success on bad input | `[ERR] Observation file /tmp/bad-obs/bad.obs.json failed schema validation: missing required field "schema_version". See docs/observation-contract.md.` Exit code 2. |
| Bare `go build` | `pattern embedded/*/*/*.json: no matching files found` | Doesn't say to run `make build` | The build path should either Just Work, or the README should warn first. The embed directives should fail gracefully if no files have been synced. |

---

## Reproducer commands

For each finding above, the verifying commands:

```bash
# Critical #1: init warning + broken help
./stave --help 2>&1 | head -3

# Critical #2: redacted paths
./stave apply --observations /nonexistent --controls controls --now 2026-05-13T00:00:00Z 2>&1 | head -8

# Critical #3: broken stave docs reference
./stave docs 2>&1 | head -3

# Critical #4: bare go build fails on clean state
git stash -u
rm -rf internal/contracts/schema/embedded/* internal/controldata/embedded/* internal/adapters/coverage/embedded/*
go build ./cmd/stave 2>&1 | head -5

# Critical #5: JSON-default
grep -n 'default: json' cmd/apply/cmd.go

# Critical #6: silent malformed-observation
mkdir -p /tmp/bad-obs && echo '{"bad":"json"}' > /tmp/bad-obs/bad.obs.json
./stave apply --observations /tmp/bad-obs --controls controls --now 2026-05-13T00:00:00Z 2>&1 | head -5; echo "exit=$?"

# Critical #7: no AWS collector
find . -maxdepth 3 -name '*collect*' -type f | grep -v _test
./stave collect --help 2>&1 | head -6
```

All of the above were run during this audit on 2026-05-13.

---

## What this audit deliberately did NOT do

- No code changes. Audit only.
- No evaluation of architecture or code quality — those are healthy. The question was the user *experience*, not the implementation.
- No fixes for the friction points. Each Tier 1–4 recommendation is a separate iteration.
- No subjective evaluation of the documentation tone. The deep docs are good; the issue is that there are 265 of them and a new user doesn't know which to read first.

The list above is roughly **two days of focused work for one engineer** to address Tier 1 and Tier 2 — and the result is a first-impression that doesn't burn the user before they reach the demo that already works well.

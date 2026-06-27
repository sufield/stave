# Stave Verify — GitHub Action

Run Stave's deterministic security verification on every Pull Request: findings go to the
**GitHub Security tab** (SARIF), a **PR comment** summarizes them, and in strict mode the
**check fails** when violations are found.

> Iteration 0 (baseline) evaluates `obs.v0.1` **snapshots that already exist in the repo**.
> Verifying raw Terraform directly arrives with the Terraform→snapshot converter (next on the
> roadmap); see "Roadmap" below.

## Usage

```yaml
# .github/workflows/stave.yml
on:
  pull_request:
    paths: ["security/snapshots/**"]
permissions:
  contents: read
  security-events: write   # SARIF upload
  pull-requests: write     # PR comment
jobs:
  stave:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sufield/stave/.github/actions/stave-verify@main
        with:
          snapshot-path: security/snapshots
          strict: "true"
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `snapshot-path` | — (required) | Directory of `obs.v0.1` snapshot JSON files. |
| `pack` | `""` (full catalog) | Scope to a pack (`quick`, `entropy`). **Empty is the safe default** — a narrow pack can miss the controls relevant to a snapshot (e.g. `quick` excludes most IAM-escalation controls). |
| `controls` | `""` (built-in) | Path to a controls directory. |
| `strict` | `true` | Fail the check on any finding. |
| `sarif` | `true` | Emit SARIF and upload to the Security tab. |
| `comment` | `true` | Post a PR comment (pull_request events). |
| `now` | `""` | Override evaluation time (RFC3339) for deterministic runs. |
| `stave-binary` / `stave-version` | `""` / `latest` | Use a prebuilt binary, or download a release from `sufield/stave`. |

Outputs: `finding-count`, `status` (`pass`/`fail`).

## What it does

1. Resolves a `stave` binary (input path or release download).
2. Runs `stave apply -o <snapshot-path> [--pack …] --format json` (and `--format sarif`).
   - Stave emits **native SARIF 2.1.0** — no conversion. Each result carries the control ID as
     `ruleId`, severity as `level`, the resource ARN as a `logicalLocation`, and the
     `reasoning_trace` in properties. Validated GitHub-Security-tab compatible.
3. Uploads the SARIF (`github/codeql-action/upload-sarif`).
4. Posts/updates a PR comment:

   > ## 🛡️ Stave Security Verification — 31 findings
   > | Severity | Control | Resource | Issue |
   > |---|---|---|---|
   > | 🔴 Critical | `CTL.IAM.ESCALATE.ADDUSERTOGROUP.001` | `user/privesc13-…` | Principal Must Not Escalate via iam:AddUserToGroup |
   >
   > **These are deterministic violations, not suggestions** — re-run to reproduce.

5. In `strict` mode, fails the check (exit 1) when `finding-count > 0`.

## Exit-code note

`stave apply` returns **3** when violations are found — that's a *successful evaluation that
found problems*, not a tool error. The action treats exit 3 as success for running, then gates
on the finding count. Tool errors (exit 2/4) fail the step loudly.

## Why deterministic findings matter in CI

Every finding is a proven control failure (same snapshot → same result), so the gate is stable:
no flaky scanner, no LLM judgment, no sampling. A developer can reproduce any finding locally
with the identical `stave apply` command.

## Roadmap

- **Now:** verify committed snapshots (this action).
- **Next (the unlock):** Terraform plan-JSON → snapshot ingestion, so the action verifies *any*
  Terraform repo without pre-built snapshots, and maps findings to `.tf` file/line in SARIF.
- **Then:** LLM-explained inline review comments; auto-fix commits; trap-triplet regression CI.

## Local component test

The formatter and SARIF path are tested without a runner:
```bash
stave apply -o <snapshot> --format sarif    # 2.1.0, Security-tab ready
stave apply -o <snapshot> --format json | … # piped to stave_pr_report.py
python3 .github/actions/stave-verify/test_stave_pr_report.py   # formatter tests
```

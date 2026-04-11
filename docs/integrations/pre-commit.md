# Pre-Commit Hook

Block unsafe cloud configurations from being committed to version control.

The hook runs `stave apply` on staged observation, control, and YAML files.
If violations are found (exit code 3), the commit is blocked.

## Install

### Option A: Git hook (no dependencies)

```bash
cp contrib/hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Option B: pre-commit framework

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/sufield/stave
    rev: v1.0.0
    hooks:
      - id: stave-apply
```

Install:

```bash
pre-commit install
```

## Behavior

The hook:

1. **Skips** if `stave` is not in PATH (soft dependency)
2. **Skips** if no `controls/` directory or `stave.yaml` exists
3. **Skips** if no observation/control/YAML files are staged
4. **Runs** `stave apply --format text`
5. **Blocks** commit on exit code 3 (violations found)
6. **Allows** commit on exit code 2 (input issues — non-blocking by default)

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `STAVE_PRECOMMIT_PROFILE` | (none) | Compliance profile to evaluate (e.g., `hipaa`) |
| `STAVE_PRECOMMIT_STRICT` | `0` | Set to `1` to block on any stave error, not just violations |
| `STAVE_PRECOMMIT_SKIP` | `0` | Set to `1` to skip the hook entirely |

### Examples

```bash
# Evaluate against HIPAA profile
export STAVE_PRECOMMIT_PROFILE=hipaa

# Strict mode — block on input errors too
export STAVE_PRECOMMIT_STRICT=1

# Emergency bypass
STAVE_PRECOMMIT_SKIP=1 git commit -m "emergency fix"
```

## Output

When violations are detected:

```
stave: checking staged configuration files...

[critical] CTL.S3.PUBLIC.001 — No Public S3 Bucket Read
  Asset: production-assets
  Duration: 24h (OVERDUE, max 12h)

Exit code 3 — violations detected

stave: violations detected — commit blocked
  Fix the violations above, then try again.
  To skip: STAVE_PRECOMMIT_SKIP=1 git commit
```

When clean:

```
stave: checking staged configuration files...
stave: no violations found
```

## CI/CD

The same evaluation runs in CI without the hook wrapper:

```bash
# GitHub Actions / GitLab CI / any CI
stave apply --format text        # exit code 3 fails the step
stave apply --format sarif       # for GitHub Security tab
```

See [CI/CD Integration](../guides/02-running-in-ci-cd.md) for full
pipeline setup.

## Files

| Path | Description |
|---|---|
| `contrib/hooks/pre-commit` | Shell script for `.git/hooks/` |
| `.pre-commit-hooks.yaml` | Hook definition for pre-commit framework |

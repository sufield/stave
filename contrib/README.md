# contrib/

Community-contributed integration scripts for running Stave in external toolchains.

## atlantis/

**`stave-post-plan.sh`** -- Atlantis post-plan hook that evaluates a Terraform plan for safety violations before `atlantis apply`.

The script converts the plan JSON to `obs.v0.1` observations (extracting resources from all root and child modules), runs `stave apply` against them, and blocks the plan if violations are found (exit 3).

Configuration via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `STAVE_CONTROLS` | _(built-in catalog)_ | Path to custom controls directory |
| `STAVE_PROFILE` | _(none)_ | Compliance profile (e.g. `hipaa`, `soc2`) |
| `STAVE_MAX_UNSAFE` | `0s` | Max unsafe duration threshold |

Prerequisites: `stave` and `jq` on the Atlantis server PATH.

## hooks/

**`pre-commit`** -- Git pre-commit hook that blocks commits introducing unsafe configurations.

Runs `stave apply` when observation, control, or YAML files are staged. Blocks on exit 3 (violations found); passes through on other exit codes.

Install:

```bash
cp contrib/hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Configuration via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `STAVE_PRECOMMIT_PROFILE` | _(none)_ | Compliance profile |
| `STAVE_PRECOMMIT_STRICT` | `0` | Set to `1` to also block on input errors |
| `STAVE_PRECOMMIT_SKIP` | `0` | Set to `1` to skip the hook |

# Add Stave to Your CI Pipeline

The finding you just fixed? Make sure it never comes back. A CI gate
evaluates every change and **blocks the merge** when a control is
violated — so the unsafe state never reaches production.

> **Environment:** Both YAML blocks below install `stave` from source
> in the CI runner — they do NOT assume the Coder workspace. The
> workspace is for adopters' interactive work; CI runs ephemeral
> jobs and the `go install` step in each block puts `stave` on
> `$PATH` for the gate step that follows.

The pattern is two steps: produce an evaluation, then gate on it.

```bash
stave apply --observations ./obs/ --format json \
  --eval-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > evaluation.json
stave ci gate --policy fail_on_any_violation --in evaluation.json
```

`stave ci gate` returns exit code **3** when the policy fails, which
fails the CI step and blocks the merge. (`apply` itself also exits `3`
on violations, so a bare `stave apply` works as a gate too; `ci gate`
adds the graduated policies below.)

## GitHub Actions

```yaml
name: stave-gate
on: [pull_request]

jobs:
  evaluate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
      - name: Install Stave
        run: go install github.com/sufield/stave/cmd/stave@latest
      - name: Evaluate security invariants
        run: |
          stave apply --observations ./obs/ --format json \
            --eval-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > evaluation.json
      - name: Gate
        run: stave ci gate --policy fail_on_any_violation --in evaluation.json
```

## GitLab CI

```yaml
stave-gate:
  image: golang:1.26
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - go install github.com/sufield/stave/cmd/stave@latest
    - export PATH="$(go env GOPATH)/bin:$PATH"
    - stave apply --observations ./obs/ --format json
        --eval-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > evaluation.json
    - stave ci gate --policy fail_on_any_violation --in evaluation.json
```

> The `./obs/` snapshot is whatever your collection step produces (see
> [01-from-steampipe-to-stave.md](./01-from-steampipe-to-stave.md)). In
> IaC pipelines this is often a snapshot derived from the planned state.

## Graduated rollout

Don't start by blocking on day-one debt. Tighten the **policy** over
time — these are the real `ci gate` modes, not arbitrary thresholds:

```
Week 1   fail_on_new_violation        Block only NEW findings vs a committed
         --baseline baseline.json     baseline. Existing debt doesn't block.

Week 2   fail_on_overdue_upcoming     Block anything that has been unsafe longer
         --max-unsafe 168h            than the allowed duration (here, 1 week).

Week 4   fail_on_any_violation        Zero tolerance — any violation fails.
```

Capture the baseline once, commit it, and the gate fails only on
*regressions*:

```bash
stave apply --observations ./obs/ --format json > baseline.json   # commit this
stave ci gate --policy fail_on_new_violation --in evaluation.json --baseline baseline.json
```

> `--max-unsafe` is a **duration** (`168h`, `720h`, `0`), not a count —
> it expresses how long an unsafe state may persist before the
> `fail_on_overdue_upcoming` policy fails. `0` means zero tolerance.

## Why this compounds

The catalog grows with each incident you fix — every new control you
add (or that ships in an update) is **automatically enforced** by the
same gate. Organizational learning becomes machine-evaluable: a class
of mistake, once encoded as an invariant, can't silently return.

---

**Back to the start:** [02-first-evaluation.md](./02-first-evaluation.md)

# Coverage Policy

## Purpose

This project uses two coverage signals:

- Repository-wide coverage for visibility and trend tracking.
- Core package coverage gates to protect critical behavior.

Repository-wide coverage is reporting-oriented. Core coverage is enforced in CI.

## Core Packages (Enforced)

The following packages are required to meet minimum statement coverage on every PR and push to `main`:

- `./internal/app`: **>= 25%**
- `./internal/predicate`: **>= 40%**
- `./internal/domain`: **>= 70%**

The gate is implemented in `.github/workflows/coverage.yml` under
`Enforce core package coverage policy`.

## Reporting Scope

Codecov remains enabled for repo-level reporting and PR comments.

Current ignore list in `codecov.yml` excludes low-priority tooling paths:

- `testdata/**`
- `vendor/**`

## Deferred Coverage Areas

The following areas are intentionally not gated for now:

- CLI glue-only paths where behavior is already exercised via app/domain flows
- Non-critical output adapter formatting paths

## Threshold Ramp Plan

Coverage thresholds should increase only when stable tests are in place:

1. Phase 1 (current baseline gate): app 25, predicate 40, domain 70.
2. Phase 2: app 40, predicate 55, domain 70.
3. Phase 3: app 55, predicate 70, domain 75.
4. Phase 4: app 65, predicate 80, domain 80.

Raise thresholds only after PRs demonstrate sustained coverage above the next target.

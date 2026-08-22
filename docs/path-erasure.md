---
title: Path Erasure
description: Use Stave to identify erasable attack paths, verify they're gone, and measure progress over time.
---

# Path Erasure

## The idea

Every Stave finding names an attack path that can be erased from your configuration. Every chain finding names a compound path where erasing one leg eliminates the entire chain.

The workflow is subtractive: find the paths, delete them, verify they're gone, track progress. The goal is fewer findings over time — not more alerts, not more dashboards — fewer paths.

## The workflow

### 1. Detect

```bash
stave apply --observations snapshot.json --format json > assessments/2026-08.json
```

Each finding is an erasable path. Each chain is a compound path where multiple conditions stack to create an attack route that no single finding describes alone.

### 2. Delete

This is your action, not Stave's. Scope the role, remove the unused key, enforce IMDSv2, add the SCP condition — whatever the finding's remediation calls for.

For compound chains, erase any one leg. The chain breaks when any condition in the composition is resolved.

### 3. Verify

Run Stave again against a fresh snapshot:

```bash
stave apply --observations snapshot-after.json --format json > assessments/2026-08-post.json
```

The finding is gone. The path was erased. If the finding persists, the remediation didn't take — the configuration still has the property.

### 4. Trend

```bash
stave trend --history ./assessments/ --format json
```

Trend computes the trajectory across runs:

- **Resolved:** findings present in earlier runs, absent now — paths erased.
- **Persisted:** findings present across multiple runs — paths not yet addressed.
- **New:** findings appearing for the first time — new paths introduced.
- **Oscillating:** findings that disappear and reappear — paths re-opened after erasure.

Oscillation is the pattern to watch. A finding that disappears during a review cycle and reappears after means someone re-introduced the path. Trend catches this automatically — point-in-time reviews miss it because each review only sees the current state.

## Path Erasure Rate

PER is the metric that answers "how much progress have we made?"

```
PER = findings resolved / total findings at baseline
```

It starts at 0. It trends toward 1. Every increment represents a structurally erased attack path — not a closed alert, not a compliance checkbox, a path that no longer exists in the configuration.

For compound chains, a single erasure (one finding resolved) can eliminate an entire multi-resource attack path. The PER increment is 1, but the attacker optionality reduction is the full chain.

## Why erasure helps monitoring

Every path you erase from configuration is one less thing your monitoring tools have to watch. The GuardDuty alert that fired on the overprivileged role stops firing when the role is scoped. The CloudTrail anomaly from the unused access key stops appearing when the key is deleted.

Erasure doesn't replace monitoring. It reduces monitoring's workload to the paths that genuinely can't be prevented — the ones where detection is the right answer because architectural elimination isn't possible.

## Quick start

```bash
# Month 1 — baseline
stave apply --observations snapshot.json --format json > assessments/2026-07.json

# Remediate — scope roles, delete keys, enforce defaults

# Month 2 — verify + measure
stave apply --observations snapshot.json --format json > assessments/2026-08.json
stave trend --history ./assessments/ --format json

# Read the trend: what was erased, what persisted, what's new
```
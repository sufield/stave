---
title: "System Invariant as Code"
sidebar_label: "System Invariant as Code"
sidebar_position: 2
description: "What system invariant as code means in Stave, and how it differs from OPA, IaC scanners, and CSPM tools."
---

# System Invariant as Code

## Definition

System Invariant as Code means you define a small set of safety truths that must always hold for your system, then evaluate snapshots against those truths.

In Stave, a control is a YAML rule (for example: "PHI buckets are never public").
A finding is produced only when observed system state violates that rule.

## The Problem

Many teams have policy checks, scanners, and cloud dashboards, but still struggle to answer:

- Did this unsafe condition persist long enough to matter?
- Can we prove the same result from the same snapshot every time?
- Can we run this in air-gapped review environments with no cloud credentials?

Stave focuses on deterministic, offline proofs over local snapshots.

## Formal Model

Let:

- `S_t` be an observation snapshot at time `t`
- `I` be a control predicate over asset properties
- `U(r, t) = 1` when asset `r` is unsafe in snapshot `S_t` under `I`

For `unsafe_state`, a violation exists if `U(r, t_now) = 1`.

For `unsafe_duration`, a violation exists when:

- `U(r, t_now) = 1`
- and `(t_now - t_first_unsafe(r)) > threshold`

This is why Stave can express "unsafe now" and "unsafe for too long" as separate control types.

## Example: S3 PHI bucket must not be public

A simplified control:

```yaml
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: No Public S3 Buckets
description: S3 buckets with sensitive data must not be publicly readable or listable.
domain: exposure
scope_tags: [aws, s3]
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
    - field: properties.storage.visibility.public_list
      op: eq
      value: true
```

If either property is true in a snapshot, Stave emits a finding.

## Alternatives

| Approach | Primary input | Cloud credentials needed at evaluation time | Offline by default | What it proves | Typical lifecycle point |
|---|---|---|---|---|---|
| Policy-as-Code (OPA/Sentinel) | Config, admission requests, policy docs | Usually no for local checks; depends on integration | Often | Policy decision for a request/config | CI/CD gates, admission control |
| IaC scanners (tfsec/Checkov) | IaC source and plan artifacts | No | Yes | Static misconfiguration patterns in IaC | Pre-merge / CI scan |
| CSPM (Wiz/Prisma/etc.) | Live cloud APIs and graph inventory | Yes | No | Continuous posture and exposure in deployed cloud | Continuous monitoring |
| Stave | Local observation snapshots + control rules | No | Yes | Deterministic control violations over observed state and time windows | Offline preflight, audit evidence, reproducible investigations |

## When to use together

- Stave + OPA:
  Use OPA for request-time or pipeline gate policy decisions; use Stave to prove state controls over snapshots and time-based thresholds.
- Stave + CSPM:
  Use CSPM for continuous cloud detection; use Stave for offline, deterministic replay and preflight checks with no API access.

## How it differs from OPA / tfsec / CSPM

- OPA/Sentinel: general policy engines for decisions. Stave: control evaluation over snapshot history with deterministic findings.
- tfsec/Checkov: static IaC analysis. Stave: evaluation of normalized observed state snapshots.
- CSPM: live cloud visibility with credentials and API calls. Stave: offline evaluation with local files only.

## What Stave does not do

- It does not continuously crawl cloud APIs.
- It does not auto-remediate infrastructure.
- It does not execute plugins or untrusted code.
- It does not replace all policy engines or CSPM platforms.

## Developer Workflow

This workflow is for contributors and product engineers using Stave without changing Stave internals.

1. Prepare observations as `obs.v0.1` JSON snapshots in a local directory.
2. Prepare controls as `ctrl.v1` YAML files (for example under `controls/s3`).
3. Validate artifacts before evaluation:
   - `stave validate --controls <dir> --observations <dir>`
4. Run evaluation:
   - `stave apply --controls <dir> --observations <dir> --max-unsafe <duration>`
5. If results are unexpected, run diagnostics:
   - `stave diagnose --controls <dir> --observations <dir> [--previous-output <file>]`
6. Iterate on control definitions and input quality (not on Stave code) until outputs match expected safety intent.

## Responsibility Split

### Developers must do

- Define control intent in YAML (IDs, predicate logic, thresholds).
- Produce valid observation snapshots from approved sources.
- Choose runtime options (`--max-unsafe`, `--now`, allow unknown input policy).
- Review and act on violations/diagnostics.
- Version-control control definitions and snapshots as evidence artifacts.

### Stave provides out of the box

- Schema validation for control and observation contracts.
- Deterministic evaluation logic over snapshots and time windows.
- Built-in operator semantics (`eq`, `in`, `missing`, `any_match`, etc.).
- Standardized output structures (JSON/text flows with safety envelope validation where enabled).
- Diagnostics for common mismatch causes (threshold too high, insufficient span, reset behavior, clock skew).
- Offline operation (no cloud credentials required at evaluation time).

## What does NOT require changing Stave code

For normal adoption, teams should only change:

- Control YAML files
- Observation snapshot inputs
- CLI runtime flags

Teams should not need to modify:

- `pkg/alpha/domain` evaluator logic
- app use-case orchestration
- input/output adapters

If you need those code changes, treat it as platform extension work, not normal control authoring.

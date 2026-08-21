---
title: Access Exception Review
description: Detect when temporary IAM access becomes permanent — without spreadsheets, calendar reminders, or manual reviews.
---
NEEDS TO BE TESTED FIRST
# Access Exception Review

## The problem

A developer gets production access during an incident. The exception is approved, the work gets done, everyone moves on. Six months later, the access is still there.

The manual workflow looks like this: set an expiration date in a spreadsheet, assign an owner, schedule a review meeting, hope someone remembers to check. Multiply by hundreds of users and roles across dozens of accounts. The spreadsheet grows. The reviews slip. Temporary becomes permanent.

## What Stave checks

Stave evaluates IAM configuration properties that detect access exceptions mechanically, without relying on anyone remembering to review them.

**Dormant roles.** Roles that haven't been assumed within a threshold period. A vendor role granted during onboarding that was last used three months ago is a finding.

**Unused credentials.** IAM users with access keys that haven't been used. The developer who left but whose keys are still active.

**Overprivileged dormant roles.** The compound case — a role that is both dormant AND has broad permissions. This is the "exception that never expired" at its most dangerous: the access is unused but the blast radius is wide.

**Session duration.** Roles with maximum session durations longer than the task required. A 12-hour session duration on a role that was meant for a 30-minute incident response.

## The workflow

### 1. Monthly snapshot

Take a configuration snapshot and run Stave against it. Save the output:

```bash
stave apply --observations snapshot-august.json --format json > assessments/2026-08.json
```

### 2. Filter for access exceptions

Pull just the findings related to stale, dormant, or unused access:

```bash
jq '[.findings[] | select(.control_id | test("DORMANT|UNUSED|STALE|CREDENTIAL"))]' \
  assessments/2026-08.json
```

This is your access exception review list. Every item on it is a role or credential that exists, has permissions, and isn't being used. No manual inventory needed.

### 3. Trend across months

Feed a directory of chronological assessment outputs into `stave trend`:

```bash
# doctest:skip — requires pre-existing assessments directory with historical assessment outputs
stave trend --history ./assessments/ --format json
```

Trend computes:

- **Persisted findings.** Dormant last month, still dormant this month. This is temporary that became permanent.
- **New findings.** Appeared this month for the first time. Fresh exceptions to investigate.
- **Resolved findings.** Were in last month's output, gone this month. Somebody cleaned up.
- **Oscillating findings.** Disappear during review periods, reappear after. The gaming pattern that point-in-time reviews can't catch.

### 4. Act on what persisted

The review meeting changes from "let's go through the spreadsheet" to "here are the 12 findings that persisted from last month." The list is pre-filtered, evidence-backed, and diffed against the prior period. The conversation is about what to revoke, not what to find.

## What this replaces

| Manual process | Stave equivalent |
|---|---|
| Spreadsheet of temporary access grants | `stave apply` findings filtered by dormancy controls |
| Calendar reminder to review exceptions | `stave trend` run monthly — no reminder needed |
| Asking managers "is this still needed?" | Finding persisted across two runs — evidence says no |
| Quarterly access review meeting | Trend output IS the review — items are pre-identified |
| Hoping someone revokes expired access | Oscillation detection catches re-granted access |

## What this doesn't replace

Stave checks the configuration state. It tells you that a role is dormant and overprivileged. It doesn't:

- Revoke the access automatically (that's your IaC pipeline or manual action)
- Know why the exception was granted (that's your ticketing system)
- Approve or deny exceptions (that's your governance process)

The human decides what to do. Stave identifies what to decide about.

## Controls involved

The access exception review draws on these control families:

- **`CTL.IAM.VENDOR.DORMANT.001`** — vendor/external role unused beyond threshold
- **`CTL.IAM.VENDOR.OVERPRIVILEGED.001`** — vendor role with excessive permissions
- **`CTL.IAM.SESSION.DURATION.001`** — role session duration exceeds policy
- **`CTL.IAM.AGENT.SESSION.DURATION.001`** — agent-assumed role session duration
- **Credential lifecycle controls** — access key age, last-used date, rotation status

The compound chain `third_party_exposure_path` fires when a vendor role is dormant AND overprivileged AND lacks an external ID condition — three facts that individually seem routine but together create an unmonitored ingress path. That's the exception that became a vulnerability.

## Getting started

```bash
# doctest:skip — example assumes user-supplied snapshots and pre-existing assessments directory
# First run — establish a baseline
stave apply --observations snapshot.json --format json > assessments/$(date +%Y-%m).json

# Next month — run again
stave apply --observations snapshot-next.json --format json > assessments/$(date +%Y-%m).json

# Compare — what persisted?
stave trend --history ./assessments/ --format json
```

Two runs and a trend. The spreadsheet is retired.
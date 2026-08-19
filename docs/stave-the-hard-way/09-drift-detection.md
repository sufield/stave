# Lab 09 — Drift Detection

You fixed the MFA theater role. Three months later, someone updates the role's
session duration. The fix drifts. How do you catch that?

## Baseline and Gate

Establish a baseline after remediation:

```bash
stave ci baseline \
  --observations internal/fixtures/labs/mfa-authage/clean/ \
  --controls internal/controls \
  --eval-time 2026-08-19T14:00:00Z \
  --out baseline.json 2>/dev/null
```

This captures the current findings state. Now gate against it:

```bash
stave ci gate \
  --observations internal/fixtures/labs/mfa-authage/clean/ \
  --controls internal/controls \
  --eval-time 2026-08-19T14:00:00Z \
  --baseline baseline.json 2>/dev/null
echo "Exit code: $?"
```

Exit 0 — no new findings relative to the baseline.

## Detecting Drift

Now run the gate against a drifted state (the bad fixture):

```bash
stave ci diff \
  --before internal/fixtures/labs/mfa-authage/clean/ \
  --after internal/fixtures/labs/mfa-authage/bad/ \
  --controls internal/controls \
  --eval-time 2026-08-19T14:00:00Z 2>/dev/null \
  | jq '.summary'
```

The diff reports a new finding — `has_multifactor_auth_age` changed from
`true` back to `false`. The drift is caught.

## Bisect — When Did It Change?

When you have a snapshot archive (timestamped observations over weeks or
months), `stave bisect` binary-searches to the exact point the property
changed:

```bash
stave bisect \
  --control-id CTL.IAM.TRUST.MFA.AUTHAGE.001 \
  --observations <snapshot-archive>/ \
  --controls internal/controls
```

Like `git bisect` for commits — O(log N) to find the transition from
compliant to non-compliant.

## The CI/CD Pattern

In a pipeline:

1. `stave ci baseline` — capture known state after remediation
2. On every deploy: `stave ci gate --baseline baseline.json`
3. Exit 0 = no drift. Non-zero = new findings since baseline.
4. On failure: `stave ci diff` to see exactly what changed.

Security is a continuous property, not a one-time check. The pipeline
catches day one. Stave catches day two through day N.

## Verify

Run the `stave ci diff` command above. Confirm it reports the AUTHAGE.001
finding as newly introduced.

Next: [Lab 10 — Continuous Verification](10-continuous-verification.md)

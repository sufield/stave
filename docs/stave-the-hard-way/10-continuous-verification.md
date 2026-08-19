# Lab 10 — Continuous Verification

Putting it all together.

## The Full Loop

```
collect → transform → apply → triage → fix → check → repeat
```

1. **Collect**: capture raw AWS CLI output (`aws iam get-role`, etc.)
2. **Transform**: `stave transform --in raw/` → obs.v0.1 observations
3. **Apply**: `stave apply --observations obs/ --format json` → findings
4. **Triage**: read findings, prioritize by severity and chain membership
5. **Fix**: follow `remediation.action`, apply the change
6. **Check**: `stave check --before obs/ --after obs-fixed/` → verify
7. **Repeat**: new snapshot, `stave ci gate --baseline baseline.json`

## In CI/CD

```yaml
# GitHub Actions example
- name: Evaluate
  run: |
    stave apply \
      --observations observations/ \
      --eval-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
      --format json > results.json

- name: Gate
  run: |
    stave ci gate \
      --baseline baseline.json \
      --observations observations/
```

Exit 0 means no new violations. Non-zero blocks the deploy.

## What You Built

Over ten labs, you:

- Read an observation (Lab 02)
- Understood a security property (Lab 03)
- Traced a predicate evaluation (Lab 04)
- Proved a control catches the bad state (Lab 05)
- Read the proof in a finding (Lab 06)
- Saw two properties compose into a compound finding (Lab 07)
- Fixed a violation and proved the fix worked (Lab 08)
- Detected drift from the fixed state (Lab 09)
- Wired it into continuous verification (Lab 10)

The MFA Theater finding was discovered by a pen tester. That pen tester
checks once. Stave checks 4,761 properties across every role in every
account, every time. That is the difference between a finding and a
guarantee.

## Where to Go Next

- [Appendix A](appendix/A-collector-contract.md) — the collector contract
- [Appendix B](appendix/B-sensitive-actions.md) — sensitive action classification
- [Appendix C](appendix/C-asset-types.md) — asset types
- [Stave documentation](https://www.systeminvariant.dev/docs)
- [Control catalog](https://www.systeminvariant.dev/docs/reference/control-catalog)

## Verify

Run the full loop yourself: apply against the bad fixture, read the finding,
apply against the clean fixture, verify with `stave check`. The proof is in
the output.

# Time Travel

Why "evaluate, not guess" is the correct framing for security investigation.

---

## The Problem with Log Reconstruction

When a security incident occurs, the standard investigation approach is log reconstruction: correlate CloudTrail events, VPC flow logs, Config timeline entries, and access logs to reconstruct what happened.

This approach has three fundamental problems:

1. **Logs are incomplete.** An attacker who disables CloudTrail before operating leaves no record of subsequent actions. Log-based reconstruction only works if the attacker did not tamper with the logs.

2. **Logs describe events, not state.** CloudTrail tells you that someone called `PutBucketAcl`. It does not tell you what the complete bucket configuration was at that moment. Reconstructing state from a sequence of mutation events requires processing every event in order — and knowing the initial state.

3. **Logs are not evaluable.** You cannot run a security assessment against a CloudTrail log. The assessment engine needs structured configuration data, not a stream of API call records.

## Evaluate, Not Guess

With Stave snapshots in git, investigation is not reconstruction — it is re-evaluation.

The snapshot from March 14 contains the complete configuration state of every observed asset on March 14. Running `stave apply` against that snapshot produces the exact assessment that would have been produced on March 14. The evaluation is deterministic.

This means:
- You know exactly which controls were passing and failing on any given day
- You can diff two days to see exactly which properties changed
- You can bisect a date range to find the exact snapshot where a violation first appeared
- The evidence is immutable in git history — it cannot be tampered with retroactively

## The Git Bisect Analogy

`stave bisect` works like `git bisect`. Given a range of snapshots where the violation was absent at the start and present at the end, bisect evaluates the midpoint and narrows the window until it finds the exact transition.

The difference from `git bisect` on source code: here you are bisecting *infrastructure configuration* over *time*. The "good" state is a snapshot where the control passes. The "bad" state is where it fails. The bisect result tells you the exact day the misconfiguration appeared.

Combined with `git log` on the snapshot repository, you can correlate the configuration change with the deployment that introduced it.

## Why This Matters for Audit Evidence

An auditor asking "was encryption enabled on this database during Q1?" has two possible answers:

1. "Our policy says encryption must be enabled, and we have no record of it being disabled." This is assertion.

2. "Here are 90 daily snapshots from Q1 showing the encryption property was true on every day. Here is the stave apply output for each snapshot proving no violation was detected. The snapshots are signed and their hashes are in the evidence archive manifest." This is evidence.

Stave produces evidence, not assertion.

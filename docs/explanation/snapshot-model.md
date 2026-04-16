# The Snapshot Model

Why Stave evaluates local files rather than querying live cloud APIs.

---

## The Air-Gap Constraint

Stave was designed for environments where the evaluation engine cannot reach the infrastructure it evaluates. Classified networks, regulated healthcare environments, financial institutions with strict network segmentation — these are real deployment contexts, not edge cases.

The constraint is not "we prefer offline operation." The constraint is "the machine running the assessment has no network path to the cloud API."

Every architectural decision follows from this constraint.

## Snapshots Are Files

A snapshot is a JSON file containing asset observations captured at a specific point in time. It is produced by an extractor (a Steampipe query, an AWS CLI script, a native collector) that runs *in the environment with API access* and outputs a file.

The file is then transferred to the assessment environment — via secure file transfer, USB in a SCIF, git push, or whatever mechanism the organization uses for cross-boundary data movement.

The assessment engine reads the file. It never reads from a cloud API.

## Files Go in Git

Because snapshots are files, they can be committed to git. This is the foundation of time travel.

A git repository of daily snapshots is a complete history of infrastructure configuration. Running `stave apply` against a snapshot from 90 days ago produces the exact assessment that would have been produced 90 days ago. The evaluation is deterministic — same input, same engine, same result.

No other CSPM tool can do this. Cloud-connected tools query live state — they cannot evaluate historical state because the API returns current configuration, not past configuration. CloudTrail tells you what changed; a snapshot tells you what the state was.

## The Trade-Off

Snapshots are point-in-time observations, not continuous streams. A daily snapshot does not capture a misconfiguration that existed for 2 hours between snapshots.

This is an acceptable trade-off for the capabilities it enables:
- Offline evaluation in air-gapped environments
- Time travel via git history
- Deterministic, reproducible assessments
- Evidence archives with tamper-evident integrity
- No credential management for cloud API access on the assessment host

The alternative — continuous API polling — requires persistent credentials, network connectivity, and produces non-reproducible results (the API state changes between queries).

## Why This Matters for Incident Investigation

When a security incident occurs, the first question is "what was the state of the infrastructure when the breach happened?" With log-based reconstruction, this requires correlating CloudTrail events, Config snapshots, and VPC flow logs — and hoping the attacker did not delete the logs.

With Stave snapshots in git, the answer is `git checkout <date> && stave apply`. The snapshot is immutable in git history. The assessment is deterministic. The evidence is reproducible.

# Scorecard Instructions

## How to Fill In

1. Copy `template.csv`
2. Rename the `tool_a`, `tool_b`, `tool_c` columns to your tool names
3. Run each tool against the SadCloud environment
4. For each ground truth entry, check if the tool produced a matching finding
5. Enter the result: FOUND, MISSED, PARTIAL, or N/A

## Values

| Value | Meaning |
|---|---|
| FOUND | Tool produced a finding that matches this ground truth entry |
| MISSED | Tool did not detect this misconfiguration |
| PARTIAL | Tool found something related but not equivalent |
| N/A | Tool does not claim to cover this service |

## Scoring

**Atomic score:** count FOUND entries out of 30.
**Compound score:** count FOUND entries out of 5.
**Total score:** count FOUND entries out of 35.

PARTIAL counts as 0.5 for scoring purposes, but the distinction matters
more than the number — a PARTIAL tells you where a tool has coverage
gaps within a service it claims to support.

## Mapping Tool Findings to Ground Truth

Most tools use different names for the same misconfiguration. To map:

1. Export your tool's findings as CSV or JSON
2. For each ground truth entry, search the tool's output by:
   - Service name (S3, IAM, CloudTrail, etc.)
   - Resource identifier (bucket name, role name, trail name)
   - Finding description keywords
3. If the tool's finding describes the same problem on the same
   resource, mark FOUND

When in doubt, use the `verification` field in `ground-truth/atomic.yaml`
to manually confirm whether the tool's finding matches.

## Tips

- Run all tools on the same day against the same deployment
- Use the same SadCloud Terraform version for all runs
- Some tools require an agent; others scan remotely. Both are valid.
- Record your tool version and scan date in the CSV header

# Tutorial: Discovering Attack Chains

This tutorial walks through running chain discovery on a
snapshot to find every privilege escalation and data
exfiltration path.

## Prerequisites

- Stave built (`cd stave && make build`)
- Soufflé installed (`souffle --version` returns v2.4+)
- A snapshot directory with observations in `obs.v0.1` format

The snapshot must contain raw IAM policy data — specifically
`trust_policy_json` and `policies_json` fields on IAM role
assets. Without these, the SIR projectors cannot emit the
access-graph edges that the Datalog engine traverses.

## Step 1: Export SIR Facts

The chain discovery engine operates on Structured Intermediate
Representation (SIR) facts — relationship triples extracted
from your snapshot by 21 projectors in
`internal/core/sirfacts/facts.go`.

```bash
./stave export-sir \
  --controls controls \
  --observations ./my-snapshot/ \
  --eval-time 2026-01-15T00:00:00Z \
  --format jsonl > /tmp/facts.jsonl
```

This produces a JSONL file with one triple per line:

```json
{"subject": "arn:aws:iam::123456789012:role/DevRole", "predicate": "can_assume", "object": "arn:aws:iam::123456789012:role/ProdRole"}
{"subject": "arn:aws:iam::123456789012:role/ProdRole", "predicate": "has_action", "object": "s3:*"}
{"subject": "arn:aws:iam::123456789012:role/ProdRole", "predicate": "has_resource", "object": "arn:aws:s3:::production-data/*"}
```

## Step 2: Run Chain Discovery

From the `stave/` directory:

```bash
make chain-discover ARGS="-snapshot ./my-snapshot/"
```

Or with pre-exported JSONL:

```bash
make chain-discover ARGS="-jsonl /tmp/facts.jsonl"
```

The engine:
1. Exports SIR facts (or uses supplied JSONL)
2. Splits JSONL into per-predicate TSV files via `extract.go`
3. Runs Soufflé with the discovery rules (`discovery.dl`)
4. Parses the output relations (paths, classifications)
5. Deduplicates against the 622 known chain patterns
6. Produces the report

## Step 3: Read the Report

```
CHAIN DISCOVERY

DATALOG EVALUATION:
  privesc_path:              42
  access_path:               387
  escalation_path:           8
  exfil_path:                2
  external_reach:            3
  confused_deputy_path:      1
  path_condition:            15

CLASSIFICATION:  14 total paths
  escalation:                8
  exfiltration:              2
  external-reach:            3
  confused-deputy:           1

DEDUPLICATION:  3 novel, 11 confirmed
```

### Novel Chains

These are the discoveries — paths that exist in your account
but aren't covered by any of the 622 known chain patterns:

```
NOVEL CHAINS (not covered by existing YAMLs):

CHAIN 1: escalation (3 hops)
  Source:   DevRole
  Target:   ProdAdminRole
  Path:     DevRole → DataSciRole → ProdAdminRole

CHAIN 2: exfiltration (2 hops)
  Source:   CognitoAuthRole
  Target:   arn:aws:s3:::customer-data/*
  Via:      DataExportRole
  Path:     CognitoAuthRole → DataExportRole → arn:aws:s3:::customer-data/*
```

### Confirmed Chains

These validate that known patterns exist in your account:

```
CONFIRMED CHAINS: 11 paths match existing chain patterns
  escalation:                8
  exfiltration:              2
  confused-deputy:           1
```

## Step 4: Focus on Specific Query Types

```bash
# Only escalation paths (privilege increase)
make chain-discover ARGS="-snapshot ./my-snapshot/ -query escalation"

# Only data exfiltration paths
make chain-discover ARGS="-snapshot ./my-snapshot/ -query exfil"

# Only external-to-internal reach
make chain-discover ARGS="-snapshot ./my-snapshot/ -query external"

# Only confused deputy paths
make chain-discover ARGS="-snapshot ./my-snapshot/ -query confused-deputy"

# Only novel chains (skip confirmed)
make chain-discover ARGS="-snapshot ./my-snapshot/ -novel-only"

# Limit path depth
make chain-discover ARGS="-snapshot ./my-snapshot/ -max-hops 3"
```

## Step 5: JSON Output for Integration

```bash
make chain-discover ARGS="-snapshot ./my-snapshot/ -json" > chains.json
```

The JSON output structure:

```json
{
  "counts": {
    "privesc_path": 42,
    "access_path": 387,
    "escalation_path": 8,
    "exfil_path": 2,
    "external_reach": 3,
    "confused_deputy_path": 1
  },
  "novel": [
    {
      "category": "escalation",
      "source": "arn:aws:iam::123456789012:role/DevRole",
      "target": "arn:aws:iam::123456789012:role/ProdAdminRole",
      "hops": 3,
      "path": ["DevRole", "DataSciRole", "ProdAdminRole"]
    }
  ],
  "confirmed": [...],
  "total": 14
}
```

## Common Patterns Chain Discovery Finds

| Pattern | What It Means | Typical Fix |
|---------|--------------|-------------|
| Role A → Role B → sensitive resource | Transitive trust allows unexpected access | Tighten Role B's trust policy |
| Lambda → overpermissioned execution role → S3 | Lambda is a pivot point | Scope the execution role |
| Cognito → assumed role → PassRole → production | Self-registration leads to production | Remove PassRole from Cognito-assumed roles |
| External account → cross-account role → internal data | Cross-account trust is too broad | Add org ID or source account conditions |
| Service principal → role (no source condition) → data | Confused deputy via service trust | Add `aws:SourceArn` condition |

## How Chain Discovery Differs from Per-Resource Controls

Per-resource controls check individual configurations:
"Is this S3 bucket encrypted?" "Does this role have wildcard
permissions?" "Is this security group too broad?"

Chain discovery checks relationships between resources:
"Can a Cognito user reach production S3 data through a three-hop
trust chain involving a Lambda function and a SageMaker role?"

Both are necessary. Per-resource controls catch individual
misconfigurations. Chain discovery catches compound risks where
every individual configuration looks acceptable but the
combination creates an attack path.

```
Per-resource: DevRole is not overpermissioned         PASS
Per-resource: ProdRole is not overpermissioned         PASS
Per-resource: S3 bucket is encrypted                   PASS
Chain:        DevRole → ProdRole → S3 production data  FAIL
```

All three resources pass individual checks. The chain between
them fails. This is the gap that chain discovery closes.

## Troubleshooting

**All zeros in the report:**

The observation snapshots are missing the raw IAM policy fields.
Check which SIR predicates are being emitted:

```bash
./stave export-sir \
  --controls controls \
  --observations ./my-snapshot/ \
  --eval-time 2026-01-15T00:00:00Z \
  --format jsonl | jq -r '.predicate' | sort | uniq -c | sort -rn | head -20
```

Look for `can_assume`, `has_action`, `has_resource`, `trusts_service`.
If missing, the observation JSON needs:
- `properties.identity.trust_policy_json` — raw trust policy JSON string
- `properties.identity.policies_json` — raw identity policy JSON string

See `reasoning/souffle/discovery/LIVE-VALIDATION.md` for a
complete runbook to create test data from a live AWS account.

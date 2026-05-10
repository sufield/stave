# EC2 IMDS SSRF Chain — Multi-Engine Analysis

## Scenario

An attacker exploits an SSRF vulnerability in an application running
on an EC2 instance to query the instance metadata service
(`169.254.169.254/latest/meta-data/iam/security-credentials/<role>`).
Because the instance still permits IMDSv1, a single HTTP GET — no
PUT-token round-trip — returns short-lived AWS credentials for the
instance's IAM role. The role is over-privileged. The IMDS hop limit
is greater than 1, so a containerized workload (Docker, ECS-on-EC2)
on the instance can also reach the metadata service through the
extra hop. Capital One's $190M breach was this exact pattern.

```
attacker SSRF on EC2-hosted application
    │
    ▼
GET 169.254.169.254/latest/meta-data/iam/security-credentials/<role>
    │   (IMDSv1 — no token round-trip required)
    ▼
short-lived AWS credentials for the instance role
    │
    ▼
hop_limit > 1: containers on the instance can also reach IMDS
    │
    ▼
exfiltration to attacker infrastructure / lateral access
```

## Chain composition

`chains/ec2_imds_container_escalation.yaml` (threshold=2, severity=high)
composes three controls:

| Member | Asset | Predicate signal |
|---|---|---|
| `CTL.EC2.IMDSV2.001` | EC2 instance | `compute.network.imdsv2_required == false` |
| `CTL.EC2.IMDSV2.002` | EC2 instance | imdsv2_required AND container reaches IMDS via host or bridge+hop>1 |
| `CTL.EC2.IMDS.HOPLIMIT.001` | EC2 instance | `compute.ec2.imds_hop_limit_excessive == true` |

`IMDSV2.001` and `IMDSV2.002` are mutually exclusive on a single asset
(`imdsv2_required` is either `false` or `true`). The chain's threshold
of 2 is met by either pair:
- `{IMDSV2.001, HOPLIMIT.001}` — IMDSv1-still-allowed pattern
  (this fixture; Capital One pattern)
- `{IMDSV2.002, HOPLIMIT.001}` — IMDSv2-but-containers-bypass pattern
  (separate fixture, not shipped here — historical weight is on the
  IMDSv1 pattern)

## Engine results — writeup-config

| Engine | Verdict | Detail |
|---|---|---|
| **Stave CEL** (`stave apply`) | 2 EC2 findings + 1 chain | `IMDSV2.001`, `IMDS.HOPLIMIT.001`; chain `ec2_imds_container_escalation` (severity: high) |
| **Stave SIR JSONL export** | ~5,200 facts | `stave export-sir --format jsonl` — predicates + closed-world axioms |
| **Stave SIR SMT-LIB v2 export** | ~21,000 lines | declared predicates + closed-world axioms ready for SMT consumers |
| **Encoding verifier** (`examples/explain/verify_encoding.py --strict`) | ✅ verifiable facts match observations | each emitted IMDS fact traces to a property path in the writeup observation |
| **Prism risk model** | empty — no modeled shape applies | the engine catalog covers cognito_unauth / self_reg / multi_hop_chain / overperm_compute / wildcard_resource. **EC2 IMDS SSRF is not yet a modeled shape — engine-rule expansion backlog.** |
| **Game-theory cost model** | empty — no attack paths under modeled shapes | same reason as prism — **engine-rule expansion backlog.** |
| **Z3** | not run | no `query.smt2` for the IMDS chain yet; the SMT2 fact base is exported and ready for one. **Engine-rule expansion backlog.** |
| **Clingo / Soufflé / PySAT / Prolog** | not run | binaries available in the Codespaces devcontainer; the JSONL fact base is consumable as-is. **Engine-rule expansion backlog.** |

## Engine results — remediated-config

| Engine | Verdict | Detail |
|---|---|---|
| **Stave CEL** (`stave apply`) | 0 EC2 findings, 0 chains | `imdsv2_required: true` and `imds_hop_limit_excessive: false` flip both chain members |
| **Stave SIR JSONL export** | identical fact-base shape, boolean facts flipped | `has_imdsv2_required → true`, `has_imds_hop_limit_excessive → false` |

## What this scenario demonstrates

For early adopters running EC2 workloads — especially ones that
co-host containers (Docker on EC2, ECS-on-EC2, Kubernetes
self-managed):

1. **IMDSv2 must be required** (`HttpTokens: required` on the
   instance's metadata options). Without it, a single SSRF round
   trip returns role credentials. `CTL.EC2.IMDSV2.001` fires.
2. **The IMDS hop limit must be 1.** Higher hop limits mean
   containers running on the instance — the same instance role's
   blast radius — can also fetch credentials. `CTL.EC2.IMDS.HOPLIMIT.001`
   fires when the limit is excessive.
3. **The chain composes** when both signals fire on the same
   instance. The compound verdict is what an operator should react
   to first; individual findings are useful for triage but the
   chain says "credential theft is one HTTP request away."

## Capital One context

The 2019 Capital One breach exfiltrated 100M+ records via:
1. SSRF in a misconfigured WAF on an EC2 instance.
2. The SSRF retrieved credentials from IMDS (IMDSv1 was the only
   option at the time — IMDSv2 didn't exist).
3. The instance role had `s3:ListBucket` and `s3:GetObject` on
   the breached buckets.
4. The attacker enumerated and downloaded the data using the
   stolen role.

This fixture stages the same pattern with current Stave controls:
`IMDSV2.001` would have detected the missing IMDSv2 requirement;
`IMDS.HOPLIMIT.001` would have detected the hop-limit gap if
the fleet ran containers; together they fire the chain.

## How to adapt to your EC2 fleet

```bash
# 1. Export your EC2 instance metadata + instance profile observations
#    (ec2:DescribeInstances + iam:GetRole)

# 2. Run stave apply to detect the chain
stave apply --observations <your-obs-dir> --format json \
  | jq '.chain_findings[] | select(.chain_id == "ec2_imds_container_escalation")'

# 3. Export the SIR fact base for richer reasoning
stave export-sir --format jsonl --observations <your-obs-dir> > facts.jsonl

# 4. (Optional) once an EC2-IMDS shape rule is added to prism /
#    game-theory / clingo / pysat, those engines consume the same
#    facts.jsonl without re-running stave.
```

## Engine-rule expansion backlog

The empty cells above are missing rules in external engines, not
gaps in the chain catalog or fact projection:

- `examples/prism-risk-prioritization/risk_model.py` — add an
  `ec2_imds_credential_theft` shape that scores P(exploitation) given
  `imdsv1_allowed`, `imds_hop_excessive`, and `instance_profile_present`
  facts.
- `examples/game-theory-cost/cost_model.py` — same shape, attacker-cost
  ranking.
- `examples/z3-ec2-imds-credential-theft/` (new) — `query.smt2`
  asserting the chain conditions and asking Z3 for `sat` (witness model)
  / `unsat` (provably safe).
- `examples/clingo-constraints/constraints.lp` — extend with a
  `violation(I, ec2_imds_credential_theft) :- ...` rule.
- `examples/sat-control-regression/compound_rules.py` — extend with a
  PySAT compound check.

These are engine-rule additions, not Stave core changes. Sibling
`examples/ecs-ssrf-credential-theft/multi-engine-results.md`
documents the same backlog for the ECS variant.

## Related

- `examples/ecs-ssrf-credential-theft/` — ECS task-metadata variant of
  the same attack class (different metadata endpoint, different
  control set, same compound shape).
- `chains/ecs_ssrf_credential_theft.yaml` — sibling chain definition.
- `controls/iam/credential/CTL.IAM.CREDENTIAL.USERDATA.001.yaml` —
  the EC2-user-data leakage variant (NHI2 secret-leakage class).

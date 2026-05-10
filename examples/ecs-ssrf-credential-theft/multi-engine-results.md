# ECS SSRF Credential Theft — Multi-Engine Analysis

## Scenario

An attacker exploits an SSRF vulnerability in an application running on
ECS to access the task metadata endpoint (`169.254.170.2/v2/credentials/<guid>`).
The endpoint returns short-lived AWS credentials for the task's IAM role.
The role is over-privileged — stolen credentials grant access to S3,
DynamoDB, or Secrets Manager beyond what the task requires. The task's
security group permits unrestricted egress, so the credentials can be
exfiltrated to attacker infrastructure in one HTTP request.

```
attacker SSRF in container
    │
    ▼
GET 169.254.170.2/v2/credentials/<guid>
    │   (ECS task metadata endpoint — no IMDSv2-style token)
    ▼
short-lived AWS credentials for the task role
    │
    ▼
unrestricted egress (sg permits 0.0.0.0/0:*)
    │
    ▼
exfiltration to attacker infrastructure / lateral access
```

## Chain composition

`chains/ecs_ssrf_credential_theft.yaml` (threshold=2, severity=critical)
composes three controls:

| Member | Asset | Predicate signal |
|---|---|---|
| `CTL.ECS.TASKMETADATA.001` | task definition | `container.task_role.is_overprivileged == true` |
| `CTL.ECS.METADATA.CREDENTIAL.001` | task definition | `container.metadata.credential_scoping_enabled == false` |
| `CTL.VPC.SG.EGRESS.001` | security group | `network.egress.unrestricted_all_ports == true` |

Threshold 2 of 3 — both ECS controls fire on the same task-definition
asset, so the chain composes by `asset.ID` on the task-def. The SG
finding is the third leg of the attack story but isn't required for
chain firing.

## Engine results — writeup-config

| Engine | Verdict | Detail |
|---|---|---|
| **Stave CEL** (`stave apply`) | 3 ECS/VPC findings + 1 chain | `TASKMETADATA.001`, `METADATA.CREDENTIAL.001`, `VPC.SG.EGRESS.001`; chain `ecs_ssrf_credential_theft` (severity: critical) |
| **Stave SIR JSONL export** | 5,253 facts | `stave export-sir --format jsonl` |
| **Stave SIR SMT-LIB v2 export** | 21,155 lines | declared predicates + closed-world axioms ready for SMT consumers |
| **Encoding verifier** (`examples/explain/verify_encoding.py --strict`) | ✅ 4/4 facts match observations | each emitted ECS/VPC fact traces to a property path in the writeup observation |
| **Prism risk model** | empty — no modeled shape applies | the engine's shape catalog covers cognito_unauth / self_reg / multi_hop_chain / overperm_compute / wildcard_resource. **ECS SSRF is not yet a modeled shape — engine-rule expansion backlog.** |
| **Game-theory cost model** | empty — no attack paths under modeled shapes | same reason as prism — **engine-rule expansion backlog.** |
| **Z3** | not run | no `query.smt2` for the ECS SSRF chain yet; the SMT2 fact base is exported and ready for one. **Engine-rule expansion backlog.** |
| **Clingo / Soufflé / PySAT / Prolog** | not run | binaries not installed in this environment (Codespaces image has them); the JSONL fact base is consumable as-is. **Engine-rule expansion backlog.** |

## Engine results — remediated-config

| Engine | Verdict | Detail |
|---|---|---|
| **Stave CEL** (`stave apply`) | 0 ECS/VPC findings, 0 chains | each predicate flips: `is_overprivileged → false`, `credential_scoping_enabled → true`, `unrestricted_all_ports → false` |
| **Stave SIR JSONL export** | identical fact-base shape to writeup, with the boolean facts flipped | demonstrates that the migration pipeline preserves fact projection across remediation |

## What this scenario demonstrates

For early adopters running ECS workloads:

1. **Task roles must follow least-privilege.** The task metadata
   endpoint has no IMDSv2-style token — credential theft is one HTTP
   request away if the role is broad. `CTL.ECS.TASKMETADATA.001` fires.
2. **Container-level credential scoping must be enabled.** Without
   `credentialSpecs`, every container in the task — including those
   vulnerable to SSRF — can reach `169.254.170.2`.
   `CTL.ECS.METADATA.CREDENTIAL.001` fires.
3. **Egress must be restricted.** Even if credentials are stolen,
   restricted egress prevents exfiltration. `CTL.VPC.SG.EGRESS.001`
   fires when the security group permits unrestricted outbound.

Stave's compound chain reads "this configuration is one HTTP request
away from credential theft" — operators see the compound verdict
before they see the individual triage queue.

## How to adapt to your ECS workloads

```bash
# 1. Export your ECS task definitions and security groups as observations
#    (use your collector of choice — the schema is in this fixture).

# 2. Run stave apply to detect the chain
stave apply --observations <your-obs-dir> --format json \
  | jq '.chain_findings[] | select(.chain_id == "ecs_ssrf_credential_theft")'

# 3. Export the SIR fact base for richer reasoning
stave export-sir --format jsonl --observations <your-obs-dir> > facts.jsonl

# 4. (Optional) once an ECS-shape rule is added to prism / game-theory
#    / clingo / pysat, those engines consume the same facts.jsonl
#    without re-running stave.
```

## Engine-rule expansion backlog

The empty cells above are not gaps in the chain catalog or the fact
projection — they are missing rules in external engines:

- `examples/prism-risk-prioritization/risk_model.py` — add an
  `ecs_ssrf_credential_theft` shape that scores P(exploitation) given
  `task_role_overprivileged`, `metadata_credential_scoping_disabled`,
  and `egress_unrestricted` facts.
- `examples/game-theory-cost/cost_model.py` — same shape, attacker-cost
  ranking.
- `examples/z3-ecs-ssrf-credential-theft/` (new) — `query.smt2`
  asserting the chain conditions and asking Z3 for `sat` (witness model)
  / `unsat` (provably safe).
- `examples/clingo-constraints/constraints.lp` — extend with a
  `violation(T, ecs_ssrf_credential_theft) :- ...` rule.
- `examples/sat-control-regression/compound_rules.py` — extend with a
  PySAT compound check.

These are engine-rule additions, not Stave core changes. Each is one
PR shape, separate from this fixture.

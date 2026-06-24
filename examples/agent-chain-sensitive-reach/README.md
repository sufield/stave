# AGENT-CHAIN-001 — Agent Role Reaching Sensitive Resources

Graph-reachability reasoning spec for `CTL.IAM.AGENT.CHAIN.SENSITIVE.001`.

The per-resource catalog control reads a derived `identity.agent_reaches_sensitive`
boolean. **This spec is where that boolean comes from** — and it proves the
verdict two independent ways, Soufflé (Datalog) and Z3 (SMT), which must agree.
Per-resource CEL can flag an agent role's *direct* grants; it is blind to the
transitive path (agent → AssumeRole → intermediate role → PassRole → secret).
Reachability rooted at agent roles is what graph engines see.

## The graph

Same six-relation model as the internet-foothold spec, but the root set is
`agent_role` (roles identified by the agent taxonomy — Bedrock/SageMaker/Lambda/
Step Functions trust principals, `*agent*`/`*bot*`/`*automation*` names, or a
`workload-type=agent` tag) instead of `internet_facing_role`.

`reachable.dl` computes transitive `controls_role` (assume/pass chains, arbitrary
depth) and `can_reach` (direct, resource-policy, or via a controlled role), then
`reachable(agent_role, sensitive_res)`. `query.smt2` asks Z3 the same question
over closed-world `define-fun` facts, bounded to two control hops — covering the
direct, two-hop, and three-entity (assume + pass) cases in the triplet.

## Run it

```bash
PATH="$HOME/.local/bin:$PATH" bash run.sh
```

```
vuln   souffle=PATH  z3=sat      agent -> assume -> pipeline-role -> prod secret        (FAIL)
fp     souffle=NONE  z3=unsat    agent -> assume -> readonly-role -> public bucket       (PASS)
fn     souffle=PATH  z3=sat      sagemaker -> assume -> etl -passrole-> admin -> KMS key (FAIL)
```

`expected/output.txt` is byte-identical. The two engines agree on every scenario
— including the **three-entity false-negative trap** (assume + PassRole), which a
direct-permission check misses but reachability proves. The fp passes because the
reachable target (a public bucket) is not a `sensitive_resource`, so no tuple is
derived.

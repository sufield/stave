# RAG-004 — Retrieval Role Reaching Beyond Declared Sources

Scope-containment reasoning spec for `CTL.BEDROCK.KB.RETRIEVAL.SCOPE.001`.

The per-resource catalog control reads a derived
`ai.knowledge_base.retrieval_exceeds_declared_scope` boolean. **This spec is
where that boolean comes from**, proved two ways (Soufflé + Z3). The KB declares
its data sources (`kb_data_source` — S3 prefixes, OpenSearch collections). The
fact generator resolves everything the retrieval role can actually reach
(`retrieval_can_access`) with **wildcard prefixes expanded, assume-role hops
followed, and resource-based-policy grants folded in** — the same pre-resolution
the foothold spec does for `has_access`/`resource_policy_grants`. Any reachable
resource outside the declared set is a scope exceedance.

## Run it

```bash
PATH="$HOME/.local/bin:$PATH" bash run.sh
```

```
vuln   souffle=EXCEEDS    z3=sat      wildcard hr-* overmatches hr-private-records         (FAIL)
fp     souffle=CONTAINED  z3=unsat    retrieval scoped exactly to the declared source      (PASS)
fn     souffle=EXCEEDS    z3=sat      non-source bucket policy grants the retrieval role    (FAIL)
```

`expected/output.txt` is byte-identical. The **false-negative trap** is a
resource-based-policy path: the retrieval role's *IAM* policy looks correctly
scoped, but another bucket's policy grants it access — caught only because that
edge is folded into `retrieval_can_access`. Both engines agree on every scenario.

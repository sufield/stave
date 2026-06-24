# RAG-003 — Retrieval Role Broader Than Embedding Role

Permission set-difference reasoning spec for `CTL.BEDROCK.KB.RETRIEVAL.OVERBROAD.001`.

The per-resource catalog control reads a derived
`ai.knowledge_base.retrieval_broader_than_embedding` boolean. **This spec is
where that boolean comes from**, proved two ways (Soufflé + Z3). This is a
two-role comparison, not reachability: the effective permissions of the KB's
embedding role (ingest: read sources, write vector store) and retrieval role
(query: read vector store + `bedrock:Retrieve`) are resolved (inline + attached
managed + boundary, wildcards expanded) into `(service, action, resource)`
tuples. Retrieval must be a strict read-only subset.

A violation is any permission retrieval holds that embedding does not (excluding
the design-intended `bedrock:Retrieve`), or any write action on the retrieval
role.

## Run it

```bash
PATH="$HOME/.local/bin:$PATH" bash run.sh
```

```
vuln   souffle=BROADER  z3=sat      retrieval s3:* (wildcard embedding lacks)            (FAIL)
fp     souffle=SUBSET   z3=unsat    retrieval read-only subset + bedrock:Retrieve        (PASS)
fn     souffle=BROADER  z3=sat      retrieval has secretsmanager via attached policy     (FAIL)
```

`expected/output.txt` is byte-identical. The **false-negative trap** catches a
permission that arrives through an *attached managed policy* (not the inline
policy) — which is why effective-permission resolution, not inline-only, is
required. Both engines agree on every scenario.

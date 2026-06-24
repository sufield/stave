# TAG-INTEGRITY-001 — Tag-Based Authorization Scheme Completeness

Reasoning spec for `CTL.IAM.TAGAUTH.COMPLETE.001`. A tag-based authorization
scheme has four layers; all must hold simultaneously or the scheme is
bypassable, and the bypass path depends on which layer fails:

| Layer (control) | If missing/incorrect → bypass |
|---|---|
| `scp-tag-001` ENFORCE | no-enforcement — tags exist but nothing checks them |
| `scp-tag-002` MUTATION | self-tag-exemption — a principal tags itself |
| `rcp-tag-001` SESSION | session-tag-injection — external principal injects the tag |
| `scp-tag-003` TAGGER | tagger-role-hijack — modify/recreate the tagger and self-exempt |

Each `layer_holds` fact is the collector's per-layer verdict — **correctness,
not mere existence**: a layer present with the wrong condition operator (e.g.
`StringNotEquals` where `StringNotLike` is required) is *not* in `layer_holds`.

```bash
PATH="$HOME/.local/bin:$PATH" bash run.sh
```
```
complete         souffle=NONE                   z3=sat     all four hold                (PASS)
rcp_missing      souffle=session-tag-injection  z3=unsat   RCP layer absent             (FAIL)
mutation_wrongop souffle=self-tag-exemption     z3=unsat   mutation lock wrong operator (FAIL)
enforce_missing  souffle=no-enforcement         z3=unsat   no enforcement SCP           (FAIL)
```
`expected/output.txt` is byte-identical. Soufflé enumerates the specific bypass
path; Z3 proves `scheme_complete = (l_001 ∧ l_002 ∧ l_rcp ∧ l_003)` — `sat` when
complete, `unsat` otherwise. They agree on every scenario, including the
`mutation_wrongop` "exists but incorrect" case.

The four atomic layer controls each read one collector-derived boolean
(`identity.tag_auth.*`), exactly like every other `identity.scp.*` control in
the catalog; the per-layer SCP/RCP condition-semantics parsing is the
collector's job. This spec proves the compound conjunction the four feed.

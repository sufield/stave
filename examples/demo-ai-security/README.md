# AI Security Demo

> Your AI agent has admin access. Your scanner says you're compliant.

Single-command demo of Stave's AI agent identity detection — five
acts in under five minutes, no Docker, no setup. Built for the AI
security talk; runs in the Codespaces devcontainer.

## Run

```bash
bash run.sh
```

That's it. The runner is pure-stave + jq + Python stdlib; everything
the Codespaces devcontainer already has.

## What it shows

| Act | What |
|---|---|
| 1 | `stave apply` finds 5 AI violations across Bedrock + Lambda + KB + S3 |
| 2 | Those 5 findings compose into **3 CRITICAL compound chains** — `bedrock_agent_overpermissioned`, `bedrock_agent_tool_phi_exposure`, `bedrock_rag_phi_exposure` |
| 3 | Stave's SIR export emits 6,000+ facts consumable by Z3 / cvc5 / Yices (already installed in the devcontainer); encoding verifier confirms every emitted fact traces to an observation property |
| 4 | Five config changes flip every predicate; all chains go silent; cost is $0 + $0.050/MAU for the guardrail |
| 5 | Component-level scanners report 6/6 PASS on the same writeup — encryption, VPC, public-access block all green. The compound detection is the gap |

## The pitch

> Your scanner checks encryption and VPC isolation.
> It doesn't check whether your AI agent can invoke any
> Lambda in the account and reach PHI data through the
> tool chain. Stave does.

## Why three chains, not one

The writeup fires three independent compound shapes because three
attack stories overlap on the same configuration:

| Chain | Members | Shape |
|---|---|---|
| `bedrock_agent_overpermissioned` | OVERPERM.LAMBDA + GUARDRAIL + LOGGING | Same-asset compound on the agent — agent has broad reach + no content filter + no audit trail |
| `bedrock_agent_tool_phi_exposure` | LAMBDA.MARKER.BEDROCK.TOOL + LAMBDA.OVERPERM.S3PHI | Same-asset compound on the Lambda — Lambda is registered as an agent action group AND its role reaches PHI |
| `bedrock_rag_phi_exposure` | BEDROCK.KB.MARKER.INDEXES + S3.MARKER.PHI | Cross-resource compound via `scope_field` — KB indexes a bucket AND that bucket is PHI-tagged |

The first chain says "the agent's permission surface is the
problem." The second says "the agent's tool chain reaches PHI."
The third says "the agent's knowledge base IS PHI." Three
distinct failure shapes, one fixture; the demo shows that Stave
distinguishes them rather than collapsing them into one finding.

## Fixture layout

```
examples/demo-ai-security/
├── README.md                 — this file
├── run.sh                    — five-act runner with projector-readable colors
└── fixtures/
    ├── writeup-config/
    │   └── observations/
    │       └── 2026-05-10T000000Z.json  — 4 assets, all three compounds fire
    └── remediated-config/
        └── observations/
            └── 2026-05-10T000000Z.json  — 5 assets (PHI bucket retained, KB redirected)
```

The four writeup assets:
- **Bedrock agent** — broad Lambda invoke, broad S3, no guardrail, no logging
- **Bedrock knowledge base** — indexes the PHI bucket
- **Lambda function** — registered as agent action group, role reaches PHI bucket
- **S3 bucket** — `data-classification=phi`

The remediated set keeps the PHI bucket present (data doesn't
move during a config-only fix) but redirects the knowledge base
to a separate `product-docs-public` bucket and tightens every
identity predicate. Demonstrates that the chain isn't fooled by
the PHI bucket's mere existence — the compound only fires when
the KB's target_bucket_arn matches the PHI bucket's asset.ID.

## Where this came from

Built on top of the six-iteration AI agent identity track:

- Iteration 2 (`8b32799cc`) — Bedrock agent overpermissioned controls
- Iteration 3 (`e43b84b31`) — SageMaker execution-role controls (not exercised here)
- Iteration 4 (`4cff058bd`) — Bedrock RAG-PHI compound + KB marker
- Iteration 5 (`30807bca1`) — Lambda Bedrock-tool marker + cross-service compound
- Iteration 6 (`8e5fd5c06`) — shadow-agent + ghost references (not exercised here)

The demo's "5 violations + 3 chains" verdict is the product of
~25 controls + 3 compound chains shipped across those iterations.

## Speaker notes (5–7 minutes total)

| Slide | Time | Content |
|---|---|---|
| Setup | 30s | "84% of orgs use AI in the cloud. Compliance scanners check encryption and VPC. Watch what they miss." |
| Act 1 | 60s | Show 5 findings. Read 2-3 control names. Pause on `LAMBDA.OVERPERM.S3PHI`. |
| Act 2 | 90s | "Not 5 findings — 3 attack chains." Read each chain name + first sentence of description. |
| Act 3 | 30s | "Stave exports facts in SMT-LIB. Z3, cvc5, Yices consume them. The devcontainer already has all three." (Skip the SMT detail if time-pressed.) |
| Act 4 | 60s | "Five config changes. $0 + $0.050 per million active users. All three chains silent." |
| Act 5 | 60s | "What your scanner says on the same configuration: COMPLIANT. The scanner checks components. Stave checks interactions." |

The Act 5 scanner output is illustrative (hardcoded text) — those
are the checks a component-level scanner *would* run, framed as
what's typically reported. Not actual output from any specific
vendor. Label it that way during the talk.

## Requirements

| Tool | Source | Used for |
|---|---|---|
| stave | built in the devcontainer | apply, export-sir |
| jq | apt | output filtering |
| python3 | apt (default) | encoding verifier |
| Z3 / cvc5 | apt + manual | optional — referenced in Act 3 but not invoked unless forbidden_state queries exist |

All of these ship in the Stave Codespaces devcontainer. No
additional setup. No internet access required at demo time.

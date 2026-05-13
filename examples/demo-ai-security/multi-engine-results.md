# AI Security Demo — Multi-Engine Analysis

Detection runs through three reasoning layers. CEL evaluates
the YAML controls' predicates and produces findings. The chain
engine composes them. External engines then consume the same
fact export (`stave export-sir`) for additional reasoning
dimensions.

## Writeup fixture

`fixtures/writeup-config/observations/` — Bedrock agent
`CUSTSUPPORTAGENT` with broad Lambda invoke scope, broad S3
access, no guardrail, no model-invocation logging — wired to a
Lambda tool that reaches a PHI-tagged S3 bucket through a
knowledge base.

| Engine | Verdict | Detail |
|---|---|---|
| **CEL** (built-in) | 5 findings | Bedrock agent overpermissioned + Lambda tool reaching PHI + KB indexing PHI |
| **Chain engine** | 3 CRITICAL | `bedrock_agent_overpermissioned`, `bedrock_agent_tool_phi_exposure`, `bedrock_rag_phi_exposure` |
| **Clingo** | 3 violation kinds | enumerates each agent governance failure axis |
| **Soufflé** | n/a | no `ai-*-reach.dl` authored yet — deferred until a per-element AI fact (e.g. per-action-group) lands |
| **Encoding verifier** | 9/9 verifiable facts match | full agent + KB + Lambda tool fact graph traceable |

### CEL (the YAML predicate evaluator)

```
CTL.BEDROCK.AGENT.OVERPERMISSIONED.001        HIGH
CTL.BEDROCK.AGENT.NO.GUARDRAIL.001            HIGH
CTL.BEDROCK.AGENT.NO.INVOCATION.LOGGING.001   MEDIUM
CTL.BEDROCK.AGENT.S3.SCOPE.BROAD.001          HIGH
CTL.BEDROCK.KB.MARKER.INDEXES.001             (marker — informational)
```

(Names approximate; exact catalog IDs may differ — see
`docs/controls/reference.md`.)

### Chain engine

```
bedrock_agent_overpermissioned
  threshold:           2 of 3
  compound_severity:   CRITICAL

bedrock_agent_tool_phi_exposure
  threshold:           2 of 3
  compound_severity:   CRITICAL

bedrock_rag_phi_exposure
  threshold:           2 of 2
  compound_severity:   CRITICAL
```

### Clingo (`examples/clingo-constraints/ai-delegation-shadow.lp`)

```
violation: agent_broad_lambda_no_guardrail  (1)
    arn:aws:bedrock:us-east-1:111122223333:agent/CUSTSUPPORTAGENT
violation: agent_broad_lambda_no_logging  (1)
    arn:aws:bedrock:us-east-1:111122223333:agent/CUSTSUPPORTAGENT
violation: agent_broad_s3_access  (1)
    arn:aws:bedrock:us-east-1:111122223333:agent/CUSTSUPPORTAGENT
```

Each rule expresses one structural failure mode (broad Lambda
without guardrail, broad Lambda without logging, broad S3
access). Clingo's strength here is that **each violation is
independently triageable** — fixing the guardrail clears one
row, fixing logging clears another, narrowing the S3 IAM
scope clears the third. The three rows surface the three
independent remediation hooks.

### Soufflé

No `ai-*-reach.dl` exists yet — every AI agent predicate the
current array projectors emit is scalar
(`has_agent_guardrail`, `has_agent_lambda_scope_broad`, etc.).
The per-element facts that Soufflé reachability typically
consumes (e.g. per-action-group facts) haven't been projected.
A `bedrock-reach.dl` would unlock blast-radius counts once a
per-action-group projector ships.

## Remediated fixture

`fixtures/remediated-config/observations/` — agent has
guardrail, invocation logging on, scoped Lambda invoke,
scoped S3 access. KB indexes a non-PHI bucket.

| Engine | Verdict |
|---|---|
| CEL | 0 findings on agent governance controls (marker still fires informationally) |
| Chain engine | 0 chains |
| Clingo | (clean) |
| Encoding verifier | 9/9 facts match |

## What each engine adds

- **CEL** is the primary detection: per-axis predicate
  evaluation produces one finding per agent governance defect.
- **The chain engine** composes the axes into the three
  CRITICAL AI safety chains.
- **Clingo** is the structural enumerator: every (agent,
  failure-mode) pair lands as one row. The CISO triage queue
  reads the rows verbatim — three rows, three remediation
  hooks, one click each.

## Reproduce

```bash
cd <repo-root>/stave
make build

./stave export-sir --format jsonl \
    --observations examples/demo-ai-security/fixtures/writeup-config/observations \
    --now 2027-01-01T00:00:00Z > /tmp/ai.jsonl

.tools-venv/bin/python3 examples/clingo-constraints/run.py \
    "ai-demo" /tmp/ai.jsonl \
    examples/clingo-constraints/constraints.lp \
    examples/clingo-constraints/ai-delegation-shadow.lp
```

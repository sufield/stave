# Your AI Agent Has Admin Access. Your Scanner Says You're Compliant.

> Conference-ready slide deck. Markdown source — render in any
> Markdown slide tool (Marp, Reveal.js Markdown, Slidev) or paste
> per-slide blocks into Google Slides / Keynote.
>
> **No code on slides except `bash run.sh`.** All demo work happens
> in a full-screen terminal. The slides set up the audience for
> what they're about to see and frame what they just saw.
>
> 15 slides total. Slides 5–9 are placeholders for the live demo;
> screenshots of each act live under `screenshots/` as the
> fallback if the Codespace fails.

---

## Slide 1 — Title

```
Your AI Agent Has Admin Access.
Your Scanner Says You're Compliant.

Bala Paranj
[Conference Name] — [Date]
```

---

## Slide 2 — The 84% problem

```
84%   of organizations use AI in the cloud
62%   have at least one vulnerable AI package
92%   aren't confident their IAM tools can manage AI identity risks

 0%   of CSPM tools check whether your AI agent can invoke any
       Lambda in the account and reach PHI through the tool chain.

Sources: Orca 2026, Qualys 2026, CSA/Tenable 2026
```

---

## Slide 3 — What your scanner checks

```
Component-level scanner results on a real configuration:

  Bedrock encryption:        ✅ PASS
  Bedrock VPC:               ✅ PASS
  Bedrock model access:      ✅ PASS
  S3 encryption:             ✅ PASS
  S3 public access:          ✅ PASS
  Lambda encryption:         ✅ PASS

6 checks. 6 passes. COMPLIANT.
```

---

## Slide 4 — Let's run it

```
$ bash examples/demo-ai-security/run.sh
```

(transition to full-screen terminal)

---

## Slide 5 — DEMO Act 1 (terminal)

> No slide content — terminal output is the slide.
>
> Fallback screenshot: `screenshots/act1-findings.png`
>
> Talking points:
> - "5 findings. Three HIGH, two from markers."
> - "Your scanner reported zero."

---

## Slide 6 — DEMO Act 2 (terminal)

> No slide content — terminal output is the slide.
>
> Fallback screenshot: `screenshots/act2-chains.png`
>
> Talking points:
> - "Those 5 findings aren't separate problems."
> - "3 CRITICAL attack chains."
> - "Agent → Lambda → S3 PHI. No guardrail. No audit trail."

---

## Slide 7 — DEMO Act 3 (terminal)

> No slide content — terminal output is the slide.
>
> Fallback screenshot: `screenshots/act3-encoding.png`
>
> Talking points:
> - "5,300 facts extracted from the configuration."
> - "9 of 9 verified against the raw observation properties."
> - "The encoding is correct — what the solver checks matches what the config says."

---

## Slide 8 — DEMO Act 4 (terminal)

> No slide content — terminal output is the slide.
>
> Fallback screenshot: `screenshots/act4-remediated.png`
>
> Talking points:
> - "4 config changes."
> - "$0 for role scoping. $0.050/MAU for the guardrail."
> - "5 findings → 0. 3 chains → 0."

---

## Slide 9 — DEMO Act 5 (terminal)

> No slide content — terminal output is the slide.
>
> Fallback screenshot: `screenshots/act5-gap.png`
>
> Talking points:
> - "Same configuration. Scanner: 6/6 PASS. Stave: 3 CRITICAL chains."
> - "The scanner checked components. Stave checked interactions."

---

## Slide 10 — Why scanners miss this

```
Scanners check:                   Stave checks:

  "Is encryption on?"               "Can this agent reach PHI
                                     through its tool chain?"

  One resource.                     Three services.
  One setting.                      Five configurations.
  One check.                        One attack path.
```

---

## Slide 11 — The architecture (60 seconds)

```
   Configuration snapshot
            │
            ▼
   Stave   (CEL evaluation + fact export)
            │
            ▼
   JSONL facts   (5,300 triples with provenance)
            │
            ▼
   ┌────────────────────────────────────────────┐
   │   Z3        Soufflé      Clingo    Prolog  │
   │   cvc5      PySAT        Risk      TLA+    │
   │   Yices     Game theory                    │
   └────────────────────────────────────────────┘
            │
            ▼
   9 independent verdicts
            │
            ▼
   Unified reasoning trace (one JSON file)
```

---

## Slide 12 — Traceability

```
Finding: "Agent can reach PHI through Lambda tool"
            │
            ▼
   fact_id:   a3f8c2e91b04
            │
            ▼
   Observation:  bedrock-agent.obs.json
   Property:     ai.agent.identity.execution_role.has_broad_lambda_invoke
   Captured:     2026-05-10T00:00:00Z
            │
            ▼
   One grep.  Full trace.
   Engine verdict → fact → observation file → property → value.
```

---

## Slide 13 — The AI agent identity gap

```
32 new controls across Bedrock + SageMaker:

  Agent overprivilege    — broad Lambda invoke, broad S3, no guardrail
  Data boundaries        — RAG indexing PHI, cross-account training
  Ghost references       — action group Lambda deleted
  Shadow agents          — created outside IaC, no governance
  Shared roles           — all Studio users = one IAM role

5 compound chains composing these into attack paths.
Zero scanner on the market checks any of them.
```

---

## Slide 14 — What this means for you

```
If you run AI workloads in AWS:

  1.  Does your scanner check what your agents can REACH,
      or just what they're CONFIGURED with?

  2.  Does your Bedrock agent's execution role have
      lambda:InvokeFunction on Resource: *?

  3.  Does your knowledge base index any bucket tagged
      with a sensitivity classification?

  4.  Do you have Bedrock agents created outside your
      IaC pipeline?

If "I don't know" to any of these:

   github.com/sufield/stave
   bash examples/demo-ai-security/run.sh
```

---

## Slide 15 — Thank you + Q&A

```
Stave — compound risk reasoning for cloud infrastructure

   github.com/sufield/stave
   2,650 controls | 9 reasoning engines | air-gapped

   Bala Paranj
   [Contact info]

   Q&A
```

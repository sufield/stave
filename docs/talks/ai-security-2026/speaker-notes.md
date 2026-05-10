# Speaker Notes — AI Security 2026

Per-slide notes. Each note caps at ~90 seconds of speaking time.
Total ~20 minutes when paced with the demo.

---

## Slide 1 — Title (0:00–0:30)

**Speaker note:** "Show of hands — how many of you have Bedrock
agents or SageMaker workloads in production?

[wait]

Keep your hand up if your security scanner checks what those
agents can reach through their tool chains.

[pause; most hands will drop]

That's the gap this talk is about."

---

## Slide 2 — The 84% problem (0:30–2:00)

**Speaker note:** "These numbers come from four independent
industry reports published in the last six months. The pattern
is consistent: AI adoption is ahead of AI security.

The interesting number is the last one — zero. No CSPM tool on
the market checks the compound interaction between an AI agent's
permissions, its tool chain, and the data those tools can reach.

That's not because the vendors are bad. It's because compound
detection is structurally different from component scanning.
Component scanning asks 'is encryption on?' — a per-resource
question. Compound detection asks 'can this agent reach PHI?' —
a multi-resource, multi-hop question. Those need different tools."

---

## Slide 3 — What your scanner checks (2:00–3:00)

**Speaker note:** "This is a real configuration — actually it's
the writeup fixture you'll see in the demo in a moment. Every
component-level check passes. Encryption is on. VPC is configured.
Public access is blocked. Your dashboard is green. Your auditor
is happy.

And the Bedrock agent on this configuration can read every
patient record in the connected S3 bucket through its Lambda
tool chain.

Let me show you."

---

## Slide 4 — Let's run it (3:00–3:30)

**Speaker note:** "This runs in a GitHub Codespace. No cloud
credentials. No API calls. Static analysis on a configuration
snapshot. Everything you're about to see runs on your laptop
with no network access.

If you want to follow along, the repo URL is on the last slide
and the command is one line."

---

## Slide 5 — DEMO Act 1 (3:30–4:30)

**Speaker note (after Act 1 prints):** "5 findings. Three HIGH,
two from informational markers — bucket has PHI tag, Lambda is
registered as a Bedrock tool.

Your scanner reported zero. None of these are component-level
properties. The agent's execution role permissions aren't a
'misconfigured component' — the role is configured correctly
for what it claims to do. The Lambda's encryption is fine. The
bucket's encryption is fine. The PHI tag is correct because the
data IS PHI.

The five findings are individual configurations that look right.
That's the trap."

---

## Slide 6 — DEMO Act 2 (4:30–6:00)

**Speaker note (after Act 2 prints):** "Those 5 findings aren't
separate problems. They compose into 3 CRITICAL attack chains.

Read the names with me: bedrock_agent_overpermissioned —
agent has broad reach AND no guardrail AND no audit trail.
bedrock_agent_tool_phi_exposure — agent → Lambda → S3 PHI.
bedrock_rag_phi_exposure — knowledge base indexes the PHI
bucket directly.

Three different attack stories about the same agent. Each
chain has a threshold — usually 2 or 3 individual findings
must fire for the chain to compose. The chain definitions are
in YAML, hand-curated, like a regex catalog for attack
patterns. We shipped 5 AI compound chains in the last six
weeks; 230 across the rest of AWS over the past two years."

---

## Slide 7 — DEMO Act 3 (6:00–7:00)

**Speaker note (after Act 3 prints):** "5,300 facts extracted
from the configuration. 9 of 9 verified against the raw
observation properties.

Stave doesn't just emit findings — it emits a fact base. Every
fact is a subject-predicate-object triple. Z3 can read those
facts as SMT-LIB and prove the attack path is reachable.
Soufflé can count blast radius. Clingo can enumerate all
violations. We ship example invocations of nine independent
engines in the same repo.

The encoding verifier is what makes this trustworthy. Every
fact has a provenance field pointing back to the property in
the observation. The verifier walks every fact back to the
observation file and confirms the value matches. If anything
drifts, the verifier fails."

---

## Slide 8 — DEMO Act 4 (7:00–8:30)

**Speaker note (after Act 4 prints):** "4 config changes. Five
if you count scoping the Lambda's role.

Cost: zero dollars for the role scoping. The Bedrock guardrail
is $0.050 per million active users per month — for a 1,000-user
internal app, that's five cents a month.

Time: about 30 minutes once a platform engineer has it on the
backlog. We're not talking about a rearchitecture. We're talking
about narrowing four IAM policies and turning on two settings.

Same engine runs on the remediated configuration. 5 findings →
0. 3 chains → 0. The attack path is gone. Not suppressed by an
exception, not whitelisted, not 'risk-accepted' — gone."

---

## Slide 9 — DEMO Act 5 (8:30–10:00)

**Speaker note (after Act 5 prints):** "Same configuration.

Scanner reports: 6/6 PASS. COMPLIANT.

Stave reports: 3 CRITICAL compound chains.

I want to be careful here — that scanner output is
illustrative. Those are checks a component-level scanner would
run; I'm not picking on any specific product. Every CSPM tool
in this space gets these right. They're real checks. They're
just the wrong question.

The scanner checked components. Stave checked interactions.

That's the talk in one sentence."

---

## Slide 10 — Why scanners miss this (10:00–11:00)

**Speaker note:** "The vulnerability isn't in any single setting.
It's in the interaction between five settings across three
services.

The agent's execution role is overpermissioned — that's a
setting. The Lambda function has S3 access — that's a setting.
The bucket contains PHI — that's a tag. Each one passes every
individual check. The interaction between them is the breach
path.

Component scanners are structurally one-resource-at-a-time.
They have to be — that's how their data model is shaped. Adding
'reach across services' to a component scanner isn't a feature
flag; it's a new product. That's the gap Stave fills."

---

## Slide 11 — The architecture (11:00–12:30)

**Speaker note:** "Stave does two things.

One: evaluate configurations with CEL predicates. CEL is the
same expression language Kubernetes admission policies use.
Each control is a YAML file with a CEL predicate that runs over
a JSON configuration snapshot. 2,650 controls in the catalog
today.

Two: export facts. The same snapshot that drives CEL evaluation
also produces a fact base — JSONL triples or SMT-LIB v2 —
consumable by external reasoning engines.

Nine engines I've shipped examples for: Z3, cvc5, Yices for
SMT proofs. Soufflé for Datalog reachability. Clingo and PySAT
for ASP and propositional encoding. Prolog for derivation trees.
Plus probabilistic risk models and game-theory cost models.

The key point: Stave is not the reasoning engine. Stave is the
fact projection. Reasoning is consensus across nine independent
tools, each of which has its own decades-old correctness story."

---

## Slide 12 — Traceability (12:30–13:30)

**Speaker note:** "Every fact has a deterministic identifier.
When Z3 says 'unsafe,' you trace that identifier back to the
specific property in the specific configuration file that caused
it.

One grep. No manual correlation across five output files.

This is what makes the nine-engine pipeline maintainable.
Without traceability, nine engines are nine sources of
confusion. With traceability, they're nine independent witnesses
to the same fact base — and disagreements between engines
become a debugging tool, not a credibility problem."

---

## Slide 13 — The AI agent identity gap (13:30–15:00)

**Speaker note:** "We shipped 32 controls specifically for AI
agent identity risks in the last six weeks. Five compound chains
that compose individual findings into attack paths.

Every control maps to the OWASP Non-Human Identity Top 10 —
NHI1 through NHI10, the framework Anthropic and Astrix and the
OWASP project released for machine identity risks. We've now
mapped 235 controls across the broader catalog to NHI risks
too, so the entire AWS surface speaks the same governance
language.

The interesting story here isn't 'we built AI security.' It's
'the same compound detection machinery that finds Cognito-to-S3
chains finds Bedrock-to-Lambda-to-PHI chains.' The engine is
reusable. The controls are domain-specific. New attack surfaces
don't require new engines — they require new control YAMLs."

---

## Slide 14 — What this means for you (15:00–17:30)

**Speaker note:** "Four questions. I'll read them out.

[read each question slowly]

Most of you can't answer these today because your tooling
doesn't ask them. Your dashboards don't show the answers. Your
auditors don't request them.

Stave is open source. The demo runs in a Codespace — click the
button on the repo, wait two minutes, run one command. You'll
have answers in five minutes.

If those answers are bad, you have a remediation path. The
demo we just ran showed it: five config changes, zero dollars
plus pennies per user, 30 minutes of work. The hard part isn't
the fix — the hard part is knowing you need it.

That's what this talk is for."

---

## Slide 15 — Thank you + Q&A (17:30–20:00)

**Speaker note:** "Stave is at github.com/sufield/stave. 2,650
controls, nine reasoning engines, runs air-gapped on a snapshot.

I'm Bala Paranj. Contact info is on the slide.

I'd love to take questions for the next two minutes. Specifically
I'd love to hear:
- Anyone who's looked at compound detection before? What
  worked or didn't?
- Anyone running AI agents in regulated workloads — HIPAA,
  PCI, financial services? What's your governance story today?
- Anyone surprised by anything in the demo?

Questions."

---

## Backup talking points (if questions slow)

**"How is this different from CSPM tools like Wiz / Orca / Prisma?"**

"Three differences. One: Stave runs on a snapshot, not your live
account — no credentials, air-gapped, deterministic. Two: Stave
does compound detection across services, not per-resource scoring.
Three: Stave exports facts to nine reasoning engines, not one
proprietary scoring algorithm. They're complementary tools — most
adopters run a CSPM for live posture and Stave for compound risk
analysis."

**"How long does it take to deploy?"**

"There's nothing to deploy. You run `stave apply` against a JSON
snapshot. The snapshot collector is one of several — Steampipe,
Cloudquery, or a custom CDK extractor. Output is JSON findings
plus a JSONL fact base. Pipe either into your existing dashboards."

**"What's the false positive rate?"**

"Per-control false positive rate is low because the controls are
boolean property checks — `is_overprivileged == true` either is
or isn't. The compound chains have configurable thresholds; the
question 'how many findings need to fire before it's a compound'
is a tuning knob. We default conservatively. The risk is
false-negatives — controls we haven't shipped yet. We map the
gap explicitly in the OWASP NHI documentation."

**"Does this handle multi-cloud?"**

"AWS is best-covered today — 2,650 controls. Azure has ~150
controls, GCP ~80, GitHub ~60, Cloudflare and m365 smaller still.
The reasoning engine and the chain composition logic are
cloud-agnostic; the gap is control authoring per cloud. We
prioritize based on what early adopters use."

**"Is the talk slide deck open source?"**

"Everything — slides, speaker notes, abstract, bio, the demo
script you saw — is at `docs/talks/ai-security-2026/` in the
Stave repo. Steal whatever's useful for your own talk."

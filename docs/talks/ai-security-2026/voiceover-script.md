# Voiceover Script — AI Security Demo Recording

Voiceover lines and pause cues for the screen-capture recording.
Measured against the shipped runner (`examples/demo-ai-security/run.sh`),
which prints all five acts in ~10 seconds wall-clock; the recording
is paced by narration, not runtime.

**Target total length:** 6:00–6:30 (with narration). The runner's
terminal output is the silent video track; voiceover fills the
pauses. Real time of the runner is irrelevant — narrate at the
cadence below regardless of how fast the terminal scrolls.

## Pre-roll (0:00–0:15)

**On screen:** terminal idle, prompt visible at column 1.

**Voiceover (15 seconds):**

> "This is a Bedrock agent configuration. Every component-level
> security check passes — encryption is on, VPC is configured,
> model access is restricted. Let's see what compound analysis
> finds."

**Action:** Type `bash examples/demo-ai-security/run.sh` slowly
enough that the audience can read it. Press Enter on the word
"finds." Don't type too fast — typing IS the visual cue that the
demo is starting.

---

## Act 1 — Findings (0:15–1:15)

**On screen:** Act 1 header + divider + 5 HIGH findings list.

**Voiceover (≈45 seconds, after Act 1 settles):**

> "Five findings. All high severity.
>
> The agent has broad Lambda invoke permissions. No guardrail
> filtering prompts or outputs. No invocation logging. The
> Lambda tool function attached to this agent can read from a
> PHI-tagged S3 bucket. The agent's role has broad S3 access.
>
> Your scanner reported zero of these. Every component-level
> check on this configuration passed."

**Pause:** 3 seconds while the divider scrolls and Act 2 begins.

---

## Act 2 — Compound chains (1:15–2:45)

**On screen:** Act 2 header + "Compound chains: 3" + three
CRITICAL chain blocks.

**Voiceover (≈75 seconds):**

> "Those five findings aren't separate problems. They compose
> into three CRITICAL compound chains.
>
> The first — `bedrock_agent_overpermissioned`: agent has
> broad Lambda access AND no guardrail AND no logging. An
> overpermissioned agent with no safety net.
>
> The second — `bedrock_agent_tool_phi_exposure`: the agent's
> tool chain reaches a PHI bucket through the Lambda function.
> Agent prompts the Lambda, Lambda reads from S3, S3 contains
> patient records.
>
> The third — `bedrock_rag_phi_exposure`: the knowledge base
> indexes the same PHI bucket directly via RAG retrieval.
> Different mechanism, same data path.
>
> Three different attack stories about the same agent."

**Pause:** 3 seconds.

---

## Act 3 — Verification (2:45–3:30)

**On screen:** Act 3 header + "Facts exported: 5,300+" +
"Encoding verified: 9/9 verifiable facts match observations".

**Voiceover (≈45 seconds):**

> "Five thousand three hundred facts extracted from the
> configuration. Every fact verified against the raw
> observation files — the encoding is correct.
>
> What the solver checks matches what the configuration says.
> No translation bugs hiding between the config file and the
> proof. Z3 and cvc5 are already installed in the Codespaces
> devcontainer; the SMT-LIB export is one pipe away from a
> formal proof."

**Pause:** 2 seconds.

---

## Act 4 — Remediation (3:30–4:45)

**On screen:** Act 4 header + 5 remediation steps + "All AI
controls pass" + cost line.

**Voiceover (≈75 seconds):**

> "Four configuration changes.
>
> Scope the agent's execution role to specific Lambda ARNs.
> Attach a Bedrock guardrail with content filtering. Enable
> per-agent invocation logging. Point the knowledge base at a
> non-PHI bucket. Scope the Lambda's role to a non-PHI bucket
> too.
>
> Cost: zero dollars for the role scoping. Five cents per
> million active users per month for the guardrail.
>
> Result: same configuration shape, every predicate flipped.
> Five findings drop to zero. Three chains drop to zero.
> Every engine agrees: safe."

**Pause:** 3 seconds.

---

## Act 5 — The gap (4:45–6:00)

**On screen:** Act 5 header + 6 illustrative "✅ PASS" scanner
checks + closing line "The scanner checked components. Stave
checked interactions."

**Voiceover (≈75 seconds):**

> "Same configuration we started with. Here's what a
> component-level scanner reports.
>
> Bedrock encryption: pass. VPC endpoint: pass. Model access
> list: pass. S3 encryption: pass. S3 public access block:
> pass. Lambda env encryption: pass.
>
> Six checks. Six passes. Compliant.
>
> Stave on the same configuration: three CRITICAL compound
> chains.
>
> The scanner checked components. Stave checked interactions.
>
> That's the gap."

**Pause:** 5 seconds (let the closing line land).

---

## Outro (6:00–6:15)

**On screen:** "Demo complete." + summary table (findings,
chains, catalog count, source URL).

**Voiceover (≈15 seconds):**

> "Stave is open source. Two thousand six hundred fifty controls
> across seventy-four AWS service domains. Nine independent
> reasoning engines. Runs in a GitHub Codespace with one
> command. Link below."

**Action:** Hold terminal output for 3 seconds after the last word.
Stop the recording at 6:18.

---

## Pacing notes

- The terminal output is **fast** (<10 seconds total). Don't
  match the terminal's speed — match the narration's speed.
- Pause after each `divider` (the cyan separator). The visual
  break gives the audience a 2-second reset; the voiceover should
  re-engage them with the first sentence of the next act.
- Voice quality matters more than tempo. A calm, even read at
  150 words/minute lands harder than a rushed 200 wpm.
- The last sentence of Act 5 ("That's the gap.") is the talk's
  closing line. Land it with a half-second pause before and a
  full-second pause after. This is the one moment that earns
  silence.

## What NOT to read

- Don't read the chain descriptions verbatim — they're dense
  technical prose. The bullet points in the voiceover script
  above are the human-readable summary; let the audience read
  the terminal for the depth.
- Don't read the SIR fact count or NHI annotations during the
  demo — they're context for slide 11 and 13, not Act 3's read.
- Don't read the Codespace install instructions — Act 4 says
  "5 cents per user per month," not "the Bedrock guardrail
  pricing is documented at aws.amazon.com/bedrock/pricing."

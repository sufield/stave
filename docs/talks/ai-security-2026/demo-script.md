# Demo Script — AI Security 2026

Exact keystrokes and pacing for the live demo. Runs ~5 minutes
end-to-end (Acts 1–5). The script is the speaker's cue sheet
during the talk.

## Pre-demo setup (before walking on stage)

1. Open the Stave repo in GitHub Codespaces — the badge on the
   README launches it. Wait for the devcontainer's `[stave
   devcontainer] ready` line so `make build` is already done.

   ```
   https://codespaces.new/sufield/stave?quickstart=1
   ```

2. Open the integrated terminal at full screen. Bump font size
   to 24pt so the back of the room can read it. Test colors are
   rendering (the runner uses red/green/yellow/cyan; if your
   terminal theme overrides, set `NO_COLOR=1` to fall back to
   plain text — readable but less dramatic).

3. Pre-position the cursor at the prompt with the command
   already typed but not Enter-pressed:

   ```
   $ bash examples/demo-ai-security/run.sh▮
   ```

   The audience reads the command while you cue them with Slide
   4. Hit Enter on the speaker's cue.

4. Pre-warm the binary: run `./stave --version` once before going
   on stage so the first apply doesn't pay the warm-up tax.

## Demo command (the one keystroke)

```bash
bash examples/demo-ai-security/run.sh
```

That is the only command typed during the demo. Everything else
is the runner emitting Act 1 → Act 5 with pauses you absorb with
talking points.

## Per-act pacing

The runner emits a `divider` (cyan separator) between acts. Each
divider is the speaker's cue to pause, deliver the commentary
below, and re-engage with the audience before the next act
prints. Slow the read on the dividers — projector latency means
the audience needs ~3 seconds after each divider to refocus.

### Act 1 (≈60s — findings)

After Act 1 prints (5 high-severity findings list):

> "5 findings. Three HIGH from CEL controls, two from
> informational markers — bucket has the PHI tag, Lambda is
> registered as a Bedrock tool.
>
> Your scanner reported zero on this configuration."

Pause for 3 seconds, then look at the cyan divider as the next
act starts.

### Act 2 (≈90s — compound chains)

After Act 2 prints (3 CRITICAL compound chains with descriptions):

> "Those 5 findings aren't separate problems. They compose into
> 3 CRITICAL attack chains.
>
> Read the names with me:
> - bedrock_agent_overpermissioned — broad reach + no filter + no audit.
> - bedrock_agent_tool_phi_exposure — agent → Lambda → S3 PHI.
> - bedrock_rag_phi_exposure — knowledge base indexes the PHI bucket.
>
> Three different attack stories about the same agent."

Pause. Move on when the audience visibly absorbs the third bullet.

### Act 3 (≈30s — encoding + SMT availability)

After Act 3 prints (5,300 facts, 9/9 verified, Z3/cvc5 available):

> "5,300 facts. 9 of 9 verified against the raw configuration.
> The encoding is correct — what the solver checks matches what
> the config says.
>
> Z3 and cvc5 are already installed in the devcontainer. The
> SMT proof step is one command away — we'll cover it in Slide 11."

Move on; this act is the briefest.

### Act 4 (≈60s — remediation)

After Act 4 prints (5 config changes, "All AI controls pass"):

> "4 config changes — five if you count scoping the Lambda's role.
> Cost: zero dollars for role scoping; $0.050 per million active
> users per month for the guardrail. Time: about 30 minutes.
>
> All AI findings: 5 → 0. All chains: 3 → 0. The attack path
> isn't suppressed; it's gone."

### Act 5 (≈60s — the gap)

After Act 5 prints (illustrative scanner-output + closing line):

> "Same configuration. Scanner: 6/6 PASS. Stave: 3 CRITICAL
> compound chains.
>
> The scanner output is illustrative — those are the checks a
> component-level scanner would run; I'm not picking on any
> specific product. Every CSPM tool in this space gets these
> right. They're real checks. They're just the wrong question.
>
> The scanner checked components. Stave checked interactions.
>
> [pause]
>
> That's the talk in one sentence."

End demo. Switch back to slides on Slide 10.

## Failure modes (read before going on stage)

| Failure | Fallback |
|---|---|
| Codespace times out / fails to attach | Open `screenshots/act1-findings.png` through `screenshots/act5-gap.png` in the slide deck; label "captured output from prior run" |
| Codespace works but terminal is slow | Don't panic — the audience reads while you talk. Pad with one extra sentence per act. |
| Runner exits non-zero unexpectedly | Open `examples/demo-ai-security/expected/` (if it exists) and read the per-act counts; pivot to "let me show you what the output normally looks like" |
| Network drops mid-demo | The runner is local — analysis continues. If the Codespace itself goes offline, fall back to screenshots. |
| Audience asks "is this rigged?" | "Fixture is in the repo at `examples/demo-ai-security/fixtures/`. Open the JSON file with me; tell me what's unrealistic." Then open it. |
| Live coding temptation | DON'T. Touch nothing during the demo except hitting Enter once. The runner is the demo; improvising breaks the timing. |

## Post-demo timing checkpoint

If you finish the demo by 8:30 (8:00 was the goal), you have a
30-second cushion. Spend it on Slide 10's commentary, not Slide 9.

If you finish by 10:00 (1:30 over), you're at the upper bound of
the demo budget. Move directly to Slide 10 without the "that's the
talk in one sentence" beat — Slide 10 says the same thing.

If you finish by 11:00 (over budget), cut Slide 11 (architecture)
to 30 seconds — one sentence per box — and recover on Slide 13.

## What to skip if Q&A starts hot

- **If Q&A is engaged at slide 14:** stop there; let the audience
  ask. Slide 15 is just the URL — flash it at the end.
- **If Q&A is dead at slide 13:** push through to slide 14 and use
  the four questions as a forcing function. Audiences engage with
  "raise your hand if…" prompts when they were too shy for open Q&A.

## One thing to remember

The demo is the talk. Slides 1–4 set it up; slides 10–15 frame it.
Don't oversell the slides — the audience came to see the terminal
output and the chain count drop from 3 to 0. Everything else is
support.

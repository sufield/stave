# Reading Chain Findings: Your Compound Risk

Chain findings are Stave's distinctive output — compound risks that
emerge from a *combination* of conditions, invisible to single-resource
scanners that check one setting at a time.

> **Environment:** The chain catalog is at `~/chains` (and
> `$STAVE_CHAINS`) in the [Coder workspace](../../stave-workspace/README.md);
> from a local clone, it's `./chains` at the repo root. Chain
> detection auto-discovers from `./chains` relative to cwd, so the
> commands below work in both contexts when you run them from where
> a `chains` directory (or symlink) resolves.

## What a chain finding is

A chain is a set of **co-failing controls** (its *legs*) that together
cross a compound-risk threshold. Each leg, alone, might be a routine
"medium" finding. Stacked, they compose into an exploitable path.

From the `demo-ai-security` run, one chain reads:

```
chain:            bedrock_agent_overpermissioned   [CRITICAL]
compound_score:   100
controls_failing (legs):
    CTL.BEDROCK.AGENT.OVERPERM.LAMBDA.001   broad lambda:InvokeFunction reach
    CTL.BEDROCK.AGENT.GUARDRAIL.001         no content guardrail
    CTL.BEDROCK.AGENT.LOGGING.001           no per-agent invocation logging
attack_stages:    execution → privilege_escalation → detection_evasion
```

Reads like a sentence: *broad reach + no filter + no audit trail =
a usable exfiltration / lateral-movement primitive.* Drop any one leg
and the attacker has either limited reach, blocked content, or visible
activity.

## Priority order

Triage compound risk before isolated settings:

```
1. Chain findings        ← compound, exploitable paths. Fix first.
2. CRITICAL single findings
3. HIGH single findings
4. The rest
```

A setting-level scan might list the three legs above as three separate
medium findings buried in a list of 47. The chain says: these three,
*together*, on this asset, are a critical path.

## Breaking a chain

Every leg must hold for the compound to fire. **Break any one leg and
the compound drops below threshold.** So:

> Pick the **easiest** leg to fix. That single change is your
> highest-leverage action — it neutralizes the whole chain.

Fixing one leg often also clears several of the single-resource
findings that participated in it.

## Visualize the chains

Render an interactive graph of each chain's legs flowing into a
compound-risk node:

```bash
# Run from the Stave repo root — chain detection uses the bundled
# chain catalog in ./chains, which ships with the repo.
stave-mcp --render-chains \
  --observations examples/demo-ai-security/fixtures/writeup-config/observations
```

It prints a `file://` path; open it in a browser. You'll see each
chain as `[ leg ] + [ leg ] + [ leg ] → COMPOUND RISK`, a clickable
chain list, and the break-any-link remediation. Zero chains is a good
result — it means all your risk is single-resource.

> Chain detection requires the chain-definition catalog. It ships in
> the repo at `./chains`; the visualizer defaults to that directory.
> Evaluating your own snapshot for chains means running where `./chains`
> resolves (the repo root), or supplying that catalog.

## Drill in (with an AI assistant)

If you run the MCP server, the model can pull one chain's full detail:

```
stave.context  type=chain  id=bedrock_agent_overpermissioned  observations=...
```

— returning the legs, narrative, stages, and participating assets.

---

**Next:** Fix a leg and prove it → [04-fix-and-verify.md](./04-fix-and-verify.md)

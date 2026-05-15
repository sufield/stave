# Clingo — ASP enumeration of violations

Where Z3 returns **one** witness per query, Clingo's stable-model
semantics enumerates **every** grounded violation atom the rule
set derives. Same fact bundle, different question shape.

## Install

```bash
brew install clingo                # macOS
conda install -c potassco clingo   # cross-platform
pip install clingo                 # Python bindings only (won't give you the CLI)
```

## Run

```bash
stave export-sir --format jsonl --observations ./my-snapshots > facts.jsonl
bash run.sh facts.jsonl

# Use a different rule file:
bash run.sh facts.jsonl ai-delegation-shadow.lp   # default
bash run.sh facts.jsonl constraints.lp            # shared helpers + general violations
```

## How the conversion works

`convert.sh` lifts each JSONL triple into a Clingo binary atom:

```
{"subject": "agent-x", "predicate": "has_agent_lambda_scope_broad", "object": "true"}
  ↓
has_agent_lambda_scope_broad("agent-x", "true").
```

That's the same shape the bundled rules already query, so no
post-processing is needed. Predicate names that Stave emits are
already valid Clingo identifiers; subjects and objects are quoted
strings so dots / dashes / ARNs pass through cleanly.

## Bundled rule files

- **`ai-delegation-shadow.lp`** — AI agent, S3 delegation, Shadow
  Admin, VPC peering, and Shadow EC2 violation patterns. Each rule
  derives a `violation(Asset, "<reason-tag>")` or `violation(Asset,
  "<reason-tag>", Detail)` atom.
- **`constraints.lp`** — shared helper predicates and general
  violation rules. The runner always loads this alongside the
  rule-specific file.

## See also

`examples/clingo-constraints/` ships a fixture-tied worked example
with a Python runner (`run.py`) that uses the `clingo` Python
package, plus an `expected/` directory pinning the expected
violations per fixture. The `.lp` files in this directory are
copies of the same rules; the dedicated directory is what the
regression suite tests against.

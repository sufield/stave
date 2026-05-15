# Soufflé — Datalog reachability and blast radius

Where Z3 finds **one** witness per query, Soufflé enumerates the
**complete** transitive closure. The output answers "how wide is the
blast radius?" rather than "does an unsafe path exist?"

## Install

```bash
brew install souffle   # macOS
apt install souffle    # Ubuntu
```

## Run

```bash
stave export-sir --format jsonl --observations ./my-snapshots > facts.jsonl
bash run.sh facts.jsonl

# Use a different rule file:
bash run.sh facts.jsonl shadow-admin-reach.dl
bash run.sh facts.jsonl delegation-reach.dl
```

## Bundled rule files

- **`reachability.dl`** — general reachability across the
  control / identity / asset graph. Computes every reachable tuple
  per derived relation and prints counts.
- **`delegation-reach.dl`** — narrower: who can reach a delegated
  resource, transitively. Useful for "if I revoke this trust, what
  unblocks?" questions.
- **`shadow-admin-reach.dl`** — does any non-admin principal hold a
  reachable path to an admin-equivalent action?

## How the conversion works

Soufflé's `.input` directives read one TSV file per relation:
`has_type.facts`, `has_action.facts`, etc. The bundled `convert.sh`
splits Stave's JSONL stream by predicate, producing one file per
distinct predicate, and pre-creates empty files for every relation
the bundled rules declare (so a fixture that doesn't emit
`can_assume` simply gets an empty `can_assume.facts` and the
relation evaluates to empty — no Soufflé warnings).

Both the convert script and the .dl files are consumer-side. Stave
exports JSONL triples and is done; Soufflé's input layout is a
local concern of this directory.

## See also

`examples/souffle-reachability/` has a fixture-tied worked example
with golden expected outputs (per fixture, per relation). The `.dl`
files here are copies of the same rules; that dedicated directory
is what the regression suite tests against.

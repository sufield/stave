# Stave Skills for Superpowers

Skills compatible with [Superpowers](https://github.com/obra/superpowers),
the skill-based agent framework. When loaded into Claude Code, Cursor,
Codex, or Gemini CLI, these skills route a cloud-security task through
Stave's machine-verifiable pipeline.

## Skills shipped

| Skill | What it does |
|---|---|
| `verifying-cloud-security` | The entry-point skill. Routes any cloud-security task through Stave's discover → collect → evaluate → prove pipeline with a binary checkpoint at every phase. |
| `writing-stave-controls` | Authoring a new CEL control. Test-first: fixtures before predicate, embedded `tests:` block, end-to-end fires-on-writeup / silent-on-remediated check. |
| `writing-steampipe-mappings` | Connecting a new cloud data source. Validate the mapping structurally before running the transform; validate the transform output before evaluating. |
| `writing-reasoning-specs` | Writing a formal verification question for Z3, cvc5, Soufflé, Clingo, Prolog, or PRISM. Includes the blind-trial discipline from `superpowers:test-driven-development`. |

## Format

Each skill follows the Superpowers shape:

```
<skill-name>/
├── SKILL.md              ← Frontmatter + workflow + checkpoints
├── <reference-file>.md   ← Progressive-disclosure detail
└── <template>.yaml       ← Fillable starter where applicable
```

Frontmatter on every `SKILL.md`:

```yaml
---
name: <skill-name>
description: <one-sentence description>
triggers:
  - trigger phrase 1
  - trigger phrase 2
requires:
  - dependency
---
```

Each skill announces itself ("I'm using the X skill to Y") and has
binary checkpoints — exit codes and counts, not prose.

## Install (manual)

These skills are NOT yet upstream in
[obra/superpowers](https://github.com/obra/superpowers). Use them
locally by copying into your Superpowers skills directory:

```bash
SUPERPOWERS=~/.superpowers  # adjust to your install
cp -r skills/superpowers/* $SUPERPOWERS/skills/stave/
```

Or symlink during development:

```bash
ln -s "$(pwd)/skills/superpowers" "$SUPERPOWERS/skills/stave"
```

## Why a separate `superpowers/` directory

This repository's top-level `skills/` directory follows the
[agentskills.io](https://agentskills.io) standard, which uses a
different frontmatter shape (`auto_invoke:`, `metadata:`,
`allowed-tools:`). The two standards target different agent runtimes;
keeping them in separate trees avoids a forced merge of incompatible
formats.

## Relationship to Stave's documentation

These skills route the agent at Stave's CLI commands and published
contracts. They do NOT duplicate Stave's documentation:

- Authoritative scope of the SIR export → `projects/stave-guide/reference/fact-export.md`
- Architectural boundaries → `stave/docs/architecture/boundaries.md`
- Per-asset contracts → `stave contract show --asset-type <T>`
- Command details → `stave <cmd> --help`

The skill is the router; the contracts are the reference.

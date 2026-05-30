# Stave onboarding skills

Executable onboarding documentation. Each `SKILL.md` is a file an AI coding
agent (Claude Code, Cursor, …) reads and executes against the current
environment — it adapts to what's installed, validates each step, and fails
loudly if something is stale. Same file serves as both the docs and the
automation.

The skills are also runnable by hand: every step is a real command.

## Progression

| # | Skill | Time | AWS? | You end with |
|---|-------|------|------|--------------|
| 1 | `_setup` | 5 min | no | a working `stave` binary + control catalog |
| 2 | `first-evaluation` | 10 min | no | findings from a bundled example; you grok the output |
| 3 | `lab-validation` | 30 min | sandbox ($0) | proof Stave matches an expert oracle (Bishop Fox) |
| 4 | `write-your-first-control` | 20 min | no | a custom control you authored and tested |
| 5 | `reasoning-engines` | 30 min | no | a compound chain derived in Z3/Soufflé/Prolog |
| 6 | `snapshot-your-account` | 30 min | real (read-only) | findings on your actual infrastructure |

Each skill is independently valuable; the order builds confidence. Skill 3 is
the trust step — findings are verified against an independent expert oracle, not
claimed.

Format: each `SKILL.md` carries `name` / `description` / `triggers` frontmatter
(obra/superpowers-compatible) so it can be added to a skill registry.

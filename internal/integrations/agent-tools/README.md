# stave-verify — Stave as an agent tool (skill registry)

One framework-agnostic engine (`stave_verify_core`) with thin shims for LangChain, CrewAI,
and any tool registry (GSD, Superpowers). Every wrapper's input is a **snapshot directory** —
Stave reads JSON on disk and never touches Terraform/IaC. Producing the snapshot is the
consumer's job (each integration brings its own adapter).

Requires the `stave` binary on `PATH` (or pass `stave_bin=`). The core has **no Python
dependencies**.

## Core (no framework)

```python
from stave_verify_core import verify, verify_text

verify("security/snapshots")          # -> {status, finding_count, findings:[{control_id, resource, severity, ...}]}
verify_text("security/snapshots")     # -> compact text for an LLM tool result
```

Each finding: `control_id`, `resource`, `severity`, `description`, `evidence`, `engine`
(`cel`/`souffle`), `remediation_hint`. Findings are **deterministic** — same snapshot, same
result. Exit 3 (violations found) is handled as success; tool errors surface in `error`.

## LangChain

```python
from langchain_tool import StaveVerifyTool, SYSTEM_PROMPT_FRAGMENT
agent = create_react_agent(llm, tools=[StaveVerifyTool()], state_modifier=SYSTEM_PROMPT_FRAGMENT)
```
`pip install stave-verify[langchain]`

## CrewAI

```python
from crewai_tool import stave_verify_tool
agent = Agent(role="Platform SRE", tools=[stave_verify_tool], ...)
```
`pip install stave-verify[crewai]`

## GSD / Superpowers / generic

```python
import skill
skill.run("security/snapshots")        # structured observations (GSD)
skill.run_text("security/snapshots")   # text result (Superpowers)
skill.SKILL_SPEC                        # name/description/input/output spec for a registry
```

## System-prompt fragment

> You have access to the stave_verify tool. It performs deterministic security verification
> against cloud configuration snapshots. Use it BEFORE recommending or deploying any
> infrastructure change. If it returns findings, you MUST address them before proceeding.
> Stave findings are deterministic — proven violations, not suggestions. Do not override them.

## Inner loop vs outer loop

This package is the **inner-loop skill**: the agent *chooses* to call it to self-correct. The
**outer-loop gate** (CI requires it before deploy) is the [GitHub Action](../../../.github/actions/stave-verify)
and equivalents. Same engine, two positions: the agent fixes its own work with the skill so it
can pass the gate.

## Tests

```bash
python3 test_core.py    # 6 tests — needs the stave binary built
```

# stave-mcp

A minimal Model Context Protocol (MCP) server that exposes
Stave's verification surface to AI agents (Claude Code, Cursor,
Copilot, etc.) over JSON-RPC 2.0 / stdio.

The premise: an agent proposes a configuration change, calls
`stave.verify` to check it against the catalog of formally-
authored invariants, calls `stave.explain` if a finding fires,
calls `stave.suggest_fix` to read the deterministic delta-path
and remediation guidance the engine produced.
Stave is the deterministic guardrail; the agent is the
probabilistic proposer. The separation is the point.

## Build

```bash
cd stave
go build -o stave-mcp ./cmd/stave-mcp
```

The binary has no dependencies beyond `pkg/stave` and the Go
standard library — no MCP SDK is pulled into go.mod.

## Tools exposed

| Tool | Inputs | Output |
|---|---|---|
| `stave.verify` | `observations_dir` (required), optional `controls_dir`, `allow_unknown_input` | The full Assessment (findings, summary, status) |
| `stave.explain` | `observations_dir`, `finding_id` | One finding's `reasoning_trace`, `chain_membership`, `compliance` |
| `stave.suggest_fix` | `observations_dir`, `finding_id` | One finding's `delta_paths` (per-property prose) and catalog-authored `remediation` |

`stave.explain` and `stave.suggest_fix` re-run `stave.verify`
internally and project the named finding. The contract is
stateless on purpose — agents that retry or shard across
finding IDs don't need an open session.

## Wire format

JSON-RPC 2.0 over stdio. One message per line. The server
handles three MCP methods:

- `initialize` — handshake, returns `serverInfo` + protocol version
- `tools/list` — returns the three tools above with JSON Schema
- `tools/call` — invokes a tool

Tool results follow MCP's `{"content": [{"type": "text", "text": "<json>"}]}`
convention — the JSON body of the Stave response is encoded
as a string under `text` so the agent's MCP client gets a
consistent shape across all tools.

## Quick demo

```bash
stave/stave-mcp <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"stave.verify","arguments":{"observations_dir":"examples/iam-overpermission-wildcard/fixtures/before/observations","controls_dir":"examples/iam-overpermission-wildcard/controls","allow_unknown_input":true}}}
EOF
```

Three response envelopes come back on stdout — the third
contains the Assessment with `CTL.IAM.POLICY.RESOURCE.WILDCARD.001`
firing on the Lambda role.

## What this is not

- **Not an LLM client.** stave-mcp doesn't call an LLM. It's
  the inverse — an LLM agent calls into it.
- **Not a long-lived daemon over the network.** stdio only.
  No port, no auth, no TLS. The MCP convention is
  process-per-session via the agent's stdio transport.
- **Not a remediation engine.** `stave.suggest_fix` returns
  the engine's delta-path projection and the catalog's authored
  remediation prose. Applying any of it to cloud infrastructure
  is the agent's responsibility, not the server's.

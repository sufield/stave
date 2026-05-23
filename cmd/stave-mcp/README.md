# stave-mcp

A minimal Model Context Protocol (MCP) server that exposes
Stave's verification surface to AI agents (Claude Code, Cursor,
Copilot, etc.) over JSON-RPC 2.0 / stdio.

The premise: an agent proposes a configuration change, calls
`stave.verify` to check it against the catalog of formally-
authored controls, calls `stave.explain` if a finding fires,
calls `stave.suggest_fix` to read the deterministic delta-path
and remediation guidance the engine produced. Around that core
loop sit catalog-exploration tools (`stave.search`,
`stave.version`), pre-evaluation intelligence (`stave.gaps`,
`stave.readiness`), and comparative analysis (`stave.diff`,
`stave.compliance`).
Stave is the deterministic guardrail; the agent is the
probabilistic proposer. The separation is the point.

## Install

```bash
go install github.com/sufield/stave/cmd/stave-mcp@latest
```

This puts `stave-mcp` on your `$PATH` (in `$(go env GOPATH)/bin`).
Or build from a checkout:

```bash
cd stave && make mcp        # builds ./stave-mcp
```

The binary has no dependencies beyond `pkg/stave` and the Go
standard library — no MCP SDK is pulled into go.mod.

## Configuration

Point your MCP client at the `stave-mcp` binary over stdio. Ready-made
configs are in [`configs/`](configs/):

- **Claude Desktop** — merge [`configs/claude-desktop.json`](configs/claude-desktop.json)
  into `claude_desktop_config.json` (Settings → Developer → Edit Config).
- **VS Code** — merge [`configs/vscode-settings.json`](configs/vscode-settings.json)
  into your `settings.json`.
- **Cursor** — merge [`configs/cursor-settings.json`](configs/cursor-settings.json)
  into `~/.cursor/mcp.json`.

All three use the same shape:

```json
{ "mcpServers": { "stave": { "command": "stave-mcp", "args": [] } } }
```

For a **hosted / shared** deployment that must never receive snapshot
data, add `"args": ["--hosted"]` (or set `STAVE_MCP_HOSTED=true`) — see
[Deployment modes](#deployment-modes). The server manifest is
[`mcp.json`](mcp.json); a worked exchange is in
[`examples/demo-conversation.md`](examples/demo-conversation.md).

See the [main Stave README](../../README.md) for the engine itself.

## Tools exposed

| Tool | Inputs | Output |
|---|---|---|
| `stave.version` | _(none)_ | Build version + capability counts: controls, packs, frameworks, ATT&CK tactics, output formats |
| `stave.search` | `query` (required), optional `severity`, `limit` | Ranked capability catalog hits (control groups + operational features) for a free-form intent |
| `stave.catalog_explain` | `control_id` (required) | Catalog-only explanation of one control: description, severity, asset type, predicate, required observation fields, framework mappings. No observations needed |
| `stave.diff` | `before`, `after` | Structured delta between the newest snapshot in each directory: assets added/removed, per-property changes |
| `stave.gaps` | `observations_dir` (required), optional `top_n` | Absent observation fields and the controls each would unlock, ranked by impact |
| `stave.readiness` | `observations_dir` (required), optional `top_n` | Which controls can fire vs. are blocked, readiness score, ranked action plan |
| `stave.compliance` | `observations_dir`, `framework` | Requirement-level posture for one framework (met / not-met / not-evaluated, coverage %) |
| `stave.verify` | `observations_dir` (required), optional `controls_dir`, `allow_unknown_input`, `format` | Evaluation result. `format`: `summary` (default) — posture score, severity breakdown, top findings; `detailed` — adds per-finding predicate/observed/fix; `raw` — full Assessment JSON |
| `stave.dashboard` | `observations` (required), optional `controls`, `allow_unknown_input` | Renders an interactive HTML posture dashboard (gauge, severity bar, sortable/filterable findings table, SLA status) to a self-contained file; returns the path + a one-line summary |
| `stave.scorecard` | `observations` (required), optional `frameworks` | Renders an interactive HTML compliance scorecard — framework tabs, per-framework requirement breakdown with expandable failures, cross-framework comparison — to a self-contained file; returns the path + per-framework percentages. Compliance is evaluated against the embedded catalog |
| `stave.chains` | `observations` (required), optional `controls`, `chains`, `severity` | Detects compound risk chains and renders an interactive HTML visualizer — each chain's co-failing controls (legs) flowing into a compound-risk node, with attack narrative and break-any-link remediation. Zero chains is a good result. Needs a chains directory (defaults to `./chains`) |
| `stave.context` | `type` + `id` (required), `observations`, optional `framework`/`controls`/`chains` | Drill into one item: `finding`, `asset` (all its findings), `chain` (legs + narrative + assets), `requirement` (status + failing controls; needs `framework`), or `framework` (full posture). The model-side endpoint a UI selection maps onto |
| `stave.explain` | `observations_dir`, `finding_id` | One finding's `reasoning_trace`, `chain_membership`, `compliance` (finding-level; needs observations) |
| `stave.suggest_fix` | `observations_dir`, `finding_id` | One finding's `delta_paths` (per-property prose) and catalog-authored `remediation` |

`stave.explain` and `stave.suggest_fix` re-run `stave.verify`
internally and project the named finding. The contract is
stateless on purpose — agents that retry or shard across
finding IDs don't need an open session.

Every tool calls the `pkg/stave` library directly — never the
CLI binary, never the network. All evaluation is offline and
deterministic. The catalog-backed tools (`stave.version`,
`stave.search`, `stave.catalog_explain`) read the embedded builtin
catalog; chain-level entries and framework filtering on
`stave.search`, and chain membership on `stave.catalog_explain`, are
out of scope (chains need a chains directory; framework-scoped
queries belong to `stave.compliance`).

## Deployment modes

The server runs in one of two modes, selected by the `--hosted`
flag or the `STAVE_MCP_HOSTED=true` environment variable:

| Mode | How | Tools registered |
|---|---|---|
| **local** (default) | no flag | all 14 tools |
| **hosted** | `--hosted` or `STAVE_MCP_HOSTED=true` | catalog-query tools only: `stave.version`, `stave.search`, `stave.catalog_explain`, `stave.explain`, `stave.suggest_fix` |

The split is by data trust. **Catalog-query tools** read only the
embedded catalog — they never touch customer snapshot data, so they
are safe to run on a shared/hosted server. **Data tools**
(`stave.verify`, `stave.dashboard`, `stave.scorecard`, `stave.chains`,
`stave.context`, `stave.diff`, `stave.gaps`, `stave.readiness`,
`stave.compliance`) take filesystem paths to observation snapshots and
must run on the customer's own machine.

This separation is **architectural, not policy**: hosted mode
physically cannot receive snapshot data because the tools that
process it are not in its tool list. A data tool is omitted from
`tools/list` *and*, as defense in depth, a direct `tools/call` to
one is rejected:

```
This tool requires local installation. Snapshot data never leaves
your machine. Install the local binary:
go install github.com/sufield/stave/cmd/stave-mcp@latest
```

The `initialize` handshake reports the active mode so a client can
see the data policy up front:

```json
{ "serverInfo": { "mode": "hosted",
                  "data_policy": "catalog-only, no customer data accepted" } }
```

## Wire format

JSON-RPC 2.0 over stdio. One message per line. The server
handles three MCP methods:

- `initialize` — handshake, returns `serverInfo` + protocol version
- `tools/list` — returns the tools above with JSON Schema
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

## Live dashboard demo

`stave.dashboard` renders an interactive HTML posture dashboard — a
score gauge, severity breakdown, and a sortable/filterable findings
table — into a **self-contained file** (all CSS/JS inline, no network,
no storage). Three ways to use it, in order of "wow":

1. **Inside an MCP client** — call `stave.dashboard`; the tool saves
   the HTML and returns the path. Open it in a browser.
2. **No MCP setup at all** — the standalone flag evaluates a snapshot
   and writes the dashboard directly, for screen-sharing on a call:

   ```bash
   stave-mcp --demo-dashboard \
     --observations examples/demo-s3-public-read/fixtures/observations
   # → prints a file:// path; open it in any browser
   ```

3. **Text only** — for clients without HTML, `stave.verify` with the
   default `summary` format gives the same posture as structured text.

The compliance **scorecard** has the same standalone mode — framework
tabs, per-requirement PASS/FAIL with expandable failures, and a
cross-framework comparison bar:

```bash
stave-mcp --render-scorecard \
  --observations examples/demo-s3-public-read/fixtures/observations \
  --frameworks pci_dss_v4.0,cis_aws_v3.0
# → file:// path; tabs per framework, click a FAIL row to see the controls
```

This is the compliance iteration loop: see a framework's percentage,
expand its failing requirements, fix the controls, re-evaluate, watch
the number climb. Omitting `--frameworks` evaluates every available
framework in a single pass (`pkg/stave.ComplianceMulti` — one
evaluation over the union of mapped controls, not one per framework).

The **chain visualizer** shows what single-resource scanners can't —
the compound risk chains, rendered as each chain's co-failing controls
(its legs) flowing into a compound-risk node:

```bash
stave-mcp --render-chains \
  --observations examples/demo-ai-security/fixtures/writeup-config/observations
# → file:// path; click a chain to see its legs and the break-any-link fix
```

Chains need a chain-definition directory; the standalone flag and the
tool default to `./chains` (run from the project root, or pass an
explicit `chains` path). Zero chains is reported as a good result —
all risk is single-resource. The three views answer different
questions of the same evaluation: the dashboard shows *what's* wrong,
the scorecard *which frameworks* are affected, the chain visualizer
*how* the compound attack composes.

The HTML renders identically in Chrome, Firefox, and Safari — the
dashboard stays under 100 KB, the scorecard and chain visualizer
under 80 KB.

## Bidirectional interaction

The visualizers and `stave.context` form a two-way loop: the user
selects something in a UI, and the model drills in.

- **Model side (works today).** `stave.context` takes a `{type, id}`
  and returns the detail behind it — every finding on an `asset`, a
  `chain`'s legs and narrative, a `requirement`'s failing controls,
  a `framework`'s posture, or one `finding`. It works whenever the
  model has an ID: from a UI event, or from a user simply asking
  "what else is wrong with that bucket?"

- **UI side (event bridge).** Each visualizer emits a selection event
  when the user clicks a row/tab/node:

  | UI | Click | Event |
  |---|---|---|
  | dashboard | a finding row | `{kind:"asset", id:<asset>}` |
  | scorecard | a framework tab | `{kind:"framework", id:<fw>}` |
  | scorecard | a failing requirement | `{kind:"requirement", id:<req>, framework:<fw>}` |
  | chains | a chain | `{kind:"chain", id:<chain>}` |

  The event is `window.parent.postMessage({source:"stave", kind, id, …})`.

**The boundary, stated plainly:** the round-trip closes only when a UI
is rendered inside a host that forwards these events to the model and
maps `{kind, id}` to a `stave.context` call — i.e. an **MCP Apps**
client rendering a `ui://` resource. The current visualizers ship as
standalone HTML files, where `staveEmit` is a deliberate no-op (no
parent to receive the event). So `stave.context` is fully usable now;
the automatic UI→model leg is wired and waiting for MCP Apps host
support, not yet verifiable end to end.

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

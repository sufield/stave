# Your First Stave Evaluation

No cloud credentials. No Steampipe. No setup. Evaluate a bundled
example snapshot and read the result in about a minute.

Stave is a **risk reasoning engine**: it takes observation snapshots
(JSON describing your cloud state) plus a catalog of controls, and
produces deterministic verdicts. Same input → same output, every time.
All evaluation is offline — no network, no credentials.

> **Environment:** The commands below assume a [Coder workspace](../../stave-workspace/README.md) —
> `stave` on `$PATH`, examples at `~/examples/`. From a local clone
> ([README Option 3](../../README.md#option-3--local-install-contributors-and-power-users))
> they work the same; just run from the repo root.

## Step 1: Clone and run (60 seconds)

```bash
git clone https://github.com/sufield/stave.git
cd stave
make build                              # builds ./stave (and syncs embedded data)
bash examples/demo-ai-security/run.sh
```

The demo evaluates a fixture AWS account with a Bedrock AI agent. It
runs entirely against local JSON — `stave apply` exits `3` when it
finds violations, which is expected here.

> Not set up for Go yet? `make build` needs Go 1.26+. Or install the
> binary directly: `go install github.com/sufield/stave/cmd/stave@latest`
> (then run the demo with `STAVE_BIN=$(go env GOPATH)/bin/stave bash examples/demo-ai-security/run.sh`).

## Step 2: Understand the output

A Stave evaluation reports a **security state** for the snapshot:

| State | Meaning |
|---|---|
| `COMPLIANT` | No violations. No approaching-threshold risk signals. |
| `AT_RISK` | No active violations, but at least one invariant is approaching its unsafe-duration threshold. |
| `NON_COMPLIANT` | At least one active violation — an invariant the snapshot breaks right now. |

Each **finding** is one control firing on one asset: a control ID
(e.g. `CTL.S3.PUBLIC.001`), the asset, a severity, and the message.

**Chain findings** are Stave's distinctive output: a *compound* risk
where several individually-acceptable conditions stack into an
exploitable path. The demo fires three critical Bedrock chains — see
[03-reading-chain-findings.md](./03-reading-chain-findings.md).

## Step 3: Evaluate your own snapshot

Point `apply` at a directory of `obs.v0.1` snapshot files:

```bash
stave apply --observations /path/to/your/obs/
stave apply --observations /path/to/your/obs/ --format json   # machine-readable
```

Exit codes: `0` = no violations · `2` = input error · `3` = violations
found · `4` = internal error. Use `--eval-time 2026-01-15T00:00:00Z` to pin
the clock for byte-identical, reproducible output.

Don't have snapshots yet? If you already run Steampipe, see
[01-from-steampipe-to-stave.md](./01-from-steampipe-to-stave.md).

## Step 4: Use it from Claude Desktop (optional)

Stave ships an MCP server so an AI assistant can call it in
conversation:

```bash
go install github.com/sufield/stave/cmd/mcp@latest
```

Add the config from [`cmd/mcp/configs/claude-desktop.json`](../../cmd/mcp/configs/claude-desktop.json)
to your Claude Desktop config, then ask: *"Evaluate the snapshot in
./obs"* — the model calls the `stave.verify` tool and summarizes the
result. See [`cmd/mcp/README.md`](../../cmd/mcp/README.md).

---

**Next:**
- Reading the compound risks → [03-reading-chain-findings.md](./03-reading-chain-findings.md)
- You collect with Steampipe → [01-from-steampipe-to-stave.md](./01-from-steampipe-to-stave.md)

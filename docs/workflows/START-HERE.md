# Welcome to Stave

Your workspace is ready. Everything is pre-installed: `stave`,
`stave-mcp`, Steampipe (with the AWS plugin), the full control
catalog, the chain catalog, the example snapshots, and every workflow
guide. **No setup. No build step.**

## Your first evaluation (60 seconds)

```bash
bash ~/examples/demo-ai-security/run.sh
```

That just evaluated a fixture AWS account against 2,650+ controls
and 585+ compound-risk chains — entirely offline, against local
JSON, in about a second. The exit code is `3` because the demo
deliberately has violations; that's expected.

## What you're looking at

The output reports an evaluation in three layers:

- **Security state** — `COMPLIANT` / `AT_RISK` / `NON_COMPLIANT`,
  the snapshot's overall verdict.
- **Findings** — each one is a control firing on a specific asset.
- **Chain findings** — compound risks where several individually-
  acceptable conditions stack into an exploitable path. This is the
  category single-resource scanners can't see.

## See it visually (30 seconds)

The three visualizers each render a self-contained HTML file:

```bash
# Posture dashboard — score, severity breakdown, sortable findings
stave-mcp --demo-dashboard \
  --observations ~/examples/demo-ai-security/obs

# Compliance scorecard — per-framework requirement breakdown
stave-mcp --render-scorecard \
  --observations ~/examples/demo-ai-security/obs \
  --frameworks hipaa,pci_dss_v4.0

# Risk chain visualizer — each compound's legs flowing into a node
stave-mcp --render-chains \
  --observations ~/examples/demo-ai-security/obs
```

Each prints a `file://` path. Open it in your workspace's browser
panel.

## Try your own snapshot

If you have AWS credentials configured in this workspace, produce
your own `obs.v0.1` snapshot with Steampipe (the field mapping is
documented in [01-from-steampipe-to-stave.md](./01-from-steampipe-to-stave.md)):

```bash
mkdir -p ~/obs
steampipe query "$(cat ~/guides/01-from-steampipe-to-stave.md \
  | sed -n '/```sql/,/```/p' | sed '1d;$d')" --output json \
  | jq '{schema_version:"obs.v0.1", captured_at:(now|todate), source:"steampipe", assets:.}' \
  > ~/obs/s3.json

stave apply --observations ~/obs/
```

No AWS access? That's fine — keep exploring with the bundled examples:

```bash
ls ~/examples/                              # all demos
ls ~/examples/demo-ai-security/fixtures/    # writeup-config + remediated-config
```

## Where to go next

| Goal | Guide |
|---|---|
| Connect your Steampipe output to Stave | [01-from-steampipe-to-stave.md](./01-from-steampipe-to-stave.md) |
| Detailed evaluation walkthrough | [02-first-evaluation.md](./02-first-evaluation.md) |
| Understand compound (chain) risk | [03-reading-chain-findings.md](./03-reading-chain-findings.md) |
| Fix a finding and prove it's fixed | [04-fix-and-verify.md](./04-fix-and-verify.md) |
| Generate auditor-ready compliance evidence | [05-compliance-evidence.md](./05-compliance-evidence.md) |
| Add Stave to a CI/CD gate | [06-ci-pipeline-gate.md](./06-ci-pipeline-gate.md) |

All guides are also at `~/guides/`.

## Use Stave from an AI assistant (MCP)

The MCP server is on `$PATH`. From Claude Desktop, VS Code with MCP,
or any client that speaks the MCP stdio protocol, configure it to
launch:

```json
{ "mcpServers": { "stave": { "command": "stave-mcp", "args": [] } } }
```

The server exposes 14 tools — `stave.verify`, `stave.dashboard`,
`stave.scorecard`, `stave.chains`, `stave.compliance`,
`stave.context`, `stave.search`, `stave.catalog_explain`, and more.
Try:

> *"Evaluate the snapshot in ~/examples/demo-ai-security/obs."*
> *"Explain CTL.S3.PUBLIC.001."*
> *"Search for encryption controls."*

Ready-made client configs are at `/opt/stave/examples/` and in the
upstream repo at [`cmd/stave-mcp/configs/`](https://github.com/sufield/stave/tree/main/cmd/stave-mcp/configs).

---

**Two operating modes worth knowing about:**

- **Local mode (default in this workspace)**: all 14 tools registered;
  snapshot-touching tools evaluate observation paths on this machine.
- **Hosted mode** (`stave-mcp --hosted` or `STAVE_MCP_HOSTED=true`):
  only catalog-query tools registered; data tools omitted *and*
  rejected on direct call. For when stave-mcp runs on a shared host
  where customer snapshot data must never land.

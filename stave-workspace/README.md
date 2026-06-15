# Stave Coder workspace template

A Coder workspace template that gives adopters a fully-configured
Stave environment in one click: `stave` and `stave-mcp` pre-built and
on `$PATH`, Steampipe (with the AWS plugin) installed, the full
control and chain catalogs available at `~/chains` and
`~/stave/controls`, every bundled example at `~/examples`, every
workflow guide at `~/guides`, and the MCP server running in the
background ready for an AI client to connect.

**Zero setup.** First evaluation in under 60 seconds:

```bash
bash ~/examples/demo-ai-security/run.sh
```

## What's in the workspace

| Tool / file | Where | What |
|---|---|---|
| `stave` | `/usr/local/bin/stave` | The CLI, built from `cmd/stave` |
| `stave-mcp` | `/usr/local/bin/stave-mcp` | The MCP server, built from `cmd/mcp` |
| Control catalog | `/opt/stave/controls` (also `$STAVE_CONTROLS`) | 2,650+ controls |
| Chain catalog | `/opt/stave/chains` (also `$STAVE_CHAINS`, `~/chains`) | 585+ compound-risk chains |
| Examples | `/opt/stave/examples` (also `~/examples`) | Demo snapshots + `run.sh` per scenario |
| Workflow guides | `/opt/stave/guides` (also `~/guides`) | `START-HERE.md` + the six numbered guides |
| Steampipe | `/usr/local/bin/steampipe` | With the AWS plugin pre-installed |
| Go toolchain | `/usr/local/go` | For rebuilding from source or custom tooling |

## Importing the template into Coder

From a checkout of the Stave repo (this directory is at `stave-workspace/`
in that tree):

```bash
# From the stave module root:
coder templates push stave --directory stave-workspace
```

The template uses Coder's Docker provider — works with Coder OSS, no
Premium-only features. It builds the workspace image from
`stave-workspace/Dockerfile` (the build context is the stave module
root one level above this directory, so the Dockerfile's `COPY
controls/ …` directives reach the canonical sources).

## Creating a workspace

```bash
coder create my-stave --template stave
```

At create time you can override the **Git repository** parameter to
clone your own fork into `~/stave` (the workspace also ships a
read-only copy of the repo content at `/opt/stave/` regardless).

## Customizing

The Dockerfile pins everything explicitly: Go toolchain (matches
`go.mod`'s `toolchain` directive), Steampipe version, Ubuntu base.
To bump a version, edit the `ARG` lines at the top of the Dockerfile
and re-`coder templates push`.

To install additional Steampipe plugins (e.g. GCP, Kubernetes), add
them to the Dockerfile's plugin-install step or run inside the
workspace after creation:

```bash
steampipe plugin install gcp
```

To skip the auto-clone of `~/stave` (e.g. you only need the
read-only `/opt/stave/` tree), edit the agent `startup_script` in
`main.tf`.

## What this template does *not* do

- **It does not install code-server.** Coder typically provisions
  IDEs as a separate concern. The `coder_app.code-server` resource
  in `main.tf` expects code-server to be available on the agent —
  add an install step to the Dockerfile or use a Coder bundle that
  ships code-server if you want the in-browser IDE.
- **It does not include AWS credentials.** Adopters configure their
  own `aws configure` inside the workspace if they want to evaluate
  their own snapshots. The bundled examples run entirely offline.
- **It does not preinstall non-AWS Steampipe plugins.** GCP, Azure,
  Kubernetes, and others are one `steampipe plugin install` away —
  not bundled to keep the image lean.

## A note on what's verified vs. what depends on your Coder install

The Dockerfile's commands, flags, and paths are all verified against
the live Stave CLI (build path, every `--render-*` / `--demo-*`
flag, the `stave features` control-count line used by the sidebar
metadata, the example `obs/` symlink that makes the START-HERE
commands short). The Coder template itself follows Coder's
documented Docker-provider pattern, but the first `coder templates
push` on a fresh Coder instance is where you'll find any
environment-specific edges (Docker socket access, host networking,
volume permissions); the template above keeps those choices simple
(`bridge` networking, named home volume, `share = "owner"` on apps)
to minimize surface area for adoption.

## Related

- [`Dockerfile`](./Dockerfile) — the workspace image (iteration 1).
- [`motd.sh`](./motd.sh) — terminal banner shown on every shell.
- [`docs/workflows/START-HERE.md`](../docs/workflows/START-HERE.md) —
  what the agent prints on workspace launch.
- [`docs/workflows/`](../docs/workflows/) — the six numbered
  workflow guides.
- [`cmd/mcp/README.md`](../cmd/mcp/README.md) — MCP
  server protocol, tool list, hosted-mode details.

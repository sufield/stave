# Stave DigitalOcean 1-Click App image

Packer build for the Stave Marketplace image. Same install logic as
the Coder workspace [`Dockerfile`](../Dockerfile) (iteration 1),
adapted for a DO droplet snapshot — one source of truth, two
delivery formats.

**Persona:** the solo security engineer or 5-person startup who needs
to evaluate their AWS posture for a SOC 2 audit in six weeks, has no
Coder instance, and wants a $6/month droplet that "just works."

## What's pinned in the image

| Component | Version | Source |
|---|---|---|
| Ubuntu base | `ubuntu-24-04-x64` | DO snapshot base |
| Go toolchain | `1.26.3` | matches `go.mod`'s `toolchain` directive |
| Steampipe | `1.0.0` | matches the Coder Dockerfile |
| AWS plugin | latest at build time | `steampipe plugin install aws` |
| Stave | `$STAVE_REF` (default `main`) | built from source on the droplet |
| Stave MCP server | same ref | built from source on the droplet |

For a production marketplace submission, pin `STAVE_REF` to a release
tag (`v0.5.0` etc.) so the image's contents are reproducible from the
build environment.

## Prerequisites

```bash
# Packer 1.7+ (HCL2-capable, plugin-aware)
packer version

# DigitalOcean plugin (Packer 1.7 split plugins out)
packer plugins install github.com/digitalocean/digitalocean

# A DO API token with read+write scope
export DO_API_TOKEN=dop_v1_…
```

## Build

From this directory:

```bash
# Optional: pin the Stave version (recommended for marketplace submissions)
export STAVE_REF=main           # or v0.5.0

packer init   marketplace-image.json
packer build  marketplace-image.json
```

Packer spins up a temporary `s-2vcpu-2gb` build droplet (`go build`
needs more than 1 GB), runs [`setup.sh`](./setup.sh), runs
[`cleanup.sh`](./cleanup.sh), snapshots, then destroys the build
droplet. The resulting snapshot name is `stave-<timestamp>`; the ID
is in Packer's final output line and visible in your DO control
panel under Snapshots.

> The snapshot can be applied to any droplet size whose disk is at
> least the snapshot's. The $6/mo `s-1vcpu-1gb` production target
> works — the larger build droplet is only for the build itself.

## Test before submitting

```bash
# Create a droplet from the snapshot (use the smallest production size)
doctl compute droplet create stave-test \
    --image  <snapshot-id> \
    --size   s-1vcpu-1gb \
    --region nyc3 \
    --ssh-keys $(doctl compute ssh-key list --format ID --no-header | head -1)

# SSH in and walk the START-HERE workflow
ssh root@<droplet-ip>
# (MOTD prints the quick-start commands)

bash ~/examples/demo-ai-security/run.sh
stave-mcp --demo-dashboard --observations ~/examples/demo-ai-security/obs
stave features
```

The full sanity-check set the Packer cleanup runs is in
[`cleanup.sh`](./cleanup.sh) — `stave version`, `stave-mcp --help`,
`steampipe --version`, `stave features`. If any of those fail at
runtime, the snapshot is broken and the marketplace submission
should not be made.

## Validate before submission

The Packer template's middle provisioner pulls DigitalOcean's
canonical validator (`marketplace-partners/scripts/img_check.sh`)
during the build, so a clean Packer build that ships its snapshot
is already validation-clean against the live ruleset. If you want
to re-run validation against an existing droplet:

```bash
ssh root@<droplet-ip> 'curl -fsSL \
    https://raw.githubusercontent.com/digitalocean/marketplace-partners/master/scripts/img_check.sh \
    | bash -s -- -t apps'
```

## Submit to DO Marketplace

Submission is via the Vendor Portal:
<https://marketplace.digitalocean.com/vendors>

You'll need:

- The snapshot ID (from Packer's output).
- The listing copy in [`listing.md`](./listing.md).
- Screenshots: SSH-in MOTD + a dashboard render.
- Your support contact.

The DO team reviews the snapshot against the same `img_check.sh`
ruleset plus a human review of the listing and security posture.
Expect ~2 weeks for the first review pass.

## What this image does *not* do

- **No pre-configured AWS credentials.** Adopters run
  `aws configure` themselves before pointing Steampipe at their
  account. The bundled examples run entirely offline so the demo
  works on a fresh droplet with no AWS setup.
- **No code-server / IDE.** The droplet is SSH-first. Adopters who
  want an editor install one inside the droplet or use the Coder
  workspace template instead.
- **No non-AWS Steampipe plugins.** GCP / Azure / Kubernetes are
  one `steampipe plugin install` away — not bundled to keep the
  image lean for the $6 runtime target.

## A note on what's verified vs. environment-dependent

This sandbox has no DigitalOcean account, no Packer binary, and no
`packer build` access — every command, version, and path inside
the scripts is verified against the live Stave CLI or the canonical
sources (Go toolchain matches `go.mod`, build paths match the
`cmd/{stave,stave-mcp}` layout, `--demo-dashboard` / `--render-*`
match the binary flags, the `obs` symlink matches the real fixtures
layout), but actual snapshot assembly, image size on disk, the
$6-droplet runtime fit, and `img_check.sh` results need a `packer
build` pass against a real DO account.

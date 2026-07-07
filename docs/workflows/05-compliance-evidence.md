# Generate Compliance Evidence

Your auditor wants evidence. Stave produces it deterministically — the
same snapshot always yields the same verdicts, so the artifact is a
verifiable record, not a point-in-time screenshot.

> **Environment:** `stave-mcp --render-scorecard` and `stave apply
> --format json` are on `$PATH` in the [Coder workspace](../../stave-workspace/README.md)
> and after [README Option 3](../../README.md#option-3--local-install-contributors-and-power-users)
> install. The `./obs/` path is wherever your collector saves
> snapshots; `~/examples/demo-s3-public-read/obs` in the workspace
> is a quick sanity-check target.

## Step 1: Render a compliance scorecard

```bash
stave-mcp --render-scorecard \
  --observations ./obs/ \
  --frameworks hipaa,pci_dss_v4.0,soc2
```

This prints a `file://` path to a self-contained HTML scorecard. It
evaluates all requested frameworks in a single pass and shows:

- a tab per framework with its overall compliance percentage,
- each requirement as PASS / FAIL / N-A,
- click a failing requirement to expand the specific controls that
  failed, on which assets,
- a cross-framework comparison bar (lowest first = highest priority).

> See available framework IDs with `stave-mcp` is not needed — the
> common ones are `hipaa`, `pci_dss_v4.0`, `cis_aws_v3.0`,
> `fedramp_moderate`, `soc2`. Omit `--frameworks` to score them all.
>
> **What the percentage means:** it's *requirement coverage* — the
> fraction of a framework's requirements whose mapped controls pass.
> A snapshot can be `NON_COMPLIANT` overall yet show 100% on a
> framework whose mapped controls all pass; unmapped failures don't
> lower that framework's number.

## Step 2: Export the machine-readable evidence

The scorecard is for humans; the JSON is for the record:

```bash
mkdir -p evidence
stave apply --observations ./obs/ --format json \
  --eval-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  > evidence/$(date +%Y%m%d).json
```

Pin `--eval-time` so the output is byte-stable. This JSON is deterministic
evidence: same input, same output, every time. Hand it to the auditor
alongside the scorecard. For a sealed, signed evidence package for
air-gapped GRC, see `stave bundle` and `stave attest`.

## Step 3: Show improvement over time

Two dated evaluations *are* the compliance narrative:

```bash
ls evidence/
#   20260115.json   ← last quarter
#   20260420.json   ← now
```

The delta in framework coverage is the story you tell:

> "We were at 68% HIPAA requirement coverage last quarter. We're at
> 84% now, and here are the deterministic evaluations that prove it."

Because the verdicts are reproducible, anyone can re-run the same
snapshot and get the same number — the evidence defends itself.

---

**Next:** Stop regressions from eroding the gains → [06-ci-pipeline-gate.md](./06-ci-pipeline-gate.md)

# S3 Assessment Workflow

This is the supported S3 MVP workflow for the current CLI surface.

## Golden Path

```text
extract (external) -> validate -> apply -> verify
```

## 1) Extract observations from an offline AWS snapshot

Use an extractor (any language) to produce `obs.v0.1` JSON from your AWS snapshot directory. See [Building an Extractor](extractor-prompt.md) for a jumpstart template, or use an existing extractor such as `stave-extractor`.

Input:
- Snapshot directory with AWS CLI exports (`list-buckets.json`, `get-bucket-*` files)

Output:
- `observations.json` (`obs.v0.1`)

## 2) Evaluate observations against the S3 control pack

```bash
stave apply --profile aws-s3 --input observations.json --include-all --now 2026-01-15T00:00:00Z > evaluation.json
```

Input:
- `observations.json`
- Built-in S3 controls under `controls/s3`

Output:
- `evaluation.json` (`out.v0.1`)
- Exit code `3` when violations are found

## 3) Verify remediation (before vs after)

```bash
stave verify \
  --before ./obs-before \
  --after ./obs-after \
  --controls ./controls/s3 \
  --now 2026-01-15T00:00:00Z \
  --out ./output
```

Input:
- Before/after observations directories
- Controls directory

Output:
- stdout JSON verification summary
- `output/verification.json` when `--out` is set

## Notes

- Offline by design: reads local files only.
- Deterministic in CI: always set `--now`.
- For troubleshooting unexpected results, run `stave diagnose`.

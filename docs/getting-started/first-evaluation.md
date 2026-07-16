# First Evaluation

Run Stave against demo fixtures — no AWS account needed.

## Quick demo

```bash
# Build from source (or: go install github.com/sufield/stave/cmd/stave@latest)
cd stave && make build

# Run the AI security demo — shows what your CSPM misses
bash examples/demo-ai-security/run.sh
```

## Step-by-step

```bash
# 1. Evaluate a public-bucket scenario
./stave apply \
  --observations examples/public-bucket/observations/ \
  --eval-time 2025-01-01T00:00:00Z

# 2. See what controls matched
./stave catalog --service s3

# 3. Try a compound chain scenario
./stave apply \
  --observations examples/imds-ssrf-chain/observations/ \
  --eval-time 2025-01-01T00:00:00Z
```

## What's next

- [Import your own snapshots](import-snapshots.md) — bring real data
- [CI integration](ci-integration.md) — gate merges on findings
- Browse [114 examples](../../examples/README.md) for scenarios close to your environment

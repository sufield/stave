# Generate Evidence Packets

Produce tamper-evident bundles for auditors. An evidence packet
includes the evaluation output, the observations used, and a
cryptographic signature tying them together.

## Create a bundle

```bash
# doctest:skip — creates output directory and files
# Run evaluation and bundle the results
stave bundle audit \
  --framework hipaa \
  --period Q2-2026 \
  --out evidence-2026-Q2
```

## Sign and verify

```bash
# doctest:skip — creates key files and requires snapshot
# One-time key setup
stave attest keygen --out stave-attest

# Sign a snapshot
stave attest sign --snapshot ./snapshot.json --key stave-attest.pem

# Verify a snapshot wasn't altered
stave attest verify --snapshot ./snapshot.json --key stave-attest.pub
```

## Sanitize before sharing

```bash
# doctest:skip — requires single snapshot file, writes to stdout
# Remove infrastructure identifiers
stave sanitize --snapshot ./snapshot.json > sanitized.json
```

See also: `stave bundle --help` for all bundling options.

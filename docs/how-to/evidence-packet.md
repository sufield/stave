# Generate Evidence Packets

Produce tamper-evident bundles for auditors. An evidence packet
includes the evaluation output, the observations used, and a
cryptographic signature tying them together.

## Create a bundle

```bash
# doctest:skip — requires observation data
# Run evaluation and bundle the results
stave bundle audit \
  --observations ./snapshots/ \
  --output evidence-2026-Q2.tar.gz
```

## Sign and verify

```bash
# doctest:skip — requires observation data and key setup
# One-time key setup
stave attest keygen

# Sign a snapshot
stave attest sign --observations ./snapshots/

# Verify a snapshot wasn't altered
stave attest verify --observations ./snapshots/
```

## Sanitize before sharing

```bash
# doctest:skip — requires observation data
# Remove infrastructure identifiers
stave sanitize --observations ./snapshots/ --output ./sanitized/
```

See also: `stave bundle --help` for all bundling options.

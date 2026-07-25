# Use Compliance Lenses

Map Stave findings to compliance frameworks — CSA AI Controls Matrix
and more as frameworks are added.

## Check mapping integrity

```bash
# Verify the framework mapping references real controls (no snapshot needed)
stave compliance --verify-mapping
```

## Check compliance posture

```bash
# doctest:skip — requires observation snapshot and freshness-threshold config
# Evaluate against a framework
stave compliance --framework aicm-v1.1 --snapshot ./snapshots/

# Export evidence for auditors
stave export compliance --profile aicm-v1.1 --snapshot ./snapshot.json
```

## Available frameworks

See [compliance frameworks](../reference/compliance-frameworks.md) for the
full list with coverage details.

## Scorecard

```bash
# doctest:skip — requires observation snapshot
# Posture across several frameworks at once
stave scorecard --snapshot ./snapshots/
```

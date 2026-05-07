# Stale Staging Endpoint Detection

Demonstrates `CTL.LIFECYCLE.STAGING.STALE.001` — an
environment-tag-aware staleness control that complements
the existing per-service dormancy controls
(`CTL.CLOUDFRONT.LIFECYCLE.DORMANT.001`,
`CTL.APIGATEWAY.ORPHAN.API.001`, etc.) without replacing
them.

## The gap this control closes

Per-service dormancy controls fire on the lifecycle
signal alone — environment-agnostic. A production warm-
standby that hasn't received traffic in 90 days is
indistinguishable from a forgotten staging API that
hasn't been deployed in 247 days. Both fire the
service-specific dormant control. Both should be
investigated; the *response* is different. Production
dormancy is a "schedule a review" finding; staging
dormancy is a "decommission this" finding.

This control adds the missing dimension: it fires only
when an asset's `tags.environment` is in a non-
production set (`staging, dev, test, qa, sandbox, demo,
poc, prototype, ...`) AND a dormancy signal is true. It
reuses the same lifecycle fields existing controls
already populate — `appears_unused`, `is_dormant`,
`last_request_days`, `last_deployment_days`. It does not
redefine staleness; it *filters* by environment intent.

## Four scenarios

| Scenario | environment | dormant | STALE.001 | Notes |
|---|---|---|---|---|
| `stale-staging` | staging | yes | **fires** | Sprint-42 demo, 247 days idle |
| `active-staging` | staging | no | silent | Within threshold — normal staging activity |
| `prod-dormant` | production | yes | **silent** | Production tag blocks the staging-specific control. Per-service dormancy controls may still fire — they're orthogonal. |
| `stale-staging-public` | demo | yes + public | **fires** + S3.PUBLIC.LIST also fires | Compound: chain `staging_endpoint_exposed` triggers, escalating compound severity to HIGH |

The `prod-dormant` row is the critical negative test.
If `CTL.LIFECYCLE.STAGING.STALE.001` fired here, the
control would just be a relabeled dormancy check. The
silent verdict proves environment awareness.

## Compound chain

`chains/staging_endpoint_exposed.yaml` lists the new
control alongside the canonical public-access controls
(`CTL.S3.PUBLIC.005`, `CTL.S3.PUBLIC.LIST.002`,
`CTL.EC2.SG.INGRESS.CIDR.001`,
`CTL.APIGATEWAY.NETWORK.PRIVATE.POLICY.001`,
`CTL.ELB.NETWORK.INTERNAL.PUBLICSUBNET.001`) with
`escalation_threshold: 2` and `compound_severity: high`.
Whenever STALE.001 + any one of those public-access
controls fire on the same asset, the compound finding
escalates to HIGH.

The `stale-staging-public` fixture is a `demo`-tagged
S3 bucket with `appears_unused: true` and
`access.public_list: true` — fires both STALE.001 and
S3.PUBLIC.LIST.002, satisfying the chain.

## Run

```bash
cd stave
go run ./examples/staging-stale-endpoint
```

Expected output: 4 scenarios, all assertions pass,
exit 0. Compare against `expected/output.txt` for
byte-for-byte determinism.

## Layout

```
examples/staging-stale-endpoint/
├── README.md                    # this file
├── main.go                      # 4-scenario runner + assertions
├── controls/                    # local copy of the two relevant controls
│   ├── CTL.LIFECYCLE.STAGING.STALE.001.yaml
│   └── CTL.S3.PUBLIC.LIST.002.yaml
├── fixtures/
│   ├── stale-staging/observations/{T1,T2}.json
│   ├── active-staging/observations/{T1,T2}.json
│   ├── prod-dormant/observations/{T1,T2}.json
│   └── stale-staging-public/observations/{T1,T2}.json
└── expected/
    └── output.txt               # captured golden
```

## Compliance

Maps to **OWASP NHI1 — Improper Offboarding** (the
canonical non-human-identity offboarding failure). Also
covers **NIST 800-53 r5 CM-2** (configuration baselining
including decommissioning) and **SOC2 CC8.1** (system
change management).

## What this control is NOT

- **NOT a replacement for per-service dormancy
  controls.** Those still fire on production dormant
  resources where the response is "investigate."
- **NOT a new staleness detector.** The lifecycle
  signals (`is_dormant`, `appears_unused`, `last_*_days`)
  are already populated by extractors and consumed by
  per-service controls. This control only adds the
  environment-tag filter.
- **NOT compound-severity by itself.** Severity is
  MEDIUM; the chain is what escalates to HIGH when the
  stale non-prod resource is also publicly reachable.

## Extension points

The non-production tag values and threshold are
parameters in the control YAML. Organizations whose
tagging convention uses `Environment` (capital E),
`env`, or `stage` as the key — or `staging-eu`,
`uat`, etc. as values — extend the
`unsafe_predicate.all[0].any` block to add their tag
keys/values. The lifecycle fields are exhaustive only
for the services Stave currently extracts; new services
that introduce `properties.<svc>.lifecycle.appears_unused`
or similar add to the second `any` block.

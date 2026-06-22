# Cognito Iteration 7 — Federation Providers (SAML / OIDC / Social)

End-to-end fixtures for the Iteration 7 federation-provider
hygiene controls. No compound chain defined for this iteration
in the catalog or the plan.

```
12 individual controls   (writeup → all fire ; remediated → 0)
 0 compound chains
```

## Controls covered

All 12 evaluate on a single `cognito_user_pool` asset. Each
predicate reduces to a pre-computed boolean — same
denormalisation pattern as previous iterations.

| Control | Predicate signal |
|---|---|
| `CTL.COGNITO.SAML.METAEXPIRED.001`  | `saml_metadata_expired == true` |
| `CTL.COGNITO.SAML.NOREFRESH.001`    | `saml_metadata_static == true` (no auto-refresh URL) |
| `CTL.COGNITO.SAML.NOSIGN.001`       | `saml_assertion_signed == false` |
| `CTL.COGNITO.SAML.NOENCRYPT.001`    | `saml_assertion_encrypted == false` |
| `CTL.COGNITO.SAML.CERTEXPIRED.001`  | `saml_signing_cert_expired == true` |
| `CTL.COGNITO.SAML.ATTRMAP.001`      | `saml_attribute_mapping_complete == false` |
| `CTL.COGNITO.OIDC.ISSUER.001`       | `oidc_issuer_reachable == false` |
| `CTL.COGNITO.OIDC.SECRETROT.001`    | `oidc_secret_rotation_overdue == true` |
| `CTL.COGNITO.OIDC.SCOPEBROAD.001`   | `oidc_scopes_broad == true` |
| `CTL.COGNITO.SOCIAL.TESTCREDS.001`  | `social_uses_test_credentials == true` |
| `CTL.COGNITO.SOCIAL.NOVERIFY.001`   | `social_email_marked_verified == false` |
| `CTL.COGNITO.SOCIAL.ANYDOMAIN.001`  | `social_allows_any_domain == true` |

## Run

```bash
cd <repo-root>/stave
make build

./stave apply \
    --observations examples/cognito-iteration7-federation/fixtures/writeup-config/observations \
    --now 2026-05-09T12:00:00Z --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(SAML|OIDC|SOCIAL)"))] | map(.control_id) | sort | unique), chains: (.chain_findings // [] | map(.chain))}'

./stave apply \
    --observations examples/cognito-iteration7-federation/fixtures/remediated-config/observations \
    --now 2026-05-09T12:00:00Z --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(SAML|OIDC|SOCIAL)"))] | length), chains: (.chain_findings // [] | length)}'
```

Expected:

```
writeup     → 12 ctls, 0 chains
remediated  → 0, 0
```

## Catalog observation: collector probes the network

Several Iteration 7 checks describe network conditions the
catalog reduces to per-asset booleans:

- `saml_metadata_expired` — collector fetched the metadata URL
  and parsed `validUntil`
- `oidc_issuer_reachable` — collector hit `/.well-known/openid-configuration`
  and got a valid response
- `saml_signing_cert_expired` — collector parsed the signing
  cert and compared `NotAfter`

This works the same way the Iteration 1 ghost-trigger family
did: the collector does the dynamic check (HTTP fetch, cert
parse, ARN existence cross-check), Stave reads the resulting
boolean. It works under one explicit assumption: **the
collector ran recently enough that its booleans reflect
current state**. A SAML metadata URL that was reachable an
hour ago but went down 5 minutes ago will still report
reachable until the next collection cycle.

The plan flagged this as VPN-restriction risk for SAML
metadata reachability checks. The collector contract that
addresses it lives outside Stave (collector freshness, retry
on transient failure, user-controlled VPN bridge) — not an
engine concern.

## Why no compound chain

The plan listed 0 compound chains for Iteration 7, and the
catalog ships none. Each federation-provider misconfiguration
is independently actionable — there's no "12 of 12 means a
worse outcome than the sum" shape that justifies a compound.
Future iterations may add a "broken federation" compound
(e.g. `cognito_ghost_idchain` from Iteration 1 already covers
some of this — IDPOOL ghost + SAMLMETA ghost + DOMAINCERT
ghost + DOMAINDNS ghost), but this iteration ships the
individual controls and stops.

## What this iteration shipped

- **12 individual controls** for SAML / OIDC / social
  federation hygiene fire end-to-end on a single
  `cognito_user_pool` asset.
- **No compound chain** — by design.

No Stave engine changes required. Same trajectory as
Iterations 3-6 — catalog content + fixtures only.

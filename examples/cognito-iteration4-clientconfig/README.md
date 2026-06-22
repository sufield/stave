# Cognito Iteration 4 — App Client Configuration

End-to-end fixtures for the Iteration 4 OAuth-flow / token /
callback-URL controls plus the two compound chains. Single
asset type (`aws_cognito_user_pool_client`), single-asset
chain composition — no `scope_field` needed, no marker
controls needed. Same shape as Iteration 3.

```
15 individual controls   (13 plan + ENUMERATION + TOKEN.REVOCATION as catalog extras)
 2 compound chains       (cognito_client_openredirect, cognito_client_longtoken)
```

## Controls covered

All 15 evaluate on a single `aws_cognito_user_pool_client`
asset with `kind: cognito_app_client`. Each predicate reduces
to a pre-computed boolean (the same denormalisation pattern
as Iterations 2 and 3 — collector evaluates the OAuth shape
and stamps a single flag).

| Control | Predicate signal |
|---|---|
| `CTL.COGNITO.CLIENT.NOSECRET.001`        | `is_public_client == false AND has_client_secret == false` |
| `CTL.COGNITO.CLIENT.IMPLICITFLOW.001`    | `allows_implicit_flow == true` |
| `CTL.COGNITO.CLIENT.ALLFLOWS.001`        | `allows_all_flows == true` |
| `CTL.COGNITO.CLIENT.CLIENTCREDS.001`     | `mixes_user_and_m2m == true` |
| `CTL.COGNITO.CLIENT.ACCESSTTL.001`       | `access_token_too_long == true` |
| `CTL.COGNITO.CLIENT.IDTTL.001`           | `id_token_too_long == true` |
| `CTL.COGNITO.CLIENT.REFRESHTTL.001`      | `refresh_token_too_long == true` |
| `CTL.COGNITO.CLIENT.HTTPCALLBACK.001`    | `callback_has_http == true` |
| `CTL.COGNITO.CLIENT.LOCALHOST.001`       | `callback_has_localhost == true` |
| `CTL.COGNITO.CLIENT.WILDCARDCB.001`      | `callback_has_wildcard == true` |
| `CTL.COGNITO.CLIENT.NOLOGOUT.001`        | `has_logout_url == false` |
| `CTL.COGNITO.CLIENT.ALLSCOPES.001`       | `allows_all_scopes == true` |
| `CTL.COGNITO.CLIENT.ATTRRW.001`          | `client_attribute_rw_all == true` |
| `CTL.COGNITO.CLIENT.ENUMERATION.001`     | `security.prevent_user_existence_errors == false` |
| `CTL.COGNITO.CLIENT.TOKEN.REVOCATION.001`| `auth.token_revocation_enabled == false` |

## Compound chains

| Chain | Members | Threshold | Compound severity | Fires on |
|---|---|---|---|---|
| `cognito_client_openredirect` | IMPLICITFLOW, WILDCARDCB, HTTPCALLBACK | 2 | critical | open-redirect-config (2 of 3) |
| `cognito_client_longtoken`    | ACCESSTTL, REFRESHTTL, TOKEN.REVOCATION | 2 | high | writeup-config (3 of 3) |

The OPENREDIRECT compound is the marketing-grade headline:
"Implicit flow returns the token in the URL fragment, and your
wildcard callback list accepts attacker-controlled redirect
targets — token theft via crafted phishing URL." Fires on the
focused `open-redirect-config` fixture without needing the rest
of the misconfigurations.

## Run

```bash
cd <repo-root>/stave
make build

# Writeup: every flag set unsafely → all 15 controls + both compounds
./stave apply \
    --observations examples/cognito-iteration4-clientconfig/fixtures/writeup-config/observations \
    --now 2026-05-09T12:00:00Z --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | startswith("CTL.COGNITO.CLIENT."))] | map(.control_id) | sort | unique), chains: (.chain_findings // [] | map(.chain) | sort)}'

# Focused open-redirect: implicit + wildcard only → 2 controls + openredirect chain
./stave apply \
    --observations examples/cognito-iteration4-clientconfig/fixtures/open-redirect-config/observations \
    --now 2026-05-09T12:00:00Z --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | startswith("CTL.COGNITO.CLIENT."))] | map(.control_id) | sort | unique), chains: (.chain_findings // [] | map(.chain) | sort)}'

# Remediated: 0 / 0
./stave apply \
    --observations examples/cognito-iteration4-clientconfig/fixtures/remediated-config/observations \
    --now 2026-05-09T12:00:00Z --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | startswith("CTL.COGNITO.CLIENT."))] | length), chains: (.chain_findings // [] | length)}'
```

Expected:

```
writeup           → 15 ctls, 2 chains
open-redirect     → 2 ctls (IMPLICITFLOW + WILDCARDCB), 1 chain (openredirect)
remediated        → 0 / 0
```

## Catalog observations

The catalog covers all 13 plan controls plus 2 extras
(ENUMERATION — user-existence error leakage; TOKEN.REVOCATION —
which the longtoken compound depends on). Same denormalisation
pattern as previous iterations: the collector evaluates the
OAuth surface and stamps a single boolean. The plan's "callback
URL string-pattern check" reduces to `callback_has_http`,
`callback_has_localhost`, `callback_has_wildcard` booleans — the
collector does the regex/prefix work, Stave reads the result.

No engine changes required. Iteration 4 closes purely on
catalog content + fixtures, same as Iteration 3.

## What this iteration shipped

- **15 individual controls** fire end-to-end on realistic
  observation data for `aws_cognito_user_pool_client`.
- **OPENREDIRECT compound** confirms the implicit-flow +
  wildcard-callback compound the plan called out as the
  headline open-redirect token-theft path.
- **LONGTOKEN compound** composes ACCESSTTL + REFRESHTTL +
  TOKEN.REVOCATION — a stolen token usable for >30 days with
  no revocation path.

No Stave engine changes needed. Same trajectory as Iteration 3:
catalog content + fixture validation.

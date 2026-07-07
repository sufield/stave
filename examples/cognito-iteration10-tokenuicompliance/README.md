# Cognito Iteration 10 — Token / Hosted UI / Resource Servers / Compliance / Cross-Account

End-to-end fixtures for the Iteration 10 residual controls.
Closes the gap-closure plan. 13 controls across 4 asset types,
no compound chain.

```
13 individual controls   (writeup → all fire ; remediated → 0)
 0 compound chains
```

## Controls covered

The plan listed 15 controls; the catalog ships 13 because two
overlap with Iteration 4's app-client family:

- `TOKEN.NOREVOKE` is `CTL.COGNITO.CLIENT.TOKEN.REVOCATION.001` (Iteration 4).
- `TOKEN.ACCESSLONG` is `CTL.COGNITO.CLIENT.ACCESSTTL.001` (Iteration 4).

Both already covered. Iteration 10 ships the 13 distinct
controls.

| Control | Asset type / `kind` | Predicate signal |
|---|---|---|
| `CTL.COGNITO.TOKEN.REFRESHNOROT.001`     | `aws_cognito_user_pool_client` (`cognito_app_client`) | `refresh_token_rotation_enabled == false` |
| `CTL.COGNITO.HOSTEDUI.DEFAULT.001`       | `aws_cognito_user_pool` (`user_pool`) | `uses_default_domain == true` |
| `CTL.COGNITO.HOSTEDUI.SIGNUPADMIN.001`   | `aws_cognito_user_pool` (`user_pool`) | `allow_admin_create_only == true AND hosted_ui_allows_signup == true` |
| `CTL.COGNITO.HOSTEDUI.CORS.001`          | `aws_cognito_user_pool` (`cognito_user_pool`) | `oauth_cors_wildcard == true` |
| `CTL.COGNITO.RESOURCESRV.NONE.001`       | `aws_cognito_user_pool` (`user_pool`) | `uses_oauth_flows == true AND has_resource_servers == false` |
| `CTL.COGNITO.RESOURCESRV.BROADSCOPE.001` | `aws_cognito_resource_server` (`cognito_resource_server`) | `resource_server_broad_scope == true` |
| `CTL.COGNITO.COMPLIANCE.NOCMK.001`       | `aws_cognito_user_pool` (`user_pool`) | `uses_cmk_encryption == false` |
| `CTL.COGNITO.COMPLIANCE.REGION.001`      | `aws_cognito_user_pool` (`user_pool`) | `in_approved_region == false` |
| `CTL.COGNITO.COMPLIANCE.NOTAG.001`       | `aws_cognito_user_pool` (`user_pool`) | `tags_complete == false` |
| `CTL.COGNITO.COMPLIANCE.LOGRETENTION.001`| `aws_cognito_user_pool` (`user_pool`) | `auth_log_retention_compliant == false` |
| `CTL.COGNITO.CROSSACCT.LAMBDA.001`       | `aws_cognito_user_pool` (`user_pool`) | `trigger_lambda_cross_account == true` |
| `CTL.COGNITO.CROSSACCT.SAML.001`         | `aws_cognito_user_pool` (`user_pool`) | `saml_idp_trusted == false` |
| `CTL.COGNITO.CROSSACCT.OIDC.001`         | `aws_cognito_user_pool` (`user_pool`) | `oidc_issuer_cross_account == true` |

## Run

```bash
cd <repo-root>/stave
make build

./stave apply \
    --observations examples/cognito-iteration10-tokenuicompliance/fixtures/writeup-config/observations \
    --eval-time 2026-05-09T12:00:00Z --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(TOKEN|HOSTEDUI|RESOURCESRV|COMPLIANCE|CROSSACCT)"))] | map(.control_id) | sort | unique), chains: (.chain_findings // [] | map(.chain))}'

./stave apply \
    --observations examples/cognito-iteration10-tokenuicompliance/fixtures/remediated-config/observations \
    --eval-time 2026-05-09T12:00:00Z --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(TOKEN|HOSTEDUI|RESOURCESRV|COMPLIANCE|CROSSACCT)"))] | length), chains: (.chain_findings // [] | length)}'
```

Expected:

```
writeup     → 13 ctls, 0 chains
remediated  → 0, 0
```

## Architecture observation: 4 asset types per fixture

The writeup fixture carries 4 asset entries because the 13
controls split across 4 `kind` discriminators:

- `kind: user_pool` (10 controls) — most common
- `kind: cognito_user_pool` (1 control: `HOSTEDUI.CORS.001`)
- `kind: cognito_app_client` (1 control: `TOKEN.REFRESHNOROT.001`)
- `kind: cognito_resource_server` (1 control: `RESOURCESRV.BROADSCOPE.001`)

The `user_pool` vs `cognito_user_pool` discriminator
inconsistency is the same gap Iteration 6's README flagged —
two different `kind` values for the same logical asset type.
The fixture fires the CORS check by emitting a separate
`#cors` asset entry with `kind: cognito_user_pool`, the same
workaround Iteration 6 used.

The cross-account family relies on collector-side join logic:

- `trigger_lambda_cross_account` — collector compares the
  Lambda ARN's account ID against the user pool's account ID.
- `oidc_issuer_cross_account` — collector resolves the OIDC
  issuer URL and checks the account of any AWS-hosted issuer.
- `saml_idp_trusted` — collector compares the SAML IdP
  metadata against an allow-list of trusted IdP organisations.

Same denormalisation pattern as Iteration 1's ghost references
(collector does the cross-asset / cross-network check, stamps
a boolean, Stave reads the boolean). Plus one cross-resource
compound from Iteration 2 (`cognito_unauth_phi_s3` via marker
controls + `scope_field`) already demonstrates the alternative
path when collector denormalisation is too coarse.

## What this iteration shipped

- **13 individual controls** for token rotation / hosted UI /
  resource server design / compliance tagging / cross-account
  trust fire end-to-end across 4 asset types.
- **No compound chain** — by design. Each finding is
  independently actionable.

No Stave engine changes required. Same trajectory as
Iterations 3-9.

---

## Cumulative status (plan complete)

| Iter | Theme | Controls | Compounds | Engine work |
|---|---|---|---|---|
| 1 | Ghost references | 15 | 2 | scope_field |
| 2 | Identity pool unauth | 7 | 3 | marker controls |
| 3 | Auth baseline | 8 | 2 | none |
| 4 | App client config | 15 | 2 | none |
| 5 | Auth role escalation | 7 | 1 | none |
| 6 | Advanced security | 6 | 0 | none |
| 7 | Federation providers | 12 | 0 | none |
| 8 | Monitoring & alarms | 10 | 0 | none |
| 9 | Lifecycle / orphans | 6 | 0 | none |
| **10** | **Token / UI / compliance** | **13** | **0** | **none** |
| **Total** | | **99** | **10** | **2 engine features** |

Plan estimated 114; catalog ships 99. The 15-control gap is
explained by:

- **Rolled-up booleans** (Iterations 3, 6) — `is_weak` covers
  the 4 password char-class checks; `enabled == false` covers
  ADVSEC OFF / AUDIT distinction.
- **Cross-iteration overlaps** (Iterations 4, 5, 9, 10) —
  TOKEN.* counted in two iterations; SAMEROLE folded into
  ROLEMAPPING.NONE; RESOURCESRV.* split across 9 and 10.

All 99 controls validated end-to-end via `stave apply` on
realistic obs.json fixtures. 10 compound chains covering the
plan's documented compounds, with the cross-resource
`cognito_unauth_phi_s3` chain (Iteration 2's PHI-via-Cognito
path) demonstrating the marker-control + scope_field
machinery in production.

Engine machinery shipped as standalone reusable features:

- `chain.scope_field` — declarative cross-asset chain grouping.
  Ready for any future cross-resource compound (CloudTrail
  key-event monitoring, IAM `sts:AssumeRole` to admin
  targets, VPC endpoint joins).
- `TypeMarker` control class — non-violation findings
  composable by chains. Same future-proofing.

The two Cognito engine commits unlock cross-resource compound
detection across **every service domain** the catalog covers —
not just Cognito.

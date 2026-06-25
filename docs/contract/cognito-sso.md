# Cognito Multi-SSO Signals

Derived observation properties for the multi-SSO Cognito User Pool controls
(COGNITO-SSO-001..005). A collector populates these; Stave core only reads them.
All live under `properties.identity.cognito.*` on asset `aws_cognito_user_pool`
(kind `cognito_user_pool`).

Inspired by Doyensec CloudsecTidbits No. 4 — *The Danger of Multi-SSO AWS Cognito
User Pools*.

## PreSignUp gate — `CTL.COGNITO.FEDERATION.PRESIGNUP.MISSING.001` (SSO-001)

| Field | Type | Meaning |
|-------|------|---------|
| `cognito.external_idp_count` | number | Count of registered external IdPs (OIDC + SAML), excluding `COGNITO`. |
| `cognito.has_presignup_trigger` | bool | `LambdaConfig.PreSignUp` is configured. **Specifically PreSignUp** — a PreAuthentication/PostConfirmation trigger does NOT set this true (PreAuthentication does not fire on first federated login). |

## Sensitive attribute mapping — `CTL.COGNITO.FEDERATION.ATTRMAP.SENSITIVE.001` (SSO-002)

| Field | Type | Meaning |
|-------|------|---------|
| `cognito.sensitive_attribute_mapped` | bool | An external IdP's `AttributeMapping` maps a `custom:*` Cognito attribute whose key matches a sensitive token (**case- and separator-insensitive** — normalize lowercase + strip `_`/`-`, so `userAccountId` matches `accountid`): `role`, `admin`, `tenant`, `userid`, `accountid`, `permission`, `privilege`, `access`, `group`, `scope`, `entitlement`. The **same list** the user-controlled write-attribute check uses (`docs/contract/cognito-attributes.md`); **configurable**, these are the defaults. |
| `cognito.sensitive_attribute_idp` | string | The IdP with the sensitive mapping (evidence). |
| `cognito.sensitive_attribute_name` | string | The Cognito attribute, e.g. `custom:role` (evidence). |
| `cognito.sensitive_attribute_claim` | string | The IdP claim it maps from, e.g. `groups` (evidence). |

## IdP identifier hijack — `SOCIAL.ANYDOMAIN.001` (extended) + `CTL.COGNITO.IDP.IDENTIFIER.DUPLICATE.001` (SSO-003)

| Field | Type | Meaning |
|-------|------|---------|
| `cognito.idp_identifier_public_domain` | bool | An IdP's `IdpIdentifiers` includes a public email domain (gmail.com, outlook.com, yahoo.com, hotmail.com, protonmail.com, icloud.com, aol.com, live.com) — routing-hijack risk. Added as an OR arm to `SOCIAL.ANYDOMAIN.001`. |
| `cognito.idp_identifier_duplicate` | bool | Two different IdPs in the pool register the **same** identifier — routing conflict (even for non-public domains). |
| `cognito.idp_identifier_conflict_value` | string | The duplicated identifier (evidence). |

## Homoglyph provider names — `CTL.COGNITO.IDP.HOMOGLYPH.001` + `CTL.COGNITO.IDP.CASECOLLISION.001` (SSO-004)

The collector builds a confusables **skeleton** of each provider name — NFKC
normalize (Go `golang.org/x/text/unicode/norm`), then fold known homoglyphs
(Cyrillic/Greek → Latin, per Unicode TR39 confusables) — and compares skeletons.
NFKC **alone is not sufficient**: Cyrillic `е` (U+0435) and Latin `e` have
distinct NFKC forms, so the homoglyph table is required (the lab's `transform.sh`
shows the reference subset). Stave reads the booleans.

| Field | Type | Meaning |
|-------|------|---------|
| `cognito.homoglyph_collision_present` | bool | Two byte-distinct provider names share a confusables skeleton (e.g. Latin `LegitCorp` vs Cyrillic `LеgitCorp`). **FAIL.** |
| `cognito.homoglyph_collision_pair` | string | The colliding pair (evidence). |
| `cognito.case_only_collision` | bool | Two provider names differ only by case (`CorpIdP` vs `corpidp`). Depends on downstream normalization — **WARN/info**, not FAIL. |

## Compound ghost identity — `CTL.COGNITO.FEDERATION.GHOST.IDENTITY.001` (SSO-005)

| Field | Type | Meaning |
|-------|------|---------|
| `cognito.ghost_identity_chain_present` | bool | **Derived (graph)**. All three hold: external IdP registered, no PreSignUp gate, and a sensitive attribute mapped — a ghost identity can be auto-created with elevated attributes. Computed by `examples/cognito-ghost-identity/` (Soufflé + Z3). |
| `cognito.ghost_identity_idp` | string | The specific IdP that creates the compound risk (the FN trap names it). |
| `cognito.ghost_identity_path` | string | The chain path (evidence). |

**Out of scope (code analysis, not config posture):** Lambda sub-splitting /
parser differentials, trigger-source branching, runtime ghost-window exploitation.

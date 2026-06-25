# Cognito User-Attribute Tampering Signals

Derived observation properties for the user-attribute tampering controls. A
collector populates these; Stave core only reads them.

Inspired by Doyensec CloudsecTidbits S1 #2 — *Tampering User Attributes In AWS
Cognito User Pools*.

## Distinction from the SSO attribute-mapping vector

`CTL.COGNITO.FEDERATION.ATTRMAP.SENSITIVE.001` (COGNITO-SSO-002) is the
**IdP-controlled** vector — a malicious external IdP sets a sensitive attribute
during federation. These controls are the **user-controlled** vector — any
authenticated user calls `update-user-attributes` directly because the app
client's `WriteAttributes` permits it. Same outcome (attacker controls a
sensitive custom attribute), different path; both are needed.

## Already covered (do not duplicate)

`CTL.COGNITO.CLIENT.ATTRRW.001` (`identity.cognito.client_attribute_rw_all`)
already flags an app client that can read **and** write **all** attributes — the
common default when neither `ReadAttributes` nor `WriteAttributes` is set. The
controls below add what it misses: the **write-only** default (write-all without
read-all) and a **scoped `WriteAttributes` that still lists a sensitive
attribute**.

## App client write attributes (asset `aws_cognito_app_client`, kind `cognito_app_client`)

| Field | Type | Meaning |
|-------|------|---------|
| `cognito.client_write_attributes_unset` | bool | The app client's `WriteAttributes` is empty/unset, so Cognito applies the **default — every attribute is writable**, including sensitive custom ones. Any authenticated user can self-modify `custom:Role` etc. → `CTL.COGNITO.CLIENT.WRITEATTR.DEFAULT.001` (CRITICAL). |
| `cognito.client_write_sensitive_attr` | bool | `WriteAttributes` **is** set (scoped) but includes a security-sensitive custom attribute — key matches (case-insensitive) `role`/`admin`/`tenant`/`user_id`/`account_id`/`permission`. Catches the scoped-but-sensitive FN trap (`custom:userAccountId`). → `CTL.COGNITO.CLIENT.WRITEATTR.SENSITIVE.001` (HIGH). |
| `cognito.client_write_sensitive_attr_name` | string | The sensitive attribute in `WriteAttributes` (evidence). |

The two are disjoint: `…_unset` is the default (all writable); `…sensitive` is an
explicitly-scoped list that still includes a sensitive attribute. A client with
`WriteAttributes=["email"]` fires neither.

## Verification before update (asset `aws_cognito_user_pool`)

| Field | Type | Meaning |
|-------|------|---------|
| `cognito.attr_verification_before_update` | bool | `UserPool.UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate` includes **both** `email` and `phone_number`. When false, a user can change their email to `victim@company.com` without verification — account-takeover risk. → `CTL.COGNITO.ATTR.VERIFYUPDATE.001`. |
| `cognito.attr_verification_missing` | string | Which of `email`/`phone_number` is unprotected (evidence). |

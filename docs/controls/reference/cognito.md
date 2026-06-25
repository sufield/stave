# Control Reference — COGNITO

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.COGNITO.ADAPTIVE.AUTH.001

**Cognito Must Block Malicious Sign-In Attempts at All Risk Levels**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Cognito user pools with advanced security must block risky sign-in attempts at low, medium, and high risk levels. Adaptive authentication detects anomalous sign-in patterns (new device, new location, impossible travel) and blocks them.

**Remediation:** Set adaptive authentication to BLOCK for low, medium, and high risk levels in the account-takeover risk configuration.

---

### CTL.COGNITO.ADVANCED.SECURITY.001

**Cognito User Pools Must Have Advanced Security Features Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** aws_security_hub: Cognito.2; mitre_attack: TA0006; nist_800_53_r5: SI-4;

Cognito Advanced Security Features detects and responds to compromised credentials, account takeover attempts, and unusual sign-in activity using adaptive authentication. It detects sign-ins from new devices, blocks credentials found in breach databases, and generates risk scores for authentication events. Without ASF, Cognito cannot detect credential stuffing using breached passwords.

**Remediation:** aws cognito-idp update-user-pool --user-pool-id <id> --user-pool-add-ons AdvancedSecurityMode=ENFORCED

---

### CTL.COGNITO.ADVANCED.SECURITY.AUDITONLY.001

**Cognito Advanced Security in AUDIT Mode (Visibility Without Enforcement)**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** aws_security_hub: Cognito.2; hipaa: 164.312(d); nist_800_53_r5: SI-4; soc2: CC6.1;

Cognito Advanced Security Features is set to AUDIT mode. In AUDIT mode Cognito collects risk metrics for each sign-in attempt — device fingerprint, IP reputation, impossible-travel signals — but does NOT enforce adaptive authentication. Compromised accounts are scored but not blocked. MFA challenges are not triggered for suspicious sign-ins. The security team sees risk scores in the Cognito console while the application continues to authenticate suspicious requests without additional verification. This is the "MFA is theatre" pattern applied to ASF — the control is visible in the console but doesn't protect against the attack path it was designed to block.

**Remediation:** aws cognito-idp update-user-pool --user-pool-id <id> --user-pool-add-ons AdvancedSecurityMode=ENFORCED. The pricing is identical between AUDIT and ENFORCED ($0.050 per MAU); only OFF is free. Once ENFORCED, configure the risk-based actions (block / MFA challenge / allow) for each risk level under the user pool's "Advanced security" settings — Compromised Credentials and Adaptive Authentication.

---

### CTL.COGNITO.ADVSEC.DEVICETRACK.001

**Cognito User Pool Has No Device Tracking Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.5; fedramp_moderate: IA-2, SI-4; iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: IA-2, SI-4; pci_dss_v4.0: 8.3; soc2: CC6.1, CC7.2;

Cognito user pool has no device tracking configured. The pool can't recognize when a user signs in from a new device versus a known device, can't apply step-up auth on new devices, and can't issue device-bound refresh tokens. Adaptive auth's device-aware risk decisions don't function.

**Remediation:** Configure device_configuration on the user pool: aws cognito-idp update-user-pool --device-configuration ChallengeRequiredOnNewDevice=true,DeviceOnlyRememberedOnUserPrompt=true. Combined with advanced security features, this enables device-aware risk scoring — sign-ins from a new device trigger step-up auth or block decisions automatically.

---

### CTL.COGNITO.ALARM.ADMINCREATE.001

**No CloudWatch Alarm for Cognito AdminCreateUser**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: AU-6, SI-4; hipaa: 164.312(b); iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.2, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches CloudTrail for AdminCreateUser API calls. Admin-created users bypass self-registration (and the validation it triggers) — silent admin account creation should generate a notification, not an audit-log entry that nobody reads.

**Remediation:** Create a CloudWatch alarm on a metric filter matching CloudTrail events with eventSource=cognito-idp.amazonaws.com AND eventName=AdminCreateUser. Wire it to the security paging topic. Test by triggering an AdminCreateUser in a sandbox and confirming the alarm fires.

---

### CTL.COGNITO.ALARM.ADMINPWD.001

**No CloudWatch Alarm for Cognito AdminSetUserPassword**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: AU-6, SI-4; hipaa: 164.308(a)(1)(ii)(D); iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.2, 10.6, 8.2; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches CloudTrail for AdminSetUserPassword API calls. Admin-side password resets bypass the user's own recovery flow — a compromised admin can set any user's password without involving the user. Notification at the API call level catches misuse early.

**Remediation:** Create a metric filter matching eventSource=cognito-idp.amazonaws.com AND eventName=AdminSetUserPassword. Wire to the security paging topic. AdminSetUserPassword bypasses the user's own recovery flow entirely — a single API call can hijack any account. The alarm should fire on every event so any use is reviewed.

---

### CTL.COGNITO.ALARM.CREATEIDPOOL.001

**No CloudWatch Alarm for Cognito CreateIdentityPool with Unauthenticated Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.2, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches CloudTrail for CreateIdentityPool API calls that include AllowUnauthenticatedIdentities=true. New identity pools that grant anonymous AWS credentials should be flagged at creation time, not discovered later by drift checks.

**Remediation:** Create a metric filter matching eventSource=cognito-identity.amazonaws.com AND eventName=CreateIdentityPool AND requestParameters.allowUnauthenticatedIdentities=true. Wire to the security topic. New identity pools with anonymous access are rare in production deployments and should always trigger investigation.

---

### CTL.COGNITO.ALARM.DELETEPOOL.001

**No CloudWatch Alarm for Cognito DeleteUserPool**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: AU-6, SI-4; hipaa: 164.308(a)(1)(ii)(D); iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.2, 10.6; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch alarm watches CloudTrail for DeleteUserPool API calls. Pool deletion destroys all users — every authentication in every dependent application breaks. Real-time notification is essential.

**Remediation:** Create a metric filter matching eventSource=cognito-idp.amazonaws.com AND eventName=DeleteUserPool, with a CloudWatch alarm on > 0 events. Wire to the highest-priority paging topic — pool deletion is unrecoverable through normal channels, so the response time matters. Combine with deletion protection on the pool itself (the existing CTL.COGNITO.DELETEPROT.001) for prevention.

---

### CTL.COGNITO.ALARM.FAILEDAUTH.001

**No CloudWatch Alarm for Cognito Failed Authentication Spike**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: AU-6, IR-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.6, 8.3.4; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches the SignInThrottles / failed-authentication metric for the user pool. Brute-force and credential-stuffing attacks proceed without throttling visibility — an attacker hitting the rate-limit ceiling doesn't trigger any alert.

**Remediation:** Create a CloudWatch alarm on the AWS/Cognito SignInThrottles metric (or the equivalent failed-auth metric for the pool's auth flow) with threshold > N over a short window. Tune N based on baseline traffic. Wire to security paging.

---

### CTL.COGNITO.ALARM.MFAFAIL.001

**No CloudWatch Alarm for Cognito MFA Challenge Failure Spike**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, IA-2; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IA-2, SI-4; pci_dss_v4.0: 10.6, 8.4; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches the MFA challenge failure rate. Spikes in MFA failures indicate brute-force MFA attacks (SMS code guessing, TOTP brute force) or stolen-session attempts to satisfy MFA after credential compromise.

**Remediation:** Create a CloudWatch alarm on Cognito's MFA failure metrics (or build one from CloudTrail RespondToAuthChallenge failures with SMS_MFA / SOFTWARE_TOKEN_MFA challenge types). Threshold > N over a short window. MFA failures should be rare in legitimate use — most users enter the right code on the first try. A spike indicates either a UX problem or an attack.

---

### CTL.COGNITO.ALARM.REGSPIKE.001

**No CloudWatch Alarm for Cognito Registration Spike**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches the SignUpRequest rate. Bot-driven registration sprees and spam-account creation campaigns produce a characteristic spike that should generate an alert; without one, the abuse fills the pool with bot accounts before anyone notices.

**Remediation:** Create a CloudWatch alarm on the SignUpRequest rate with threshold > N over a short window. Baseline against normal registration patterns; tune N to match expected daily peaks plus a margin. Wire to operations paging or a queue for follow-up review.

---

### CTL.COGNITO.ALARM.RISKCONFIG.001

**No CloudWatch Alarm for Cognito SetRiskConfiguration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, CM-3; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, CM-3, SI-4; pci_dss_v4.0: 10.2, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches CloudTrail for SetRiskConfiguration API calls. Advanced security configuration changes (turning off adaptive auth, weakening risk thresholds, disabling compromised-credentials checks) should generate notifications, not silent state changes.

**Remediation:** Create a metric filter matching eventSource=cognito-idp.amazonaws.com AND eventName=SetRiskConfiguration. Wire to the security topic. Advanced security settings determine whether risky sign-ins are blocked, whether compromised credentials are blocked, and whether adaptive auth is in audit or enforced mode — every change matters.

---

### CTL.COGNITO.ALARM.UPDATEPOOL.001

**No CloudWatch Alarm for Cognito UpdateUserPool**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: AU-6, CM-3, SI-4; hipaa: 164.312(b); iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, CM-3, SI-4; pci_dss_v4.0: 10.2, 10.6; soc2: CC7.2, CC7.3, CC8.1;

No CloudWatch alarm watches CloudTrail for UpdateUserPool API calls. User pool configuration changes — MFA settings, password policy, Lambda triggers — happen without notification, leaving the security team unaware until the next audit.

**Remediation:** Create a metric filter matching eventSource=cognito-idp.amazonaws.com AND eventName=UpdateUserPool, with a CloudWatch alarm on > 0 events. Wire to the security topic. Pool configuration is the wide attack surface — MFA flips, password-policy weakening, Lambda trigger swaps all happen via UpdateUserPool.

---

### CTL.COGNITO.ATTR.VERIFYUPDATE.001

**Cognito User Pool Does Not Require Verification Before Email/Phone Update**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: IA-5, IA-8; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1, CC6.7;

A Cognito User Pool does not require attribute verification before update for email and phone_number — UserAttributeUpdateSettings. AttributesRequireVerificationBeforeUpdate omits one or both. Without it, a user can change their email to victim@company.com (or a phone to a victim's number) WITHOUT proving control of the new value. If any downstream flow trusts the email/phone — password recovery, notifications, identity linking — this is an account-takeover primitive. AWS recommends requiring verification before update for these attributes.
Inspired by Doyensec CloudsecTidbits S1 #2 — Tampering User Attributes In AWS Cognito User Pools.

**Remediation:** Set UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate to include both "email" and "phone_number". A changed value then stays pending until the user verifies control of it.

---

### CTL.COGNITO.CLIENT.ACCESSTTL.001

**Cognito App Client Access Token Validity Exceeds One Hour**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-2, IA-5; iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: IA-2, IA-5, SC-12; pci_dss_v4.0: 8.6; soc2: CC6.1, CC6.3;

Cognito app client issues access tokens with validity longer than one hour. Long-lived access tokens widen the window during which a stolen token can be used; the refresh-token model is designed to keep access tokens short-lived (5–60 minutes) while refresh tokens carry longevity.

**Remediation:** Set access_token_validity to one hour (3600 seconds) or less: aws cognito-idp update-user-pool-client with --access-token-validity 60 and --token-validity-units AccessToken=minutes. Refresh tokens carry longevity and rotate on use; access tokens should be short.

---

### CTL.COGNITO.CLIENT.ALLFLOWS.001

**Cognito App Client Enables All OAuth Flows Indiscriminately**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, SA-10; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito app client has all three OAuth flows enabled simultaneously (authorization code, implicit, and client credentials). A real application uses one flow; allowing all three multiplies the attack surface and indicates the app client was provisioned without thinking about the use case.

**Remediation:** Determine which flow the application uses (authorization-code with PKCE for almost all modern apps; client_credentials only for machine-to-machine workloads) and remove the others from allowed_o_auth_flows. Each disabled flow closes a parallel authentication path.

---

### CTL.COGNITO.CLIENT.ALLSCOPES.001

**Cognito App Client Has All OAuth Scopes Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.5; nist_800_53_r5: AC-3, AC-6, IA-2; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

Cognito app client has every available OAuth scope enabled (openid, email, profile, phone, aws.cognito.signin.user.admin, plus every custom scope from every resource server). The client can request any scope the user pool defines — over-permissioned by default.

**Remediation:** List the scopes the application requires, then update allowed_o_auth_scopes to that list only: aws cognito-idp update-user-pool-client. Most apps need only openid + email + profile; adding aws.cognito.signin.user.admin enables the user-admin API surface (often a much larger surface than the app needs).

---

### CTL.COGNITO.CLIENT.ATTRRW.001

**Cognito App Client Can Read and Write All User Attributes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6; hipaa: 164.308(a)(4)(ii)(B); iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.1, 7.2, 8.3; soc2: CC6.1, CC6.3;

Cognito app client has all user attributes in both read_attributes and write_attributes. The client can read every attribute Cognito stores (including sensitive ones like phone, ssn-bearing custom attributes, internal flags) and write every attribute (including admin-only attributes that should be immutable from the client side).

**Remediation:** Narrow read_attributes to what the application actually displays and write_attributes to what the user is allowed to self-modify (typically just profile fields like preferred_username, given_name, family_name, picture). Admin- only attributes (groups, custom:role, internal flags) should not be in write_attributes for any user-facing client.

---

### CTL.COGNITO.CLIENT.CLIENTCREDS.001

**Cognito App Client Mixes User-Facing and Client-Credentials Flows**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-2, IA-3; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, IA-3; pci_dss_v4.0: 7.2, 8.3; soc2: CC6.1, CC6.3;

Cognito app client allows the client_credentials OAuth flow alongside user-facing flows (code or implicit). client_credentials is for machine-to-machine authentication — there is no user. Mixing it with user flows on the same client creates ambiguous security boundaries: the client can issue tokens as itself or on behalf of a user.

**Remediation:** Split into two app clients: one for the user-facing flow (code with PKCE) and a separate one for machine-to-machine workloads (client_credentials only). Remove client_credentials from the user client and remove user flows from the M2M client. Keep their secrets and scopes independent.

---

### CTL.COGNITO.CLIENT.ENUMERATION.001

**Cognito App Clients Must Prevent User Existence Disclosure**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Cognito app clients must enable PreventUserExistenceErrors to suppress user-existence disclosures. Without this, authentication error messages reveal whether a username exists, enabling account enumeration attacks.

**Remediation:** Set PreventUserExistenceErrors to ENABLED on the app client.

---

### CTL.COGNITO.CLIENT.HTTPCALLBACK.001

**Cognito App Client Callback URL Uses HTTP**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-2, SC-8; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: IA-2, SC-8; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

Cognito app client lists a callback URL with http:// scheme rather than https://. The authorization-code or token returned from Cognito traverses the network in plaintext on the redirect — observable by any on-path attacker.

**Remediation:** Replace http:// callback URLs with https:// in the app client configuration: aws cognito-idp update-user-pool-client with corrected callback_urls. Ensure the application's web server has a valid TLS certificate at the new URL before flipping the configuration. Localhost callbacks during development are tracked separately by the LOCALHOST control.

---

### CTL.COGNITO.CLIENT.IDTTL.001

**Cognito App Client ID Token Validity Exceeds One Hour**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-2, IA-5; iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: IA-2, IA-5; pci_dss_v4.0: 8.6; soc2: CC6.1;

Cognito app client issues ID tokens with validity longer than one hour. ID tokens carry user-identity claims (sub, email, groups, custom attributes); long validity means stale claims persist long after the source data changes (e.g., user's group membership was revoked, but the ID token still says they're an admin).

**Remediation:** Set id_token_validity to one hour or less: aws cognito-idp update-user-pool-client --id-token-validity 60 --token-validity-units IdToken=minutes. Apps that use ID tokens for authorization decisions (which is itself questionable — use access tokens for authorization) benefit doubly from short ID-token lifetimes.

---

### CTL.COGNITO.CLIENT.IMPLICITFLOW.001

**Cognito App Client Allows OAuth Implicit Flow**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-2, SC-8; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, SC-8; pci_dss_v4.0: 4.2, 8.3; soc2: CC6.1;

Cognito app client lists `implicit` in its allowed OAuth flows. The implicit flow returns access tokens in URL fragments — observable in browser history, server logs, and referer headers. OAuth 2.1 explicitly removes implicit; modern clients should use authorization-code with PKCE.

**Remediation:** Remove `implicit` from allowed_o_auth_flows on the app client. Migrate any client still using implicit to authorization-code with PKCE — the modern equivalent for browser apps that retains the same UX without the URL-fragment token leak. SPAs that need public-client behavior get auth code via the BFF (backend-for-frontend) pattern or direct PKCE in the browser.

---

### CTL.COGNITO.CLIENT.LOCALHOST.001

**Cognito App Client Has Localhost Callback URL in Production**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-2, CM-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, CM-2; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito app client lists a callback URL containing localhost or 127.0.0.1. Localhost callbacks are valid during development but should not appear in production app clients — they hint that the client is mis-promoted from a development environment, and an attacker controlling local DNS or running a local server can intercept callbacks.

**Remediation:** Remove localhost / 127.0.0.1 entries from the app client's callback_urls. Maintain separate app clients for development (with localhost) and production (with the deployed domain only). Cognito does not itself enforce 'production-only' — the discipline lives in the app client configuration.

---

### CTL.COGNITO.CLIENT.NOLOGOUT.001

**Cognito App Client Has No Logout URL Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-12; iso_27001_2022: A.5.17; nist_800_53_r5: AC-12, IA-2; pci_dss_v4.0: 8.6; soc2: CC6.1, CC8.1;

Cognito app client has no logout URLs configured. Users cannot complete the hosted-UI logout flow back to the application's logout-confirmation page. Sessions become harder to terminate cleanly — users either remain logged in via refresh tokens or land on a generic page after logout.

**Remediation:** Add a logout URL pointing at the application's signed-out landing page: aws cognito-idp update-user-pool-client with --logout-urls including https://app.example.com/signed-out. The application should also call the Cognito logout endpoint (auth.example.com/logout) and use revoke token revocation to invalidate refresh tokens server-side.

---

### CTL.COGNITO.CLIENT.NOSECRET.001

**Cognito App Client Has No Client Secret**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-2, IA-3; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, IA-3, IA-5; pci_dss_v4.0: 8.3; soc2: CC6.1, CC6.3;

Cognito app client is configured without a client secret while serving as the authentication credential for a server-side application. Public clients (browser SPAs, mobile apps) intentionally have no secret; server-side clients should always have one. A confidential application without a secret has no client-level authentication — anybody can pretend to be the application to Cognito.

**Remediation:** Generate a secret on the app client (aws cognito-idp create-user-pool-client with --generate-secret) and rotate the application's stored credential through Secrets Manager. Only intentionally public clients (SPA, mobile) should remain secret-less; document why each public client is public so future audits don't re-flag.

---

### CTL.COGNITO.CLIENT.REFRESHTTL.001

**Cognito App Client Refresh Token Validity Exceeds 30 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-2, IA-5; iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: IA-2, IA-5; pci_dss_v4.0: 8.6; soc2: CC6.1;

Cognito app client issues refresh tokens with validity longer than 30 days. Refresh tokens are the long-lived authentication credential — a 365-day refresh token is effectively a year-long session. Combined with absent rotation, a single stolen refresh token gives the attacker a year of access.

**Remediation:** Set refresh_token_validity to 30 days or less for typical applications: aws cognito-idp update-user-pool-client --refresh-token-validity 30 --token-validity-units RefreshToken=days. For sensitive workloads (financial, health), consider seven days or shorter. Pair with refresh-token rotation enabled so tokens rotate on use rather than persisting unchanged.

---

### CTL.COGNITO.CLIENT.TOKEN.REVOCATION.001

**Cognito App Clients Must Enable Token Revocation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Cognito app clients must enable token revocation so revoked refresh tokens and their derived access/ID tokens are immediately invalidated. Without revocation, compromised tokens remain valid until expiry.

**Remediation:** Set EnableTokenRevocation to true on the app client.

---

### CTL.COGNITO.CLIENT.WILDCARDCB.001

**Cognito App Client Callback URL Uses Wildcard**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-2, SC-7; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, SC-7; pci_dss_v4.0: 8.3; soc2: CC6.1, CC6.7;

Cognito app client has a callback URL containing a wildcard (*) or other broad pattern. Wildcards in callback URLs enable open-redirect attacks: an attacker crafts an authorization request with a callback matching the wildcard but pointing to an attacker-controlled origin, and Cognito redirects the auth code there.

**Remediation:** Remove all wildcard entries from callback_urls. Replace with explicit, full URLs for every callback the app legitimately needs. If multiple subdomains need the same client, list each subdomain explicitly rather than using *.example.com — Cognito callback URLs must match the registered list exactly.

---

### CTL.COGNITO.CLIENT.WRITEATTR.DEFAULT.001

**Cognito App Client WriteAttributes Unset — Every Attribute Is Writable**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, AC-6, AC-16; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC6.3;

A Cognito app client has no WriteAttributes configured, so Cognito applies the default: EVERY user attribute is writable from the client, including sensitive custom attributes (custom:Role, custom:isAdmin, custom:tenantID, linking IDs). Any authenticated user can call update-user-attributes and self-modify those attributes. If the application trusts custom attributes for authorization, this is direct privilege escalation. Most teams never set WriteAttributes and so get this default silently.
CRITICAL counterpart to CTL.COGNITO.CLIENT.WRITEATTR.SENSITIVE.001 (HIGH, fires when WriteAttributes IS scoped but still lists a sensitive attribute); the two are disjoint. Distinct from CTL.COGNITO.CLIENT.ATTRRW.001, which requires read AND write on ALL attributes — this fires on the write-default even when reads are scoped. The user-controlled counterpart to the IdP-controlled CTL.COGNITO.FEDERATION.ATTRMAP.SENSITIVE.001.
Inspired by Doyensec CloudsecTidbits S1 #2 — Tampering User Attributes In AWS Cognito User Pools.

**Remediation:** Set WriteAttributes explicitly to the minimal list the client needs (e.g. email, name) and exclude all security-sensitive custom attributes. Treat sensitive attributes as admin-only; write them server-side, never from the client.

---

### CTL.COGNITO.CLIENT.WRITEATTR.SENSITIVE.001

**Cognito App Client WriteAttributes Includes a Sensitive Custom Attribute**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, AC-16; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A Cognito app client has WriteAttributes scoped to an explicit list, but that list still includes a security-sensitive custom attribute — its key matches role / admin / tenant / user_id / account_id / permission (case-insensitive). Any authenticated user can call update-user-attributes and self-modify that attribute. A scoped WriteAttributes looks safe (only a few attributes) but custom:userAccountId, custom:role, or custom:tenantId among them is still a self-escalation path — the collector matches the pattern rather than only checking whether WriteAttributes is set.
HIGH counterpart to CTL.COGNITO.CLIENT.WRITEATTR.DEFAULT.001 (CRITICAL, the unset/all-writable default); the two are disjoint. The user-controlled counterpart to the IdP-controlled CTL.COGNITO.FEDERATION.ATTRMAP.SENSITIVE.001.
Inspired by Doyensec CloudsecTidbits S1 #2 — Tampering User Attributes In AWS Cognito User Pools.

**Remediation:** Remove the sensitive custom attribute from WriteAttributes. Write sensitive attributes server-side with an admin/provisioning identity, never from the client. Keep WriteAttributes limited to non-sensitive profile fields.

---

### CTL.COGNITO.COMPLIANCE.LOGRETENTION.001

**Cognito Authentication Logs Retained Below Compliance Window**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: AU-9, AU-11; hipaa: 164.312(b), 164.316(b)(2)(i); iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: AU-9, AU-11; pci_dss_v4.0: 10.5.1, 10.7; soc2: CC7.1, A1.2;

CloudWatch log group receiving Cognito authentication event logs has retention set shorter than the applicable compliance framework requires (typically 1 year for SOC 2, 6 years for HIPAA, 1 year for PCI-DSS). Authentication audit trail expires before the compliance window closes.

**Remediation:** Set retention on Cognito-associated log groups to meet the applicable framework's minimum: aws logs put-retention-policy --log-group-name <name> --retention-in-days 365 (SOC 2 / PCI-DSS), 2190 (HIPAA), or higher per organizational policy. The catalog already has log-group retention controls (CW-2 LOGGROUP.RETENTION.SHORT) — this control adds Cognito-specific framing when those log groups carry auth events.

---

### CTL.COGNITO.COMPLIANCE.NOCMK.001

**Cognito User Pool Not Encrypted with Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-12, SC-13, SC-28; hipaa: 164.312(a)(2)(iv), 164.312(e)(2)(ii); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-13, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1, CC6.7;

Cognito user pool processing PII does not use a customer-managed KMS key for encryption. Default AWS-managed encryption protects data at rest but the customer has no key-policy control, no audit visibility into decryption, and no revocation path.

**Remediation:** Configure custom_email_sender or KMS- encrypted attributes on the user pool using a customer-managed KMS key. For pools subject to compliance requirements (HIPAA, PCI-DSS, FedRAMP), CMK encryption is typically a baseline requirement; default AWS-managed encryption may not satisfy auditors.

---

### CTL.COGNITO.COMPLIANCE.NOTAG.001

**Cognito Resources Missing Required Compliance Tags**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-8, SA-22; soc2: CC8.1;

Cognito user pool, identity pool, or app client lacks tags identifying its compliance scope (data classification, business unit, owner, environment). Without tags, audit scope can't be derived, cost allocation can't be attributed, and policy automation can't target the resource.

**Remediation:** Tag the resource with the organization's standard tag set: Environment (production/staging/dev), DataClass (PII, PHI, confidential), Owner (team email or ID), CostCenter, and any compliance- specific tags (SOC2, HIPAA, PCI). Apply via aws cognito-idp tag-resource. Pair with an SCP that denies cognito-idp:CreateUserPool without the required tag set so future creations enforce the standard.

---

### CTL.COGNITO.COMPLIANCE.REGION.001

**Cognito User Pool in Non-Compliant Region**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-4; hipaa: 164.310(d)(2)(i); iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: AC-3, AC-4, SA-22; pci_dss_v4.0: 12.10; soc2: CC6.1, CC8.1;

Cognito user pool deployed in an AWS region that's not on the organization's approved-region list. For data-residency- regulated workloads (GDPR for EU users, HIPAA for US-only PHI), pools in off-policy regions are immediate compliance violations.

**Remediation:** Migrate the user pool to an approved region (Cognito does not support cross- region replication; migration requires user re-registration or a custom migration trigger). Add an SCP that denies cognito-idp:CreateUserPool in non-approved regions to prevent future occurrences.

---

### CTL.COGNITO.COMPROMISED.CREDS.001

**Cognito Must Block Sign-In with Compromised Credentials**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Cognito user pools with advanced security must block sign-in attempts using credentials detected in known breaches. Requires advanced security ENFORCED mode with compromised-credentials policy set to BLOCK on sign-in events.

**Remediation:** Enable advanced security in ENFORCED mode and set the compromised-credentials policy to BLOCK for sign-in events.

---

### CTL.COGNITO.CROSSACCT.LAMBDA.001

**Cognito Lambda Trigger Lives in Different Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-4; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-4, CM-3; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.6;

Cognito user pool's Lambda trigger ARN points at a function in a different AWS account from the user pool. Cross-account Lambda invocation crosses a trust boundary on every authentication event; the foreign account becomes a soft dependency for pool authentication.

**Remediation:** Move the trigger Lambda into the user pool's account, or document the cross- account dependency with explicit trust review. If cross-account is intentional (centralized authentication logic shared across multiple pools), require the foreign-account Lambda's resource policy to scope cognito-idp invocation to the expected pool ARNs.

---

### CTL.COGNITO.CROSSACCT.OIDC.001

**Cognito OIDC Provider Issuer Hosted in External AWS Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-4, IA-8; iso_27001_2022: A.5.16, A.5.18; nist_800_53_r5: AC-3, AC-4, IA-8; pci_dss_v4.0: 7.2, 8.3; soc2: CC6.1, CC6.6;

Cognito OIDC identity provider's issuer URL resolves to infrastructure in a different AWS account. The federation depends on a foreign account's OIDC service; an attacker who compromises that account can issue tokens that exchange for legitimate access to the user pool's application.

**Remediation:** If the cross-account OIDC dependency is intentional (e.g., centralized identity provider in a dedicated account), document the relationship and ensure the foreign account's OIDC service has equivalent security controls. If unintentional, remove the provider and configure federation against an internally-owned OIDC service.

---

### CTL.COGNITO.CROSSACCT.SAML.001

**Cognito SAML Provider Federates with Untrusted Organization**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, IA-8; iso_27001_2022: A.5.16, A.5.18; nist_800_53_r5: AC-3, AC-6, IA-8; pci_dss_v4.0: 7.2, 8.3; soc2: CC6.1, CC6.6;

Cognito SAML identity provider's metadata references an IdP at an organization outside the user pool owner's trust scope. Federated users from the untrusted org authenticate into the application as if they were trusted users.

**Remediation:** Verify the IdP organization is on the approved-partner list before federation can proceed. If it isn't, remove the SAML provider configuration. If it should be, document the federation relationship in a vendor-management record so future audits don't re-flag.

---

### CTL.COGNITO.DELETEPROT.001

**Cognito User Pools Must Have Deletion Protection Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

Cognito user pools must have deletion protection set to ACTIVE. Without protection, accidental or malicious deletion destroys the user directory and all authentication state.

**Remediation:** Set deletion protection to ACTIVE on the user pool.

---

### CTL.COGNITO.DOMAIN.CERTEXPIRY.001

**Cognito Custom Domain Certificate Has Expired**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12, SC-23; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-23; owasp_nhi: NHI7; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7, A1.1;

Cognito user pool custom domain references an ACM certificate that has expired. The hosted UI fails TLS handshake; OAuth flows that route through the custom domain break. Different from GHOST.DOMAINCERT (cert deleted from ACM) — here the cert exists but is past validity.

**Remediation:** Request a new ACM certificate for the custom domain (must be in us-east-1) and update the user pool's custom domain to use the new certificate ARN. ACM certificates issued by AWS auto-renew if DNS validation remains in place; an expired ACM cert typically means DNS validation failed (Route 53 record was removed, the domain was transferred without re-validating). Fix the DNS validation, then request renewal.

---

### CTL.COGNITO.DOMAIN.HTTPS.001

**Cognito Custom Domain Does Not Enforce HTTPS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-8, SC-23; iso_27001_2022: A.8.20, A.8.24; nist_800_53_r5: SC-8, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

Cognito user pool custom domain does not enforce HTTPS — the hosted UI is reachable over plaintext HTTP, or HTTPS is configured but redirects are not enforced. OAuth flows that should always be HTTPS may transit in plaintext.

**Remediation:** Cognito's CloudFront distribution serves the hosted UI on HTTPS by default; if HTTP traffic is reaching the custom domain, check whether a CloudFront distribution in front of it has been configured with viewer protocol policy set to allow HTTP. Set ViewerProtocolPolicy to redirect-to-https or https-only on any CDN layer in front of the Cognito domain. Remove A records pointing at IPs that don't enforce HTTPS.

---

### CTL.COGNITO.FEDERATION.ATTRMAP.SENSITIVE.001

**Cognito IdP AttributeMapping Maps a Security-Sensitive Attribute**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6, AC-16; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

An external IdP's AttributeMapping writes a security-sensitive custom attribute (e.g. custom:role, custom:tenantID, custom:isAdmin, custom:permissions) from an IdP claim during federation. An attacker controlling the IdP can set arbitrary values for these attributes. Even with WriteAttributes restrictions, JIT provisioning Lambdas using AdminUpdateUserAttributes bypass WriteAttributes entirely, so the mapping is the real control point.
The collector flags any custom:* attribute whose key contains (case-insensitive) role / admin / tenant / permission / privilege / access — a configurable pattern list, not an exact allow-list, so custom:accessLevel is caught (the FN trap). Standard attributes (email, name, phone_number) are expected and do not fire. Distinct from CTL.COGNITO.SAML.ATTRMAP.001, which flags MISSING required attributes (the opposite direction).
Inspired by Doyensec CloudsecTidbits No. 4 — The Danger of Multi-SSO AWS Cognito User Pools.

**Remediation:** Remove security-sensitive attributes (role/tenant/admin/permission/privilege/ access) from the IdP AttributeMapping. Derive authorization attributes server-side from a trusted source after federation, not from IdP claims. If a sensitive attribute must be mapped, validate and overwrite it in a PreSignUp or PreTokenGeneration trigger.

---

### CTL.COGNITO.FEDERATION.GHOST.IDENTITY.001

**Cognito Pool Enables Ghost Identity Injection With Elevated Attributes**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2, AC-6; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Three conditions hold together on this Cognito User Pool: an external IdP is registered, there is no PreSignUp Lambda gate before user creation, and a security-sensitive attribute is mapped from that IdP's claims. An attacker controlling the IdP federates and a ghost identity is auto-created with the sensitive attribute (e.g. custom:role=admin) set from an attacker-controlled claim — no trigger prevented it, and the identity persists.
Each condition alone is a finding (CTL.COGNITO.FEDERATION.PRESIGNUP.MISSING.001 for the missing gate, CTL.COGNITO.FEDERATION.ATTRMAP.SENSITIVE.001 for the mapping); this compound proves all hold for a specific IdP. The finding names the IdP that creates the risk — on a pool with one safe and one risky IdP, it fires for the risky one only. Computed by examples/cognito-ghost-identity/ (Soufflé + Z3, which agree).
Inspired by Doyensec CloudsecTidbits No. 4 — The Danger of Multi-SSO AWS Cognito User Pools.

**Remediation:** Break any one link: add a PreSignUp Lambda gate, remove the sensitive attribute from the IdP AttributeMapping, or remove the untrusted external IdP. Adding the PreSignUp gate addresses the broadest set of federation risks.

---

### CTL.COGNITO.FEDERATION.PRESIGNUP.MISSING.001

**Cognito User Pool With External IdPs Has No PreSignUp Trigger**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2, IA-8; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1, CC6.3;

A Cognito User Pool has one or more external identity providers registered (OIDC or SAML) but no PreSignUp Lambda trigger. The PreSignUp trigger is the only gate before user-object creation: without it, any federated user from any registered external IdP is automatically persisted. If an external IdP is malicious or compromised, ghost identities land in the pool with no validation, and there is no automatic rollback — cleanup is manual, and the window between creation and cleanup is exploitable.
The trigger must specifically be PreSignUp. PreAuthentication and PostConfirmation do NOT fire on the first federated login, so they do not gate ghost-identity creation — the collector sets has_presignup_trigger only for an actual PreSignUp configuration (the FN trap). Distinct from CTL.COGNITO.GHOST.PRESIGNUP.001, which flags a PreSignUp trigger pointing at a deleted Lambda; this flags the trigger being absent entirely.
Inspired by Doyensec CloudsecTidbits No. 4 — The Danger of Multi-SSO AWS Cognito User Pools.

**Remediation:** Configure a PreSignUp Lambda trigger (LambdaConfig.PreSignUp) that validates the incoming federated profile (email domain, IdP, required claims) and rejects unexpected registrations before the user object is created. A PreAuthentication trigger is not a substitute — it does not fire on first federated login.

---

### CTL.COGNITO.GHOST.CREATEAUTH.001

**Cognito Create Auth Challenge Lambda Trigger References Deleted Function**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3, IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, CM-3, IA-2; owasp_nhi: NHI1; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1, A1.1;

Cognito create-auth-challenge Lambda has been deleted. The trigger that materializes the challenge payload (CAPTCHA, code, magic link) is gone — custom auth flows that pass define-auth fail immediately at challenge creation.

**Remediation:** Redeploy the create-auth-challenge Lambda along with the matching define-auth and verify-auth handlers. Custom auth state must be coherent across the three triggers.

---

### CTL.COGNITO.GHOST.CUSTOMMSG.001

**Cognito Custom Message Lambda Trigger References Deleted Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3, IA-5; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-3, IA-5; owasp_nhi: NHI1; pci_dss_v4.0: 8.2; soc2: CC6.1, CC7.1, CC8.1;

Cognito custom message Lambda trigger has been deleted. Verification messages, MFA codes, and reset notifications fall back to default templates or fail entirely depending on the flow. Branded user communications break.

**Remediation:** Redeploy the Lambda, or remove custom_message from lambda_config and rely on Cognito's default templates. Default templates send verification codes but with the AWS-default sender and branding — typically not acceptable for production user communications.

---

### CTL.COGNITO.GHOST.DEFINEAUTH.001

**Cognito Define Auth Challenge Lambda Trigger References Deleted Function**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3, IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, CM-3, IA-2; owasp_nhi: NHI1; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1, A1.1;

Cognito define-auth-challenge Lambda has been deleted while the user pool still uses custom authentication. The pool advertises CUSTOM_AUTH flows but the trigger that decides the next challenge is gone — every custom auth flow fails.

**Remediation:** Custom auth typically uses three triggers together (define, create, verify). Redeploy all three together or migrate the pool back to standard authentication flows. Partial redeployment can produce inconsistent behavior — flows that get past define-auth then fail at create-auth.

---

### CTL.COGNITO.GHOST.DOMAINCERT.001

**Cognito Custom Domain Certificate Deleted from ACM**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3, SC-12; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: CM-2, CM-3, SC-12; owasp_nhi: NHI1; pci_dss_v4.0: 4.2; soc2: CC6.1, CC8.1, A1.1;

Cognito user pool custom domain references an ACM certificate that has been deleted or has expired. The hosted UI domain stops serving HTTPS traffic. Login flows that route through the custom domain break.

**Remediation:** Either request a new ACM certificate for the custom domain (must be in us-east-1 for Cognito custom domains) and update the user pool's custom domain configuration, or remove the custom domain and fall back to the default Cognito domain. ACM certificate deletion is permanent — the original certificate cannot be restored.

---

### CTL.COGNITO.GHOST.DOMAINDNS.001

**Cognito Custom Domain DNS Record Missing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.5.16, A.8.2; nist_800_53_r5: CM-2, CM-3; owasp_nhi: NHI1; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1, A1.1;

Cognito user pool has a custom domain configured but the DNS CNAME no longer points at the Cognito CloudFront distribution. Users hitting auth.example.com get DNS resolution failures or are routed to a different endpoint entirely.

**Remediation:** Recreate the CNAME record pointing at the distribution_domain_name returned by DescribeUserPoolDomain. If the original Route 53 hosted zone or DNS provider record was deleted, recreate it; if the record now points elsewhere, restore the correct target. Cognito's distribution domain is stable for the life of the custom domain.

---

### CTL.COGNITO.GHOST.IDPOOL.001

**Cognito Identity Pool References Deleted User Pool**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, CM-3, IA-2; iso_27001_2022: A.5.16, A.8.2; nist_800_53_r5: AC-3, CM-2, CM-3, IA-2; owasp_nhi: NHI1; pci_dss_v4.0: 8.3, 7.2; soc2: CC6.1, CC8.1;

Cognito identity pool has a Cognito identity provider entry pointing at a user pool that has been deleted. The identity pool advertises authenticated identity exchange but cannot validate tokens from a non-existent user pool. Authenticated AWS-credential exchange fails.

**Remediation:** Either recreate the user pool with the same ID (impossible — pool IDs are unique and not reusable) or repoint the identity pool at the current authenticating user pool: aws cognito-identity update-identity-pool --identity-pool-id <id> with corrected cognito_identity_providers list. Audit applications that depended on the original user pool — they are now silently broken.

---

### CTL.COGNITO.GHOST.POSTAUTH.001

**Cognito Post-Authentication Lambda Trigger References Deleted Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, CM-3; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, CM-2, CM-3, SI-4; owasp_nhi: NHI1; pci_dss_v4.0: 10.2; soc2: CC7.1, CC8.1;

Cognito post-authentication trigger Lambda has been deleted. The login itself succeeds, but post-login processing — analytics, audit logging, session state writes — fails. Authentication succeeds; downstream side effects are silently dropped.

**Remediation:** Redeploy the Lambda or remove post_authentication from lambda_config. Post-auth triggers commonly write to audit pipelines or update last-login timestamps — if those records are missing, the audit trail has gaps you'll need to backfill.

---

### CTL.COGNITO.GHOST.POSTCONFIRM.001

**Cognito Post-Confirmation Lambda Trigger References Deleted Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, CM-3; owasp_nhi: NHI1; pci_dss_v4.0: 8.2; soc2: CC6.1, CC7.1, CC8.1;

Cognito post-confirmation Lambda trigger has been deleted. Confirmation succeeds (the user is verified) but post-confirmation processing — user provisioning, group assignment, downstream account creation — fails silently.

**Remediation:** Redeploy the Lambda or remove post_confirmation. Audit recently confirmed users for missing downstream state (group membership, profile records, role assignments) and backfill.

---

### CTL.COGNITO.GHOST.PREAUTH.001

**Cognito Pre-Authentication Lambda Trigger References Deleted Function**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3, IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, CM-3, IA-2; owasp_nhi: NHI1; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1, A1.1, A1.2;

Cognito user pool has a pre-authentication Lambda trigger configured but the Lambda has been deleted. Every login attempt invokes a function that doesn't exist; the authentication call returns an error. The most disruptive trigger ghost — login is the most-used pool operation.

**Remediation:** Redeploy the Lambda with the same ARN, or remove pre_authentication from lambda_config: aws cognito-idp update-user-pool. Pre-authentication triggers commonly enforce IP allow-lists, risk gates, or device fingerprinting — confirm that intent is preserved through another control surface before removing.

---

### CTL.COGNITO.GHOST.PRESIGNUP.001

**Cognito Pre-Sign-Up Lambda Trigger References Deleted Function**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3, IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, CM-3, IA-2; owasp_nhi: NHI1; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1, A1.2;

Cognito user pool has a pre-sign-up Lambda trigger configured but the Lambda function has been deleted. Every user signup attempt fails because the trigger Lambda invocation errors. The pool appears configured; the signup flow is broken.

**Remediation:** Either redeploy the Lambda with the same ARN (preserving the trigger configuration) or remove the pre-sign-up trigger from the user pool: aws cognito-idp update-user-pool --user-pool-id <id> with lambda_config omitting pre_sign_up. After fix, validate by completing a signup in a sandbox.

---

### CTL.COGNITO.GHOST.PRETOKEN.001

**Cognito Pre-Token Generation Lambda Trigger References Deleted Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3, IA-5; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, CM-3, IA-5; owasp_nhi: NHI1; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito pre-token-generation Lambda has been deleted. Custom claim injection, token-time authorization decisions, and dynamic scope customization all stop working. Tokens are issued without the customizations the application expects.

**Remediation:** Redeploy the Lambda. After deployment, inspect a freshly issued token to confirm the expected custom claims are present. Until repair, downstream services that authorize using custom claims may fall back to default behavior — review whether the fallback is safe (deny by default) or permissive (allow by default).

---

### CTL.COGNITO.GHOST.RESOURCESRV.001

**Cognito App Client References Deleted Resource Server Scope**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, CM-3; iso_27001_2022: A.5.16, A.8.2; nist_800_53_r5: AC-3, CM-2, CM-3; owasp_nhi: NHI1; pci_dss_v4.0: 7.2; soc2: CC6.1, CC8.1;

Cognito user pool app client lists allowed OAuth scopes that include scopes from a resource server that has been deleted. Token requests that ask for those scopes return invalid_scope errors. The app client appears configured; some OAuth flows fail.

**Remediation:** Either recreate the resource server with the same identifier and scopes (preserving the app client configuration) or update the app client to remove the orphaned scopes: aws cognito-idp update-user-pool-client with allowed_o_auth_scopes filtered.

---

### CTL.COGNITO.GHOST.SAMLMETA.001

**Cognito SAML Identity Provider Metadata Unreachable**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, IA-2, IA-8; iso_27001_2022: A.5.16, A.5.17; nist_800_53_r5: AC-3, CM-2, IA-2, IA-8; owasp_nhi: NHI1; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito user pool has a SAML identity provider configured with a metadata URL that is no longer reachable. SAML federation fails because Cognito cannot fetch the IdP certificate or endpoints. Federated logins break.

**Remediation:** Verify the IdP metadata URL responds with valid metadata XML. If the IdP changed their endpoint, update the Cognito provider: aws cognito-idp update-identity-provider with corrected metadata URL or refreshed metadata file. For static metadata configurations, fetch fresh metadata from the IdP and re-upload.

---

### CTL.COGNITO.GHOST.USERMIGRATE.001

**Cognito User Migration Lambda Trigger References Deleted Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, CM-3; owasp_nhi: NHI1; pci_dss_v4.0: 8.2; soc2: CC6.1, CC8.1;

Cognito user-migration Lambda has been deleted while the pool still uses migration- on-sign-in. Users from the legacy directory cannot be migrated and cannot sign in to the new pool — the migration path is broken.

**Remediation:** Redeploy the Lambda or, if migration is complete, remove user_migration from lambda_config. If migration is partial, audit which legacy users have not yet signed in — those users are now blocked until the trigger is restored.

---

### CTL.COGNITO.GHOST.VERIFYAUTH.001

**Cognito Verify Auth Challenge Response Lambda Trigger References Deleted Function**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3, IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, CM-3, IA-2; owasp_nhi: NHI1; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1, A1.1;

Cognito verify-auth-challenge-response Lambda has been deleted. Even when define-auth and create-auth produce a challenge, the response cannot be validated — users complete the challenge correctly but their answer is never confirmed.

**Remediation:** Redeploy the verify-auth-challenge-response Lambda. Verify after deployment by running a complete custom-auth flow end-to-end in a sandbox.

---

### CTL.COGNITO.HOSTEDUI.CORS.001

**Cognito OAuth Endpoints Allow Wildcard CORS Origin**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-2, SC-7; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: IA-2, SC-7, SC-8; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

Cognito's OAuth endpoints (or a CDN layer in front of them) allow CORS from any origin. Tokens and authorization codes flowing through these endpoints become cross-origin readable, expanding the surface for XSS-driven token exfiltration.

**Remediation:** Restrict CORS to the application's explicit origins. If a CDN sits in front of Cognito, set CORS in the CDN configuration to the application domain list. Cognito itself doesn't expose arbitrary CORS configuration on its endpoints, so the misconfiguration is typically in customer-managed infrastructure (CloudFront, custom Lambda@Edge).

---

### CTL.COGNITO.HOSTEDUI.DEFAULT.001

**Cognito Hosted UI Uses Default Cognito Domain**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, AC-22; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito user pool hosted UI is reachable only through the default *.amazoncognito.com domain — no custom domain configured. Users see AWS infrastructure URLs during login; brand-mismatched URLs invite phishing confusion and damage trust signals.

**Remediation:** Register a custom domain on the user pool: aws cognito-idp create-user-pool-domain --domain auth.example.com --custom-domain-config CertificateArn=... Update application redirect URLs to use the custom domain. The default Cognito domain remains as a backup and continues to work.

---

### CTL.COGNITO.HOSTEDUI.SIGNUPADMIN.001

**Cognito Hosted UI Allows Sign-Up When Pool Is Admin-Managed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-2, IA-2; iso_27001_2022: A.5.16, A.5.18; nist_800_53_r5: AC-2, IA-2; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito user pool hosted UI is configured to allow self-sign-up but the pool's AdminCreateUserConfig has AllowAdminCreateUserOnly=true. The hosted UI shows a sign-up button that, when clicked, contradicts the pool's intent — inconsistent UX and surface mismatch.

**Remediation:** Disable hosted-UI sign-up so the presentation layer matches the pool's intent: aws cognito-idp update-user-pool-client with --explicit-auth-flows excluding self-sign-up. Alternatively, flip AllowAdminCreateUserOnly to false if self-sign-up is actually intended.

---

### CTL.COGNITO.IDENTITY.GUEST.001

**Cognito Identity Pools Must Not Allow Guest Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Cognito identity pools must disable unauthenticated (guest) identities. When enabled, any client can obtain temporary AWS credentials without signing in. The unauthenticated IAM role's permissions become effectively public.

**Remediation:** Disable unauthenticated identities on the identity pool. If guest access is required, scope the unauthenticated role to minimal permissions.

---

### CTL.COGNITO.IDP.CASECOLLISION.001

**Cognito Provider Names Differ Only by Case**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-4; soc2: CC7.1;

Two IdP provider names in the same Cognito User Pool differ only by letter case (e.g. CorpIdP and corpidp). Cognito treats them as distinct, but any downstream component that does case-insensitive comparison (.lower()) resolves them to the same provider, risking identity split or lookup mismatch. This is advisory: it is only exploitable if a downstream component normalizes case, so it is a WARN-class finding (low severity), distinct from the homoglyph collision (CTL.COGNITO.IDP.HOMOGLYPH.001, high).
Inspired by Doyensec CloudsecTidbits No. 4 — The Danger of Multi-SSO AWS Cognito User Pools.

**Remediation:** Rename one provider so the names differ by more than case, and normalize provider-name comparisons consistently across all downstream components.

---

### CTL.COGNITO.IDP.HOMOGLYPH.001

**Cognito User Pool Has Visually Confusable (Homoglyph) Provider Names**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** iso_27001_2022: A.8.16; nist_800_53_r5: IA-4, AU-10; owasp_nhi: NHI3; soc2: CC6.1, CC7.1;

Two IdP provider names in the same Cognito User Pool are visually identical but byte-distinct, using Unicode homoglyphs — e.g. LegitCorp (Latin 'e') and LеgitCorp (Cyrillic 'е' U+0435). Cognito enforces uniqueness only on byte-equal names, so both are accepted. They look identical in UIs, logs, and CLI output; if any downstream component normalizes inconsistently (lower(), NFKC), identity split or lookup mismatch follows — a confused-deputy and audit-log-confusion risk.
The collector NFKC-normalizes provider names (golang.org/x/text/unicode/norm) and flags a collision when two byte-distinct names share an NFKC form. Case-only collisions are a separate, lower-severity finding (CTL.COGNITO.IDP.CASECOLLISION.001).
Inspired by Doyensec CloudsecTidbits No. 4 — The Danger of Multi-SSO AWS Cognito User Pools.

**Remediation:** Rename one provider to an ASCII-only, visually distinct name. Restrict provider names to a known character set ([A-Za-z0-9_-]) at creation time and reject names that NFKC-normalize to an existing provider's form.

---

### CTL.COGNITO.IDP.IDENTIFIER.DUPLICATE.001

**Cognito IdP Identifier Claimed by More Than One Provider**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: IA-8, AC-4; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1;

Two different identity providers in the same Cognito User Pool register the same IdpIdentifier (e.g. both claim company.com). IdP identifiers drive email-domain routing, so a duplicate is an ambiguous routing conflict — which IdP receives users for that domain is undefined, and an attacker-controlled IdP that duplicates a legitimate domain identifier can intercept that domain's federation. Cognito does not reject byte-distinct duplicate identifiers across providers, so the platform must catch it. Detected even when the domain is not a public email domain (the FN trap).
Inspired by Doyensec CloudsecTidbits No. 4 — The Danger of Multi-SSO AWS Cognito User Pools.

**Remediation:** Ensure each IdpIdentifier is claimed by exactly one IdP. Remove the duplicate from the unintended provider and verify domain ownership before assigning a domain identifier to any IdP.

---

### CTL.COGNITO.IDPOOL.AUTHROLE.ASSUMEROLE.001

**Cognito Identity Pool Authenticated Role Can Assume Admin Roles**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6; hipaa: 164.308(a)(4)(ii)(B); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

Cognito identity pool's authenticated role has sts:AssumeRole permission targeting roles with administrative privileges. Any signed-in user can call AssumeRole, get short-lived credentials for the admin role, and operate as that role — lateral escalation through Cognito.

**Remediation:** Remove sts:AssumeRole permissions from the authenticated role unless there is a specific legitimate workflow (rare for end-user-facing apps). If needed, scope Resource to a single non-admin role and add a sts:ExternalId condition to prevent confused-deputy attacks. Verify the trust policy on the target role explicitly allows the Cognito authenticated role's ARN (not just 'any role from this account').

---

### CTL.COGNITO.IDPOOL.AUTHROLE.BROAD.001

**Cognito Identity Pool Authenticated Role Has Broad Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6; hipaa: 164.308(a)(4)(ii)(B); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

Cognito identity pool's authenticated IAM role has broad permissions — more than 20 allowed actions or wildcard actions. Every signed-in user receives credentials with the role's full action surface; broad roles collapse least-privilege at the authentication boundary.

**Remediation:** Replace wildcard actions with explicit action lists. Split capabilities across role mappings (admin users get role A, standard users get role B) rather than one wide role for everyone. Remove actions the application doesn't use; for actions used by a subset of users, gate them with role mapping based on Cognito group membership.

---

### CTL.COGNITO.IDPOOL.AUTHROLE.CROSSACCT.001

**Cognito Identity Pool Authenticated Role Permits Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-4, AC-6; hipaa: 164.308(a)(4)(ii)(B); iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-4, AC-6; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3, CC6.6;

Cognito identity pool's authenticated role policy grants actions on resources in another AWS account. Signed-in users obtain credentials authorized to act across the account boundary — data and operations in the foreign account are reachable through Cognito.

**Remediation:** Cross-account Cognito access is rare for legitimate end-user apps. If the cross-account permission is intentional (centralized resource accessed by multiple-account consumers), document the trust relationship and ensure the foreign-account resource policy or trust policy validates aws:PrincipalOrgID rather than blanket account allow. If unintentional, remove the cross-account Resource ARNs from the authenticated role's policy.

---

### CTL.COGNITO.IDPOOL.AUTHROLE.PASSROLE.001

**Cognito Identity Pool Authenticated Role Has iam:PassRole**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6; hipaa: 164.308(a)(4)(ii)(B); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

Cognito identity pool's authenticated role policy contains iam:PassRole. Any signed-in user can launch services (EC2, Lambda, ECS) with a different role attached — escalating to whatever permissions the passed role carries. Cognito turns into a privilege- escalation primitive.

**Remediation:** Remove iam:PassRole from the authenticated role. If the application genuinely needs PassRole (rare for end-user-facing apps — PassRole is typically a deployment-time permission), scope the action to a single specific role ARN with iam:PassedToService conditions matching the legitimate consumer service. The existing CTL.IAM.POLICY.PASSROLE.001 catches PassRole broadly; this control flags the case where Cognito's authenticated role is one of the holders.

---

### CTL.COGNITO.IDPOOL.CLASSICFLOW.001

**Cognito Identity Pool Allows Classic Authentication Flow**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2, SC-8; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, SC-8; pci_dss_v4.0: 8.3; soc2: CC6.1;

Cognito identity pool has allow_classic_flow set to true. The classic flow returns the raw OpenID token in the GetCredentialsForIdentity response — exposing a token format Cognito no longer recommends. Enhanced (basic) flow does not return a token; the recommended default is enhanced.

**Remediation:** Set allow_classic_flow to false on the identity pool: aws cognito-identity update-identity-pool with --allow-classic-flow false. Verify that the application uses GetCredentialsForIdentity (enhanced flow, no raw token) rather than the classic GetOpenIdTokenForDeveloperIdentity → AssumeRoleWithWebIdentity sequence.

---

### CTL.COGNITO.IDPOOL.PROVIDER.NOVALIDATION.001

**Cognito Identity Pool Provider Has No Audience Validation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-2, IA-8; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, IA-8, SC-8; pci_dss_v4.0: 8.3; soc2: CC6.1;

Cognito identity pool has an OIDC or SAML identity provider configured without audience restriction. Tokens issued for any audience by that provider are accepted for credential exchange — including tokens issued for completely unrelated services.

**Remediation:** Configure aud (audience) restriction on OIDC providers and SAML providers attached to the identity pool. The audience should be the specific app client ID or service identifier that issued the token. Tokens whose aud claim doesn't match should be rejected. Without this, Cognito accepts tokens from any consumer of the same provider.

---

### CTL.COGNITO.IDPOOL.ROLEMAPPING.NONE.001

**Cognito Identity Pool Has No Role Mapping**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.1; soc2: CC6.1, CC6.3;

Cognito identity pool has no role mapping configured — every authenticated user receives the default authenticated role regardless of their attributes, group membership, or token claims. There is no differentiation between admin users and standard users at the AWS-credentials layer.

**Remediation:** Configure role mapping rules using cognito-identity:role_mapping based on Cognito user-pool group membership or custom token claims. A typical pattern: map cognito:groups=admin to an admin role with elevated permissions, and a default 'authenticated' role for everyone else. Without role mapping, the pool cannot express least privilege between user populations even if the IAM role policies are perfectly written.

---

### CTL.COGNITO.IDPOOL.UNAUTH.BROAD.001

**Cognito Identity Pool Unauthenticated Role Has Broad Permissions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6; hipaa: 164.308(a)(4)(ii)(B); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, IA-2; pci_dss_v4.0: 7.1, 7.2, 8.3; soc2: CC6.1, CC6.3;

Cognito identity pool allows unauthenticated access AND the unauthenticated IAM role has broad permissions (more than ten allowed actions, or wildcard actions). Anonymous clients receive AWS credentials with excessive privileges — every action allowed by the role is publicly invocable on the internet.

**Remediation:** Either disable unauthenticated access entirely (most cases — see GUEST control) or scope the unauthenticated role to a handful of specific read-only actions against narrow resources. Replace wildcard actions with explicit action lists. The unauthenticated role should typically have fewer than five distinct actions, all against tightly-scoped resources.

---

### CTL.COGNITO.IDPOOL.UNAUTH.DDB.001

**Cognito Identity Pool Unauthenticated Role Has DynamoDB Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6; hipaa: 164.308(a)(4)(ii)(B), 164.312(a)(1); iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6, IA-2; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3, CC6.6;

Cognito identity pool allows unauthenticated access AND the unauthenticated role grants DynamoDB actions (GetItem, Query, Scan, PutItem, or wildcard dynamodb actions) on one or more tables. Anonymous clients can read from or write to DynamoDB through the Cognito session.

**Remediation:** Remove DynamoDB actions from the unauthenticated role. If anonymous read of specific items is genuinely required, front the table with an authenticated API rather than expose dynamodb:GetItem directly. Audit CloudTrail for dynamodb API calls under the unauth role — those are anonymous reads or writes that may have already touched the table.

---

### CTL.COGNITO.IDPOOL.UNAUTH.IAM.001

**Cognito Identity Pool Unauthenticated Role Has IAM Privileges**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6; hipaa: 164.308(a)(4)(ii)(B); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, IA-2; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

Cognito identity pool allows unauthenticated access AND the unauthenticated IAM role has IAM privileges (iam:* or admin-level IAM actions like CreateRole, PutRolePolicy, AttachRolePolicy, PassRole). Anonymous clients can escalate privileges through IAM — publicly available IAM administration.

**Remediation:** Remove all iam:* actions from the unauthenticated role immediately. There is no legitimate reason for an anonymous client to administer IAM. After removal, audit CloudTrail for any iam: API calls performed under the role's session — those were anonymous calls.

---

### CTL.COGNITO.IDPOOL.UNAUTH.LAMBDA.001

**Cognito Identity Pool Unauthenticated Role Has Lambda Invoke Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6; hipaa: 164.308(a)(4)(ii)(B); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, IA-2; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

Cognito identity pool allows unauthenticated access AND the unauthenticated role grants lambda:InvokeFunction on one or more Lambda functions. Anonymous clients can invoke Lambdas — turning the function into a publicly callable endpoint regardless of the function's intended access pattern.

**Remediation:** Remove lambda:InvokeFunction from the unauthenticated role. If anonymous invocation is genuinely required, front the Lambda with API Gateway or Lambda function URL with their own throttling and authentication, rather than expose direct Invoke through Cognito.

---

### CTL.COGNITO.IDPOOL.UNAUTH.S3.001

**Cognito Identity Pool Unauthenticated Role Has S3 Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-4, AC-6; hipaa: 164.308(a)(4)(ii)(B), 164.312(a)(1); iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-4, AC-6, IA-2; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3, CC6.6;

Cognito identity pool allows unauthenticated access AND the unauthenticated role grants S3 actions (GetObject, PutObject, ListBucket, or wildcard s3 actions) on one or more buckets. Anonymous clients can read from or write to S3 by exchanging Cognito identities for AWS credentials.

**Remediation:** Remove S3 actions from the unauthenticated role unless the bucket is intentionally public (and even then, prefer making the bucket itself public via bucket policy rather than threading anonymous access through Cognito). Audit CloudTrail for s3 API calls performed under the unauthenticated role's session — those are anonymous reads or writes that may have already exfiltrated or modified data.

---

### CTL.COGNITO.IDPOOL.UNAUTH.UNUSED.001

**Cognito Identity Pool Allows Unauthenticated Access But No Application Uses It**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, CM-8; iso_27001_2022: A.5.9, A.5.18; nist_800_53_r5: AC-3, CM-2, CM-8, SA-22; pci_dss_v4.0: 7.1; soc2: CC6.1, CC8.1;

Cognito identity pool allows unauthenticated identities but no application references this identity pool. The default-on configuration exposes anonymous AWS credentials with no matching legitimate use. Either clean up the pool or disable unauthenticated access.

**Remediation:** Either delete the identity pool entirely (no application uses it — it's pure governance debt) or disable unauthenticated access if the pool will be wired into an application later. Default-on unauthenticated access is exposure without purpose.

---

### CTL.COGNITO.INCOMPLETE.001

**Complete Data Required for Cognito Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** identity

The observation snapshot is missing required Cognito user pool properties.

**Remediation:** Ensure the extractor calls aws cognito-idp describe-user-pool and maps MfaConfiguration to the identity observation properties.

---

### CTL.COGNITO.LOCKOUT.NONE.001

**Cognito User Pool Has No Brute-Force Lockout**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.6; fedramp_moderate: AC-7; hipaa: 164.308(a)(5)(ii)(D); iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: AC-7, IA-2; pci_dss_v4.0: 8.3.4; soc2: CC6.1, CC6.6;

Cognito user pool has neither account-level lockout configured nor advanced security features enabled to provide adaptive auth. Failed-login attempts can continue indefinitely with no throttling beyond Cognito's per-account rate limits. Brute- force and credential-stuffing attacks face no application-side resistance.

**Remediation:** Enable advanced security features on the user pool with risk_configuration set so high-risk events block authentication and medium-risk events require step-up authentication: aws cognito-idp set-risk-configuration with appropriate actions on Compromised Credentials and Account Takeover Risk decisions. Advanced security adds adaptive throttling that detects brute-force patterns and locks the offending IP / username combination.

---

### CTL.COGNITO.METRICS.LOGINS.001

**No CloudWatch Metrics for Cognito Login Success or Failure**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, AU-12, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

No CloudWatch metrics capture login success and failure rates for the user pool. The team has no baseline to detect anomalies against — no graph of 'what's normal,' no alert when the curve diverges, no data feed for SIEM ingestion.

**Remediation:** Configure CloudWatch metric filters on CloudTrail events for InitiateAuth success / failure, RespondToAuthChallenge outcomes, and SignUp success. Publish them as CloudWatch metrics so they're chartable, alarmable, and exportable to SIEM. Without this base layer of metrics, the Cognito sign-in alarm controls have nothing to alarm on.

---

### CTL.COGNITO.MFA.001

**Cognito User Pool Must Enforce MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2(1); hipaa: 164.312(d); nist_800_53_r5: IA-2(1); owasp_nhi: NHI4; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

Cognito user pools handling PHI must enforce multi-factor authentication. Without MFA, a compromised password grants full access to the application and any PHI it serves.

**Remediation:** Set MfaConfiguration to ON (required) on the user pool. Run: aws cognito-idp set-user-pool-mfa-config --user-pool-id xxx --mfa-configuration ON --software-token-mfa-configuration Enabled=true

---

### CTL.COGNITO.MFA.SMSONLY.001

**Cognito User Pool MFA Allows Only SMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.5; fedramp_moderate: IA-2, IA-5; hipaa: 164.308(a)(5)(ii)(D), 164.312(a)(2)(i); iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: IA-2, IA-5; pci_dss_v4.0: 8.4, 8.5; soc2: CC6.1, CC6.6;

Cognito user pool has MFA enabled but only SMS is permitted as the second factor. SMS MFA is the weakest standard MFA channel — vulnerable to SIM swap, SS7 interception, and social engineering against carriers. A pool that requires SMS for MFA is requiring something many attackers can defeat.

**Remediation:** Enable software_token_mfa_configuration (TOTP) on the user pool: aws cognito-idp set-user-pool-mfa-config with SoftwareTokenMfaConfiguration.Enabled=true. Encourage or require users to enroll an authenticator app (TOTP). Keep SMS as a fallback if needed but make TOTP the preferred path during enrollment. For populations whose threat model includes SIM-swap (executives, finance, security teams), make TOTP the only acceptable MFA.

---

### CTL.COGNITO.OIDC.ISSUER.001

**Cognito OIDC Provider Issuer URL Unreachable**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2, IA-8; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, IA-8; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito OIDC identity provider's issuer URL is unreachable. Cognito cannot fetch the OpenID Connect discovery document; OIDC- federated logins fail.

**Remediation:** Verify the issuer URL responds at /.well-known/openid-configuration. If the IdP changed their issuer URL, update the provider configuration: aws cognito-idp update-identity-provider with corrected OIDC issuer. Test with curl from outside the VPC if the issuer is internet-facing, or from a Cognito-reachable network if the issuer is private.

---

### CTL.COGNITO.OIDC.SCOPEBROAD.001

**Cognito OIDC Provider Requests Excessive Scopes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.5; nist_800_53_r5: AC-3, AC-6, IA-2; owasp_nhi: NHI3; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

Cognito OIDC identity provider configuration requests scopes beyond `openid profile email`. Extra scopes (groups, offline_access, custom IdP scopes) request more authorization than the application needs and grant Cognito access to more user data than intended.

**Remediation:** Update the Cognito OIDC provider to request only the minimum scopes (typically `openid profile email`): aws cognito-idp update-identity-provider with provider_details containing the narrowed authorize_scopes value. Any additional scope (groups, offline_access) should have a documented justification.

---

### CTL.COGNITO.OIDC.SECRETROT.001

**Cognito OIDC Provider Client Secret Not Rotated**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-5; iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: IA-5; owasp_nhi: NHI3; pci_dss_v4.0: 8.6; soc2: CC6.1, CC8.1;

Cognito OIDC identity provider's client secret has not been rotated in 90+ days. Long-lived OIDC client secrets become high-value credentials over time; compromise of a secret rotated infrequently yields long-term federated access.

**Remediation:** Generate a new client secret at the IdP, update the Cognito provider with the new value: aws cognito-idp update-identity- provider with provider_details containing the new client_secret. Revoke the old secret at the IdP after a brief overlap window. For high-trust deployments, automate the rotation cycle on a quarterly cadence.

---

### CTL.COGNITO.ORPHAN.CLIENT.001

**Cognito App Client Has No Recent Authentication Activity**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-8, IA-5; owasp_nhi: NHI1; soc2: CC8.1;

Cognito user pool app client has had no authentication activity in 90+ days — TokenIssuance metric reports zero, no refresh activity. The client exists with valid credentials and a callback list but no application uses it.

**Remediation:** Confirm with the application owner that the client is unused. If decommissioned, delete the app client (aws cognito-idp delete-user-pool-client). Orphaned clients with secrets are particularly dangerous — a forgotten client_secret in old code or stored in a long-lived secrets manager grants the same access today as it did when the client was created.

---

### CTL.COGNITO.ORPHAN.IDPOOL.001

**Cognito Identity Pool Has No Identity Providers**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-8, SA-22; owasp_nhi: NHI1; soc2: CC8.1;

Cognito identity pool exists with no identity providers configured (no Cognito user pool, no SAML, no OIDC, no social providers, no developer-authenticated identities). The pool can't actually authenticate anyone — it's a configuration shell.

**Remediation:** Confirm whether the pool is intended for use. If yes, configure an identity provider (link to a Cognito user pool, add a SAML/OIDC provider, etc.). If no, delete the pool. An identity pool with no providers but allow_unauthenticated=true is the worst kind of dead-but-dangerous — no legitimate users but anonymous credentials still issuable.

---

### CTL.COGNITO.ORPHAN.NOCLIENTS.001

**Cognito User Pool Has No App Clients**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-8, SA-22; owasp_nhi: NHI1; soc2: CC8.1;

Cognito user pool exists but has zero app clients configured. The pool can hold users but no application can authenticate against it. Either the pool is leftover from a decommissioned project or a new pool was created and the integration was abandoned mid-setup.

**Remediation:** Confirm whether any application is intended to use this pool. If yes, create the app client per the integration plan. If no, delete the pool — the controls in COG-1 through COG-8 don't apply because there's no consumer, but the pool still consumes quota and contributes to compliance scope.

---

### CTL.COGNITO.ORPHAN.NOUSERS.001

**Cognito User Pool Has Zero Users for 90+ Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-8, SA-22; owasp_nhi: NHI1; soc2: CC8.1;

Cognito user pool's estimated user count is zero and has been zero for 90+ days. The pool is dormant — no users, no authentication traffic, no reason to keep it. Same dormancy threshold as the rest of the catalog (Lambda, ELB, Secrets Manager).

**Remediation:** Confirm with the application team that the pool is genuinely unused. If decommissioned, delete the pool to remove it from compliance scope and free quota. If the pool is intended to receive future registrations (a slow-rolling launch), tag it so future audits don't re-flag.

---

### CTL.COGNITO.ORPHAN.RESOURCESRV.001

**Cognito Resource Server Has No Referencing App Clients**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-8, SA-22; owasp_nhi: NHI1; soc2: CC8.1;

Cognito resource server defines custom scopes but no app client lists those scopes in allowed_o_auth_scopes. The scopes can never be requested or issued — the resource server is configuration noise.

**Remediation:** Confirm whether the resource server's scopes are intended for use. If yes, update an app client to include the scopes in allowed_o_auth_scopes. If no, delete the resource server (aws cognito-idp delete-resource-server). Orphan resource servers usually exist because the integrating application was decommissioned but Cognito-side resources weren't cleaned up.

---

### CTL.COGNITO.ORPHAN.TRIGGERS.001

**Cognito User Pool Has Lambda Triggers but Pool Is Dormant**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-8, SA-22; owasp_nhi: NHI1; soc2: CC8.1;

Cognito user pool has Lambda triggers configured AND the pool is dormant (zero users, no auth activity). The triggers don't fire — the pool has no auth traffic — but they exist in configuration, accumulate drift, and contribute to attack surface if the pool is later reactivated by an attacker.

**Remediation:** Decide whether the pool is dormant intentionally or by neglect. If intentional and the pool will be reactivated, leave the triggers but document the pause. If by neglect, delete the pool — the COG-1 ghost controls catch trigger Lambdas that later get deleted, and you'll save yourself a future incident.

---

### CTL.COGNITO.PASSWORD.001

**Cognito User Pools Must Enforce a Strong Password Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-5(1); hipaa: 164.312(d); nist_800_53_r5: IA-5(1); pci_dss_v4.0: 8.3.6; soc2: CC6.1;

Cognito user pools must enforce a minimum password length of 12 characters and require at least three of four character classes (uppercase, lowercase, numbers, special characters). Cognito password policy is independent of the IAM account password policy — a strong IAM policy does not protect application users authenticated through Cognito. A user pool with weak defaults allows end users to set trivially guessable passwords. Temporary password validity must not exceed 7 days — temporary passwords issued during account creation or password reset that remain valid for extended periods are a credential exposure risk if the invitation email is intercepted. For user pools handling PHI (patient portals, healthcare applications), weak application passwords are a direct credential compromise risk that IAM password controls cannot address.
This control reads a pre-computed `is_weak` rollup that the collector derives from the underlying minimum-length and char-class requirements (uppercase, lowercase, numbers, symbols). The rollup is intentional: one finding fires on weak-password configurations of any shape rather than four near-identical findings per char-class. The cost is triage granularity — the finding does not name *which* specific requirement is missing. Operators inspect the observation's `password_policy` object directly to identify the failing field. Temporary password validity is covered by a sibling control (`TEMPPASSWORD.001`) reading `temp_password_valid_days_exceeded`.

**Remediation:** Update the user pool password policy via the Cognito console or UpdateUserPool API. Set minimum password length to 12 or higher. Require at least three of: uppercase, lowercase, numbers, special characters. Set temporary password validity to 7 days or less. Consider enabling Cognito advanced security features for compromised credential detection as a complementary control.

---

### CTL.COGNITO.RECOVERY.NOMFA.001

**Cognito Account Recovery Bypasses MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.5; fedramp_moderate: IA-2, IA-5; hipaa: 164.308(a)(5)(ii)(D), 164.312(a)(2)(i); iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: IA-2, IA-5, AC-7; owasp_nhi: NHI4; pci_dss_v4.0: 8.4, 8.5; soc2: CC6.1, CC6.6;

Cognito user pool enforces MFA but the account-recovery configuration permits recovery via email or phone without challenging MFA. An attacker who controls the user's email or SMS recovery channel can reset the password and complete authentication without ever encountering the second factor. MFA becomes effectively optional through the recovery path.

**Remediation:** Configure the account-recovery setting so the recovery flow re-challenges MFA after the user proves control of the email or phone. AdminResetUserPassword and self-service password reset both need to re-issue the MFA challenge before completing. If the user pool uses advanced security features, configure the recovery risk decision to require step-up auth.

---

### CTL.COGNITO.RESOURCESRV.BROADSCOPE.001

**Cognito Resource Server Has Single Broad Scope**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.5; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

Cognito resource server defines a single scope that covers all operations on the protected API. There's no granularity — any token with the scope can perform any operation. The OAuth surface exists but doesn't differentiate read from write, admin from user, or anything else.

**Remediation:** Split the single scope into operation- aligned scopes (read, write, admin) or domain-aligned scopes (orders.read, orders.write, customers.read, etc.). Update app clients to grant only the scopes the user populations need. The application then checks token scopes per-operation; users with the read scope cannot perform write operations even if their tokens validate.

---

### CTL.COGNITO.RESOURCESRV.NONE.001

**Cognito User Pool Has OAuth Flows Without Resource Servers**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.5; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

Cognito user pool has app clients using OAuth flows (code, implicit) but no resource servers defined. The pool can only issue tokens with the standard scopes (openid, email, profile, aws.cognito.signin.user.admin) — there is no way to express fine-grained authorization for the application's protected resources.

**Remediation:** Define resource servers matching the application's API surfaces, with scopes matching the API operations: aws cognito-idp create-resource-server --identifier https://api.example.com --scopes ScopeName=read,ScopeDescription=... Update app clients to include the new scopes in allowed_o_auth_scopes. The application can then check token scopes to authorize specific operations rather than relying on group membership alone.

---

### CTL.COGNITO.SAML.ATTRMAP.001

**Cognito SAML Attribute Mapping Missing Required Attributes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2, IA-8; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, IA-8; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito SAML provider's attribute mapping doesn't include required attributes such as email or name. Federated users authenticate but their Cognito records lack the attributes the application expects. Application-side authorization (group lookups, profile rendering, recovery flows) fails because the data isn't there.

**Remediation:** Update the SAML provider's attribute mapping to include at minimum email and name attributes from the IdP. Use aws cognito-idp update-identity-provider with --attribute-mapping email=mail,given_name=givenname,... matching the IdP's claim names. Verify by completing a federated login and checking that the resulting Cognito user's attributes are populated.

---

### CTL.COGNITO.SAML.CERTEXPIRED.001

**Cognito SAML Provider Signing Certificate Expired**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-2, SC-12; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: IA-2, SC-12; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito SAML identity provider's signing certificate (in cached metadata) has expired. Signature verification fails on every incoming assertion; federation is broken until the cached cert is refreshed.

**Remediation:** Refresh the metadata so Cognito picks up the IdP's current cert. For URL-based metadata, force a refresh by reapplying the configuration. For static metadata, fetch fresh metadata from the IdP and re-upload. Coordinate with the IdP team to confirm their current certificate rotation cadence — chronic cert-expiration failures suggest the metadata refresh path itself is broken.

---

### CTL.COGNITO.SAML.METAEXPIRED.001

**Cognito SAML Provider Metadata Cached as Expired**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-2, IA-8; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, IA-8, SC-12; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito SAML identity provider's cached metadata document is past its validUntil date. Cognito treats expired metadata as invalid; SAML federation begins to fail silently as the cached document ages out. Distinct from GHOST.SAMLMETA (URL unreachable) — here the metadata fetched successfully but has aged past validity.

**Remediation:** Refresh the metadata: aws cognito-idp update-identity-provider with the same metadata URL forces Cognito to refetch. For static metadata (file upload rather than URL), pull fresh metadata from the IdP and re-upload. Long-term, prefer URL- based metadata so refresh is automatic.

---

### CTL.COGNITO.SAML.NOENCRYPT.001

**Cognito SAML Assertion Encryption Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-2, SC-8, SC-13; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: IA-2, SC-8, SC-13; owasp_nhi: NHI3; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

Cognito SAML identity provider does not request encrypted SAML assertions. Assertions travel through the user's browser in plaintext, exposing IdP-issued attributes (email, group memberships, custom claims) to anyone who can intercept the response — malicious browser extensions, network on- path attackers, leaked browser history.

**Remediation:** Enable assertion encryption: configure EncryptedResponses on the IdP side and upload Cognito's signing certificate to the IdP. The assertion travels encrypted end-to-end and only Cognito (with the private key) can decrypt. Note that HTTPS protects the channel between browser and IdP / browser and Cognito, but the assertion sits in the browser as POST data — encryption keeps it confidential at that layer too.

---

### CTL.COGNITO.SAML.NOREFRESH.001

**Cognito SAML Provider Configured with Static Metadata File**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: CM-2, IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, IA-2, IA-8; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito SAML identity provider is configured with a static metadata file rather than a metadata URL. Static metadata never auto- refreshes — IdP certificate rotation breaks federation until a human re-uploads. The failure mode is silent until the next IdP cert rotation.

**Remediation:** Switch to URL-based metadata: aws cognito-idp update-identity-provider with provider_details containing MetadataURL pointing at the IdP's metadata endpoint. Cognito periodically refetches the URL, picking up certificate rotations automatically. Static-file uploads are reserved for tightly-controlled scenarios where the metadata URL isn't reachable from Cognito.

---

### CTL.COGNITO.SAML.NOSIGN.001

**Cognito SAML Provider Does Not Require Signed Assertions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-2, SC-12, SC-13; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, SC-12, SC-13; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1;

Cognito SAML identity provider configuration does not require signed assertions. Cognito accepts assertions without verifying the signature — an attacker who can craft a SAML response (no infrastructure access required) can forge a federated identity.

**Remediation:** Enable signature verification on the SAML provider: aws cognito-idp update-identity-provider with provider details requiring signed assertions. Verify by submitting an unsigned assertion to the SAML endpoint and confirming Cognito rejects it. Pair with encrypted assertions for full protection against tampering and eavesdropping.

---

### CTL.COGNITO.SELFREG.001

**Cognito User Pools Must Disable Unrestricted Self-Registration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

Cognito user pools should require administrator-created accounts (AllowAdminCreateUserOnly=true). Unrestricted self-registration lets anyone create an account and potentially access resources mapped through identity pools.

**Remediation:** Set AllowAdminCreateUserOnly to true in AdminCreateUserConfig.

---

### CTL.COGNITO.SOCIAL.ANYDOMAIN.001

**Cognito Provider Allows Any Email Domain or Claims a Public-Domain Identifier**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-2, IA-2; iso_27001_2022: A.5.16, A.5.18; nist_800_53_r5: AC-2, IA-2, IA-8; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1, CC6.3;

Cognito federation has an open-domain routing risk. Either (1) a social identity provider has no domain restriction — anyone with a Google, Facebook, Apple, or Amazon account can register regardless of email domain; or (2) an IdP's IdpIdentifiers registers a public email domain (gmail.com, outlook.com, yahoo.com, hotmail.com, protonmail.com, icloud.com, …). IdP identifiers control email-domain routing (user@domain -> the IdP that owns the domain), and Cognito does not enforce domain ownership — so an IdP claiming a public domain hijacks routing for every user on that domain. For applications meant only for users with corporate identities, both open the front door to the internet.
Inspired by Doyensec CloudsecTidbits No. 4 — The Danger of Multi-SSO AWS Cognito User Pools.

**Remediation:** Decide which email domains should be permitted for federated registration. For internal-only applications, restrict to corporate domains. Use a pre-sign-up Lambda trigger to inspect the email domain on the incoming social-provider profile and reject non-matching registrations. Document the allow-list so future expansions don't silently bypass the gate.

---

### CTL.COGNITO.SOCIAL.NOVERIFY.001

**Cognito Social Provider Maps Email Without Marking It Verified**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2, IA-5; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, IA-5; owasp_nhi: NHI3; pci_dss_v4.0: 8.2; soc2: CC6.1;

Cognito social identity provider's attribute mapping passes email through but doesn't mark email_verified=true even though the social provider has already verified the email. Cognito treats the email as unverified and the application's verified- email checks block legitimate users while silently accepting spoofed inputs.

**Remediation:** Update the social provider's attribute mapping to set email_verified=true based on the IdP's verified-email claim. Google, Apple, and Amazon all release email_verified in their token responses — map that claim through. Facebook treats email as verified by default after successful authentication; map a literal 'true' in that case. Test by completing a federated login and confirming the Cognito user's email_verified attribute is true.

---

### CTL.COGNITO.SOCIAL.TESTCREDS.001

**Cognito Social Provider Configured with Test Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: CM-2, IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, IA-2; owasp_nhi: NHI3; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

Cognito social identity provider (Google, Facebook, Apple, Amazon, etc.) is configured with credentials that match known test or sandbox app IDs — promotion to production without rotating credentials. Test app IDs often have different rate limits, distinct consent UX, and may permit registration patterns the production app intentionally blocks.

**Remediation:** Create a production app at the social provider (Google Cloud Console, Meta for Developers, Apple Developer, etc.) and update the Cognito provider to use the production client_id and client_secret. The test app was probably created during initial integration and never rotated.

---

### CTL.COGNITO.TEMPPASSWORD.001

**Cognito Temporary Passwords Must Expire Within 7 Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; owasp_nhi: NHI7;

Cognito user pool temporary password validity must not exceed 7 days. Long-lived temporary passwords increase the window for credential interception or misuse.

**Remediation:** Set TemporaryPasswordValidityDays to 7 or less.

---

### CTL.COGNITO.TOKEN.REFRESHNOROT.001

**Cognito App Client Does Not Rotate Refresh Tokens**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-5; iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: IA-5; pci_dss_v4.0: 8.6; soc2: CC6.1;

Cognito app client does not rotate refresh tokens on use. The same refresh token works for the entire validity window (potentially 30+ days), making token theft a long-term compromise rather than a short-term one. Refresh-token rotation invalidates each token after exchange and issues a fresh one.

**Remediation:** Enable refresh-token rotation on the app client: aws cognito-idp update-user-pool-client with --enable-token-revocation true and the appropriate refresh token rotation setting. After enable, every refresh exchange invalidates the old token and issues a new one — a stolen token works only until the legitimate user next refreshes.

---

### CTL.COGNITO.VERIFY.EMAIL.001

**Cognito User Pool Does Not Auto-Verify Email**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.5; fedramp_moderate: IA-2, IA-5; hipaa: 164.308(a)(5)(ii)(D); iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: IA-2, IA-5; pci_dss_v4.0: 8.2; soc2: CC6.1, CC6.6;

Cognito user pool does not auto-verify the email attribute. Users register with whatever email they type, including emails they don't control. Account recovery flows that target the email send recovery codes to the unverified address — the listed owner may never receive the message.

**Remediation:** Add email to auto_verified_attributes on the user pool: aws cognito-idp update-user-pool with --auto-verified-attributes email. After this, signup requires the user to receive and submit a verification code sent to the email — confirming control of the address before the account is usable. Existing users with unverified email need a separate backfill or re-confirmation flow.

---

### CTL.COGNITO.VERIFY.PHONE.001

**Cognito User Pool Uses SMS MFA Without Phone Verification**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.5; fedramp_moderate: IA-2, IA-5; hipaa: 164.308(a)(5)(ii)(D); iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: IA-2, IA-5; pci_dss_v4.0: 8.4, 8.5; soc2: CC6.1, CC6.6;

Cognito user pool has SMS MFA enabled but the phone_number attribute is not auto-verified. MFA codes are sent to unverified phone numbers — the listed number may not actually belong to the user. An attacker who registers with a victim's phone (typo, social engineering) receives the victim's MFA codes.

**Remediation:** Add phone_number to auto_verified_attributes on the user pool: aws cognito-idp update-user-pool --auto-verified-attributes email phone_number (preserve any other auto-verified attributes). Before SMS MFA can be used, the user must complete the phone-verification flow proving they receive SMS at the registered number. For existing users with unverified phone, require a one-time re-verification at next login.

---

### CTL.COGNITO.WAF.001

**Cognito User Pools Must Have WAF ACL Attached**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Cognito user pools must be associated with an AWS WAFv2 web ACL for rate limiting, bot protection, and IP filtering on the hosted UI and public API endpoints. Without WAF, the authentication endpoint is unprotected against credential stuffing and brute force attacks.

**Remediation:** Associate a WAFv2 web ACL with the user pool. Configure rate limiting and bot protection rules.

---


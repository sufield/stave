# OWASP Non-Human Identity (NHI) Top 10 — Stave Coverage

This document maps each OWASP NHI Top 10 risk to specific Stave
controls that detect or prevent it. Annotations live in each
control's `compliance.owasp_nhi` field, queryable via
`stave controls list --format json`.

- Catalog version: 2816 controls
- Reference: <https://owasp.org/www-project-non-human-identities-top-10/>

## Coverage Summary

| #     | Risk                                | Controls | Coverage |
|-------|-------------------------------------|----------|----------|
| NHI1  | Improper Offboarding                | 41       | HIGH     |
| NHI2  | Secret Leakage                      | 11       | HIGH     |
| NHI3  | Vulnerable Third-Party NHI          | 21       | HIGH     |
| NHI4  | Insecure Authentication             | 13       | HIGH     |
| NHI5  | Overprivileged NHI                  | 75       | HIGH     |
| NHI6  | Insecure Cloud Deployment           | 14       | HIGH     |
| NHI7  | Long-Lived Secrets                  | 36       | HIGH     |
| NHI8  | Insufficient Logging and Monitoring | 17       | HIGH     |
| NHI9  | Lack of Secrets Management          | 9        | MEDIUM   |
| NHI10 | Human Use of NHI                    | 3        | LOW      |

Coverage levels: HIGH = 5+ controls span multiple services;
MEDIUM = 2-4 controls; LOW = 1 control or partial coverage;
NONE = gap.

A given control may map to multiple NHI risks. The annotation
records every applicable risk (e.g. `owasp_nhi: "NHI1, NHI7"`).

## NHI1 — Improper Offboarding

**Risk:** Stale credentials, orphaned service accounts, and
decommissioned resources that retain active permissions or
references after their owning workload is gone.

**Detection theme:** signal staleness on the identity object
itself (last-used age, unused access keys) and signal ghost
references where one resource points to a deleted dependency
(Cognito triggers naming a deleted Lambda; IAM trust naming a
deleted external account).

**Stave controls:**

IAM credential lifecycle:
- `CTL.IAM.ACCOUNT.INACTIVE.001` — IAM user has not signed in or used a key
- `CTL.IAM.CRED.UNUSED.001` — Access key never used
- `CTL.IAM.CRED.UNUSED45.001` — Access key not used in 45+ days
- `CTL.IAM.CRED.SETUPKEY.001` — Setup-only access key still active
- `CTL.IAM.ROLE.UNUSED.001` — IAM role with no recent activity
- `CTL.IAM.IDENTITY.USERS.EXCESSIVE.001` — Account has more IAM users than expected
- `CTL.IAM.CHAIN.GHOST.DELETION.001` — Role chain references deleted role

IAM trust ghosts:
- `CTL.IAM.TRUST.GHOST.ACCOUNT.001` — Trust policy names a non-existent AWS account
- `CTL.IAM.TRUST.GHOST.ORG.001` — Trust policy names a non-existent organization
- `CTL.IAM.TRUST.GHOST.SAML.001` — Trust policy names a deleted SAML provider

Cognito trigger ghosts (15 controls — one per trigger type):
- `CTL.COGNITO.GHOST.PRESIGNUP.001`
- `CTL.COGNITO.GHOST.PREAUTH.001`
- `CTL.COGNITO.GHOST.POSTAUTH.001`
- `CTL.COGNITO.GHOST.POSTCONFIRM.001`
- `CTL.COGNITO.GHOST.PRETOKEN.001`
- `CTL.COGNITO.GHOST.CUSTOMMSG.001`
- `CTL.COGNITO.GHOST.CREATEAUTH.001`
- `CTL.COGNITO.GHOST.DEFINEAUTH.001`
- `CTL.COGNITO.GHOST.VERIFYAUTH.001`
- `CTL.COGNITO.GHOST.USERMIGRATE.001`
- `CTL.COGNITO.GHOST.RESOURCESRV.001`
- `CTL.COGNITO.GHOST.SAMLMETA.001`
- `CTL.COGNITO.GHOST.IDPOOL.001`
- `CTL.COGNITO.GHOST.DOMAINCERT.001`
- `CTL.COGNITO.GHOST.DOMAINDNS.001`

Cognito orphans:
- `CTL.COGNITO.ORPHAN.CLIENT.001`
- `CTL.COGNITO.ORPHAN.IDPOOL.001`
- `CTL.COGNITO.ORPHAN.NOCLIENTS.001`
- `CTL.COGNITO.ORPHAN.NOUSERS.001`
- `CTL.COGNITO.ORPHAN.RESOURCESRV.001`
- `CTL.COGNITO.ORPHAN.TRIGGERS.001`

Active Directory + Azure stale identities:
- `CTL.AD.ACCOUNT.STALE.001` — AD account inactive
- `CTL.AD.STALE.ADMIN.001` — Inactive admin account retains privileges
- `CTL.AZURE.IDENTITY.STALE.001` — Azure identity inactive

KMS / secrets lifecycle:
- `CTL.KMS.LIFECYCLE.DORMANT.001` — KMS key unused
- `CTL.KMS.PENDING.DELETION.001` — Key scheduled for deletion still referenced
- `CTL.KMS.GRANT.ORPHAN.001` — KMS grant points to deleted grantee
- `CTL.KMS.CROSSACCOUNT.DECOMMISSIONED.001` — Cross-account grant to retired account
- `CTL.KMS.POLICY.GHOSTREF.001` — KMS policy references deleted principal
- `CTL.SECRETS.GHOST.ROTATIONLAMBDA.001` — Secret rotation Lambda is deleted

Lifecycle (already annotated):
- `CTL.LIFECYCLE.STAGING.STALE.001` — Stale non-production resource

## NHI2 — Secret Leakage

**Risk:** Credentials embedded in code, configuration, user data,
or environment variables — accessible to anyone with read on
those surfaces.

**Stave controls:**

- `CTL.IAM.CREDENTIAL.USERDATA.001` — AWS keys in EC2 user data
- `CTL.IAM.CREDENTIAL.CFN.001` — AWS keys in CloudFormation parameters
- `CTL.IAM.CREDENTIAL.CICD.001` — AWS keys in CI/CD configuration
- `CTL.IAM.ROOT.ACCESSKEY.001` — Root account uses an access key (apex credential)
- `CTL.LAMBDA.ENV.SECRETS.001` — Lambda env var likely contains a secret
- `CTL.LAMBDA.ENV.VISIBLE.VERSIONS.001` — Secret-shaped env var retained across versions
- `CTL.LAMBDA.ENV.EXCESSIVE.001` — Excessive env vars increase leakage surface
- `CTL.LAMBDA.LAYER.SECRETS.001` — Secret detected in Lambda layer contents
- `CTL.LAMBDA.SECRETS.NOTMANAGED.001` — Secret used without secrets-manager wrapping
- `CTL.LAMBDA.SECRETS.SSM.INSECURE.001` — SSM parameter holds a secret as plain string
- `CTL.LAMBDA.SECRETS.BROKEN.REF.001` — Lambda references a missing secret

## NHI3 — Vulnerable Third-Party NHI

**Risk:** Federated identities, OIDC/SAML providers, and social
sign-in integrations expand the trust surface to systems
operated by parties outside the workload's blast radius.

**Stave controls:**

IAM federation:
- `CTL.IAM.FEDERATION.001` — Federation baseline misconfigured
- `CTL.IAM.FEDERATION.ROLEMAPPING.001` — Federated role mapping permissive
- `CTL.IAM.FEDERATION.SAML.AUDIENCE.001` — SAML audience restriction missing
- `CTL.IAM.FEDERATION.SAML.CERT.001` — SAML signing certificate weak
- `CTL.IAM.FEDERATION.SESSION.DURATION.001` — Federated session too long
- `CTL.IAM.FEDERATION.SESSIONTAG.001` — Session tag handling exposed

IAM OIDC trust:
- `CTL.IAM.TRUST.OIDC.001` — OIDC trust missing audience claim
- `CTL.IAM.TRUST.OIDC.002` — OIDC trust missing subject claim
- `CTL.IAM.TRUST.OIDC.003` — OIDC trust permits wildcard subjects

Cognito federation:
- `CTL.COGNITO.OIDC.ISSUER.001` — OIDC issuer URL untrusted
- `CTL.COGNITO.OIDC.SCOPEBROAD.001` — OIDC scope too broad
- `CTL.COGNITO.OIDC.SECRETROT.001` — OIDC client secret stale
- `CTL.COGNITO.SAML.ATTRMAP.001` — SAML attribute mapping permissive
- `CTL.COGNITO.SAML.CERTEXPIRED.001` — SAML signing cert expired
- `CTL.COGNITO.SAML.METAEXPIRED.001` — SAML metadata expired
- `CTL.COGNITO.SAML.NOENCRYPT.001` — SAML assertions unencrypted
- `CTL.COGNITO.SAML.NOREFRESH.001` — SAML metadata never refreshed
- `CTL.COGNITO.SAML.NOSIGN.001` — SAML assertions unsigned
- `CTL.COGNITO.SOCIAL.ANYDOMAIN.001` — Social login accepts any domain
- `CTL.COGNITO.SOCIAL.NOVERIFY.001` — Social login skips email verification
- `CTL.COGNITO.SOCIAL.TESTCREDS.001` — Social login uses test credentials

## NHI4 — Insecure Authentication

**Risk:** Weak machine-to-machine authentication mechanisms —
trust policies that admit too much, MFA gaps, or session
configurations that don't bind to expected callers.

**Stave controls:**

- `CTL.IAM.TRUST.CONFUSEDDEPUTY.001` — Trust policy lacks confused-deputy protection
- `CTL.IAM.TRUST.WILDCARD.001` — Trust policy uses Principal wildcard
- `CTL.IAM.TRUST.SOURCEARN.001` — Trust missing aws:SourceArn condition
- `CTL.IAM.TRUST.EXTERNALID.001` — Cross-account trust missing ExternalId
- `CTL.IAM.TRUST.SESSION.001` — Trust policy permits long sessions
- `CTL.IAM.SESSION.DURATION.001` — IAM session duration too long
- `CTL.IAM.CONSOLE.MFA.001` — Console user without MFA
- `CTL.IAM.MFA.HWKEY.001` — MFA not hardware-backed
- `CTL.IAM.SSO.MFA.001` — SSO permission set lacks MFA enforcement
- `CTL.IAM.POLICY.MFA.001` — Policy doesn't require MFA for sensitive ops
- `CTL.IAM.CROSSCLOUD.MFA.001` — Cross-cloud federation lacks MFA
- `CTL.COGNITO.MFA.001` — Cognito user pool doesn't enforce MFA
- `CTL.COGNITO.RECOVERY.NOMFA.001` — Recovery flow bypasses MFA

## NHI5 — Overprivileged NHI

**Risk:** Service accounts, IAM roles, and service principals
with permissions broader than the workload requires. Detection
covers both shape (wildcards, broad actions) and effect
(privilege escalation paths, admin policy attachment).

**Stave controls:**

IAM policy shape:
- `CTL.IAM.POLICY.ADMIN.001` — Policy attaches AdministratorAccess
- `CTL.IAM.POLICY.RESOURCE.WILDCARD.001` — Resource wildcard with broad actions
- `CTL.IAM.POLICY.SERVICEWILDCARD.001` — Action wildcard at service level
- `CTL.IAM.POLICY.PASSROLE.001` — iam:PassRole without condition
- `CTL.IAM.POLICY.PASSROLE.CONDITION.001` — PassRole condition missing
- `CTL.IAM.POLICY.SHADOW.001` — Shadow admin path (variant 1)
- `CTL.IAM.POLICY.SHADOW.002` — Shadow admin path (variant 2)
- `CTL.IAM.POLICY.INLINE.001` — Inline policy escalation risk (variant 1)
- `CTL.IAM.POLICY.INLINE.002` — Inline policy escalation risk (variant 2)
- `CTL.IAM.POLICY.ESCALATION.001` — Policy contains known escalation pattern
- `CTL.IAM.POLICY.CLOUDSHELL.001` — CloudShell policy unbounded
- `CTL.IAM.POLICY.SOD.001` — Separation-of-duties violation

IAM admin/escalation surface:
- `CTL.IAM.ADMIN.COUNT.001` — Too many admin identities
- `CTL.IAM.SCP.FULLACCESS.001` — SCP allows FullAccess to any service
- `CTL.IAM.NEP.ADMIN.001` — NEP admin reach
- `CTL.IAM.NEP.BOUNDARY.001` — NEP boundary breach
- `CTL.IAM.NEP.ESCALATION.001` — NEP escalation path
- `CTL.IAM.NEP.PHI.001` — NEP reaches PHI scope
- `CTL.IAM.CROSSCLOUD.ADMIN.001` — Cross-cloud admin reach
- `CTL.IAM.ROOT.USAGE.001` — Root identity used for non-root operations
- `CTL.IAM.ROLE.LAMBDA.SCOPING.001` — Lambda role over-scoped
- `CTL.IAM.ZT.PERIMETER.001` — Zero-trust perimeter check
- `CTL.IAM.ZT.SHORTLIVED.001` — Short-lived credential not enforced

IAM privilege-escalation patterns (44 controls under
`controls/iam/escalation/`, each detecting a known
escalation API path):
- `CTL.IAM.ESCALATE.ADDLAYER.001`
- `CTL.IAM.ESCALATE.ADDUSERTOGROUP.001`
- `CTL.IAM.ESCALATE.ASSUMEROLE.001`
- `CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001`
- `CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001`
- `CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001`
- `CTL.IAM.ESCALATE.CHAIN.001`
- `CTL.IAM.ESCALATE.CONFUSED.CFN.UPDATE.001`
- `CTL.IAM.ESCALATE.CONFUSED.LAMBDA.INVOKE.001`
- `CTL.IAM.ESCALATE.CREATEACCESSKEY.001`
- `CTL.IAM.ESCALATE.CREATEACCOUNT.001`
- `CTL.IAM.ESCALATE.CREATEGRANT.001`
- `CTL.IAM.ESCALATE.CREATEINSTANCEPROFILE.001`
- `CTL.IAM.ESCALATE.CREATELOGINPROFILE.001`
- `CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001`
- `CTL.IAM.ESCALATE.DELETEBOUNDARY.001`
- `CTL.IAM.ESCALATE.ECRTOKEN.001`
- `CTL.IAM.ESCALATE.EDITLAMBDA.001`
- `CTL.IAM.ESCALATE.EXECUTECOMMAND.001`
- `CTL.IAM.ESCALATE.GETPASSWORDDATA.001`
- `CTL.IAM.ESCALATE.KMSKEYPOLICY.001`
- `CTL.IAM.ESCALATE.LAMBDAADDPERM.001`
- `CTL.IAM.ESCALATE.MODIFYINSTANCE.001`
- `CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001`
- `CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001`
- `CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001`
- `CTL.IAM.ESCALATE.PASSROLE.CREATEPIPELINE.001`
- `CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001`
- `CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001`
- `CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001`
- `CTL.IAM.ESCALATE.PUTBUCKETPOLICY.001`
- `CTL.IAM.ESCALATE.PUTGROUPPOLICY.001`
- `CTL.IAM.ESCALATE.PUTROLEPOLICY.001`
- `CTL.IAM.ESCALATE.PUTUSERPOLICY.001`
- `CTL.IAM.ESCALATE.RESYNCMFADEVICE.001`
- `CTL.IAM.ESCALATE.SERVICELINKEDROLE.001`
- `CTL.IAM.ESCALATE.SNSADDPERM.001`
- `CTL.IAM.ESCALATE.SQSADDPERM.001`
- `CTL.IAM.ESCALATE.STARTBUILD.001`
- `CTL.IAM.ESCALATE.STARTSESSION.001`
- `CTL.IAM.ESCALATE.UPDATEDEVENDPOINT.001`
- `CTL.IAM.ESCALATE.UPDATEFUNCTIONCONFIG.001`
- `CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001`
- `CTL.IAM.ESCALATE.UPDATETRUST.001`

KMS overprivilege:
- `CTL.KMS.GRANT.BROAD.001` — KMS grant too broad
- `CTL.KMS.GRANT.EXCESSIVE.001` — Too many grants on a single key
- `CTL.KMS.POLICY.ADMIN.BROAD.001` — Key admin policy too broad
- `CTL.KMS.POLICY.DECRYPT.BROAD.001` — Key decrypt policy too broad

Secrets policy:
- `CTL.SECRETS.POLICY.READWRITE.001` — Secret policy permits read+write
- `CTL.SECRETS.POLICY.SPRAWL.001` — Excessive principals on a single secret
- `CTL.SECRETSMANAGER.POLICY.PUBLIC.001` — Secret policy permits public read

S3 access (already annotated):
- `CTL.S3.ACCESS.EXTERNAL.ORG.001` — PHI bucket reachable from outside org

## NHI6 — Insecure Cloud Deployment

**Risk:** Deployment-time misconfiguration of cloud identities —
trust relationships that don't enforce boundary controls, SCPs
missing required guardrails, cross-account/cross-environment
plumbing without isolation.

**Stave controls:**

- `CTL.IAM.TRUST.DUAL.001` — Trust permits both human and machine principals
- `CTL.IAM.TRUST.ORGBOUNDARY.001` — Trust crosses organization boundary unintentionally
- `CTL.IAM.CROSS.ENV.001` — Identity crosses environment boundary
- `CTL.IAM.CROSS.ENV.PATH.001` — Cross-environment access path detected
- `CTL.IAM.SCP.CLOUDTRAIL.001` — SCP missing CloudTrail protection
- `CTL.IAM.SCP.CONFIG.001` — SCP missing AWS Config protection
- `CTL.IAM.SCP.GUARDDUTY.001` — SCP missing GuardDuty protection
- `CTL.IAM.SCP.IAM.001` — SCP missing IAM-mutation protection
- `CTL.IAM.SCP.LEAVEORG.001` — SCP missing leave-org protection
- `CTL.IAM.SCP.ROOT.001` — SCP missing root-action protection
- `CTL.KMS.POLICY.CROSSACCOUNT.001` — Cross-account key policy unsafe
- `CTL.KMS.CROSSACCOUNT.BLASTRADIUS.001` — Cross-account grant blast radius too high
- `CTL.SECRETS.CROSSACCOUNT.BLASTRADIUS.001` — Cross-account secret blast radius
- `CTL.SECRETS.CROSSACCOUNT.NOKMS.001` — Cross-account secret without CMK

## NHI7 — Long-Lived Secrets

**Risk:** API keys, certificates, and credentials that exist
indefinitely without rotation. Includes IAM access keys, KMS
keys, certificates, and secret-manager rotation gaps.

**Stave controls:**

IAM credential rotation:
- `CTL.IAM.CRED.EXPIRY.001` — Access key has no expiration
- `CTL.IAM.CRED.ROTATION.001` — Access key not rotated within window
- `CTL.IAM.CRED.SINGLEKEY.001` — Single key prevents rotation pattern
- `CTL.IAM.PASSWORD.ROTATION.001` — Password rotation policy missing

KMS rotation:
- `CTL.KMS.ROTATION.001` — KMS automatic rotation disabled
- `CTL.KMS.LIFECYCLE.ROTATION.PERIOD.001` — KMS rotation period too long
- `CTL.KMS.ALARM.ROTATION.FAILURE.001` — KMS rotation failure not alerted
- `CTL.KMS.IMPORTED.EXPIRY.001` — Imported KMS key material expired

Secrets Manager rotation:
- `CTL.SECRETS.ROTATION.001` — Secret has no rotation lambda
- `CTL.SECRETS.ROTATION.NEVER.001` — Secret never rotated
- `CTL.SECRETS.ROTATION.STALE.001` — Last rotation outside SLA
- `CTL.SECRETS.ROTATION.INTERVAL.LONG.001` — Rotation interval too long
- `CTL.SECRETS.ROTATION.SINGLEUSER.PROD.001` — Single-user rotation in prod
- `CTL.SECRETS.ALARM.ROTATION.FAILURE.001` — Rotation failure not alerted
- `CTL.SECRETS.ALARM.ROTATION.APPROACHING.001` — Rotation deadline approaching

Cert expiry (long-lived TLS material):
- `CTL.ACM.CERT.EXPIRY.001` — ACM certificate near expiry
- `CTL.CLOUDFRONT.VIEWER.CERT.EXPIRY.WARN.001` — CloudFront viewer cert near expiry
- `CTL.ELB.CERT.EXPIRY.WARN.001` — ELB cert near expiry
- `CTL.APIGATEWAY.DOMAIN.CERT.EXPIRY.WARN.001` — API Gateway cert near expiry
- `CTL.APIGATEWAY.NETWORK.CLIENTCERT.EXPIRY.001` — Client cert near expiry
- `CTL.OPENSEARCH.CUSTOM.CERT.EXPIRY.001` — OpenSearch cert near expiry
- `CTL.COGNITO.DOMAIN.CERTEXPIRY.001` — Cognito domain cert expired
- `CTL.COGNITO.TEMPPASSWORD.001` — Temporary password validity too long

Azure / GCP / AD / EKS rotation:
- `CTL.AZURE.IDENTITY.SP.EXPIRY.001` — Azure service principal credential expiring
- `CTL.AZURE.KEYVAULT.KEY.EXPIRY.001` — Key Vault key near expiry
- `CTL.AZURE.KEYVAULT.SECRET.EXPIRY.001` — Key Vault secret near expiry
- `CTL.AZURE.KEYVAULT.ROTATION.001` — Key Vault rotation policy missing
- `CTL.AZURE.STORAGE.KEYROTATION.001` — Storage account key rotation missing
- `CTL.GCP.IAM.APIKEY.ROTATION.001` — GCP API key not rotated
- `CTL.GCP.IAM.SA.ROTATION.001` — GCP service-account key not rotated
- `CTL.GCP.KMS.ROTATION.001` — GCP KMS key rotation missing
- `CTL.AD.ACCOUNT.NOEXPIRY.001` — AD account password never expires
- `CTL.AD.KRBTGT.ROTATION.001` — krbtgt password rotation overdue
- `CTL.AD.PASS.MAXAGE.001` — AD password max age too long
- `CTL.EKS.SECRETS.ROTATION.001` — EKS secrets-encryption key rotation missing
- `CTL.STEPFUNCTIONS.ENCRYPT.KMS.NOROTATION.001` — Step Functions KMS key rotation missing

## NHI8 — Insufficient Logging and Monitoring

**Risk:** NHI activities (role assumption, key creation, MFA
events, policy changes) need an audit trail and active
monitoring. Annotated controls focus on identity-event-shaped
logging and alarm gaps, not generic resource logging.

**Stave controls:**

CloudWatch identity-event monitors:
- `CTL.CLOUDWATCH.MONITOR.IAMPOLICY.001` — IAM policy changes not monitored
- `CTL.CLOUDWATCH.MONITOR.NOMFA.001` — Sign-in without MFA not monitored
- `CTL.CLOUDWATCH.MONITOR.PASSROLE.001` — iam:PassRole calls not monitored
- `CTL.CLOUDWATCH.MONITOR.ACCESSKEY.001` — Access key creation not monitored
- `CTL.CLOUDWATCH.MONITOR.ROOT.001` — Root usage not monitored
- `CTL.CLOUDWATCH.MONITOR.TRUST.001` — Trust policy changes not monitored
- `CTL.CLOUDWATCH.MONITOR.MFADEVICE.001` — MFA device changes not monitored
- `CTL.CLOUDWATCH.MONITOR.AUTHFAIL.001` — Auth failures not monitored
- `CTL.CLOUDWATCH.MONITOR.UNAUTH.001` — Unauthorized API calls not monitored
- `CTL.CLOUDWATCH.MONITOR.STS.ANOMALOUS.001` — Anomalous STS use not monitored
- `CTL.CLOUDWATCH.MONITOR.IMDS.001` — IMDS abuse pattern not monitored
- `CTL.CLOUDWATCH.MONITOR.ESCALATION.001` — Privilege-escalation API not monitored
- `CTL.CLOUDWATCH.MONITOR.ASSUMEROLE.001` — STS:AssumeRole bursts not monitored
- `CTL.CLOUDWATCH.MONITOR.BOUNDARY.001` — Boundary changes not monitored
- `CTL.CLOUDWATCH.MONITOR.CROSSACCOUNT.001` — Cross-account API not monitored
- `CTL.CLOUDWATCH.MONITOR.CMK.001` — CMK changes not monitored

CloudTrail integrity (audit-trail tampering by IAM):
- `CTL.CLOUDTRAIL.ACCESS.STOPLOGGING.IAM.001` — IAM role can disable CloudTrail logging

## NHI9 — Lack of Secrets Management

**Risk:** Secrets handled outside a secrets-management
service — sprawled across config, scattered grants, broken
rotation infrastructure. Distinct from NHI7 (rotation gaps on
managed secrets) and NHI2 (secrets in surfaces): NHI9 is
absence of the *infrastructure* itself.

**Stave controls:**

- `CTL.SECRETSMANAGER.ACCESS.001` — Secrets-manager access policy missing
- `CTL.SECRETS.POLICY.CROSSACCOUNT.001` — Cross-account secret policy unbounded
- `CTL.SECRETS.POLICY.SPRAWL.001` — Same secret referenced by sprawling principals
- `CTL.SECRETS.CROSSACCOUNT.VALUECOPIED.001` — Secret value duplicated across accounts
- `CTL.LAMBDA.SECRETS.NOTMANAGED.001` — Lambda secret not managed (overlaps NHI2)
- `CTL.LAMBDA.SECRETS.SSM.INSECURE.001` — Lambda uses plain SSM param, not SecureString
- `CTL.KMS.POLICY.GRANTWITHGRANT.001` — Key policy permits GrantWithGrant transfer
- `CTL.KMS.POLICY.NOCONTEXT.001` — Key policy lacks encryption-context binding
- `CTL.KMS.POLICY.NOVIASERVICE.001` — Key policy missing aws:ViaService

## NHI10 — Human Use of NHI

**Risk:** Humans signing in as a service account, sharing
service-account credentials, or using break-glass identities
in routine operations.

**Stave controls (limited coverage):**

- `CTL.IAM.ROOT.USAGE.001` — Root identity used for non-root operations
- `CTL.IAM.CRED.SINGLEKEY.001` — Single key for both human and machine use
- `CTL.IAM.SESSION.SOURCE.001` — Cross-source session indicates handoff

**Why coverage is LOW:** Stave can detect "this identity was
used" but cannot reliably distinguish "by a human" vs
"by automation" from observation data alone — the signal
typically requires session-level behavioral analytics
(unusual hours, unusual source IPs, paired logins) which
exceed Stave's static-analysis scope.

## Gaps and Future Work

| Risk    | Gap                                                          | Suggested control |
|---------|--------------------------------------------------------------|-------------------|
| NHI10   | No control flags an IAM user with both console password and active access keys (mixed human/machine use) | `CTL.IAM.IDENTITY.MIXED.MODE.001` |
| NHI10   | No control flags break-glass roles assumed during business hours | `CTL.IAM.ROLE.BREAKGLASS.HOURS.001` |
| NHI8    | No control flags Lambda execution role lacking CloudTrail Lambda data events | `CTL.LAMBDA.AUDIT.DATAEVENTS.001` |
| NHI2    | No control flags secrets in EKS pod env vars (vs current Lambda focus) | `CTL.EKS.POD.ENV.SECRETS.001` |
| NHI3    | No control flags GitHub Actions OIDC trust without `repository_owner` claim | `CTL.IAM.TRUST.GHA.OWNER.001` |

These gaps reflect either observation-data limits (NHI10 mostly)
or domain coverage that hasn't reached the relevant resource
type yet. They are not blockers for the current coverage claim.

## Updating this document

When adding controls that detect NHI risks:

1. Add `owasp_nhi: "NHIx"` (or comma-separated list) to the
   control's `compliance:` block in YAML.
2. List the control in the relevant section above.
3. Re-run `make sync-controls` and `make readme` so embedded
   metadata and downstream docs stay in sync.

The annotation is the source of truth — `grep -r 'owasp_nhi'
controls/` enumerates every annotated control. This document
is a curated narrative on top of those annotations.

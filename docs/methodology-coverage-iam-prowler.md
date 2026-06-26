# Prowler IAM Coverage

> **Generated file** — do not edit directly. This document is
> regenerated from the embedded control catalog and the inventory at
> `data/alternatives/prowler-iam.yaml` by `go run ./internal/tools/genmethodologycoverage`.

Cross-reference of Prowler's 47 IAM checks against Stave's IAM control catalog.

## Summary

- **Prowler IAM checks surveyed:** 47
- **COVERED:** 39
- **PARTIAL:** 5
- **NOT COVERED:** 3

## Coverage table

| # | Alternative check | Stave status | Stave control(s) | Notes |
|---|---|:---:|---|---|
| 1 | `iam_administrator_access_with_mfa` | COVERED | `CTL.IAM.CONSOLE.MFA.001`, `CTL.IAM.MFA.HWKEY.001` | Stave requires hardware MFA on privileged accounts; Prowler requires any MFA. Stave is stricter on MFA factor. |
| 2 | `iam_avoid_root_usage` | COVERED | `CTL.IAM.ROOT.RECUR.001`, `CTL.IAM.ROOT.USAGE.001` | Both check root-account activity signals. |
| 3 | `iam_aws_attached_policy_no_administrative_privileges` | COVERED | `CTL.IAM.POLICY.ADMIN.001` | Fires on identity.policies.has_admin_access = true for any principal attachment, including AWS-managed. |
| 4 | `iam_check_saml_providers_sts` | PARTIAL | `CTL.IAM.FEDERATION.001` | Stave encourages federation but doesn't inventory SAML provider presence. |
| 5 | `iam_customer_attached_policy_no_administrative_privileges` | COVERED | `CTL.IAM.POLICY.ADMIN.001` | Same field as AWS-managed; has_admin_access is agnostic to policy source. |
| 6 | `iam_customer_unattached_policy_no_administrative_privileges` | PARTIAL | `CTL.IAM.POLICY.ADMIN.001` | Stave's signal is per-principal-attached; unattached admin policies (inventory hygiene) not currently surfaced. |
| 7 | `iam_group_administrator_access_policy` | COVERED | `CTL.IAM.POLICY.ADMIN.001`, `CTL.IAM.POLICY.ADMIN.002` | Catches admin access regardless of whether attached directly or via group membership. |
| 8 | `iam_inline_policy_allows_privilege_escalation` | COVERED | `CTL.IAM.ESCALATE.ADDLAYER.001`, `CTL.IAM.ESCALATE.ADDUSERTOGROUP.001`, `CTL.IAM.ESCALATE.ASSUMEROLE.001`, `CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001`, `CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001`, `CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001`, `CTL.IAM.ESCALATE.CHAIN.001`, `CTL.IAM.ESCALATE.CREATEACCESSKEY.001`, `CTL.IAM.ESCALATE.CREATEACCOUNT.001`, `CTL.IAM.ESCALATE.CREATEGRANT.001`, `CTL.IAM.ESCALATE.CREATEINSTANCEPROFILE.001`, `CTL.IAM.ESCALATE.CREATELOGINPROFILE.001`, `CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001`, `CTL.IAM.ESCALATE.DELETEBOUNDARY.001`, `CTL.IAM.ESCALATE.ECRTOKEN.001`, `CTL.IAM.ESCALATE.EDITLAMBDA.001`, `CTL.IAM.ESCALATE.EXECUTECOMMAND.001`, `CTL.IAM.ESCALATE.GETPASSWORDDATA.001`, `CTL.IAM.ESCALATE.KMSKEYPOLICY.001`, `CTL.IAM.ESCALATE.LAMBDAADDPERM.001`, `CTL.IAM.ESCALATE.MODIFYINSTANCE.001`, `CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEENDPOINT.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATENOTEBOOK.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEPIPELINE.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEPROCESSINGJOB.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATETRAININGJOB.001`, `CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001`, `CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001`, `CTL.IAM.ESCALATE.PUTBUCKETPOLICY.001`, `CTL.IAM.ESCALATE.PUTGROUPPOLICY.001`, `CTL.IAM.ESCALATE.PUTROLEPOLICY.001`, `CTL.IAM.ESCALATE.PUTUSERPOLICY.001`, `CTL.IAM.ESCALATE.RESYNCMFADEVICE.001`, `CTL.IAM.ESCALATE.SAGEMAKER.PRESIGNEDURL.001`, `CTL.IAM.ESCALATE.SENDSSHPUBLICKEY.001`, `CTL.IAM.ESCALATE.SERVICELINKEDROLE.001`, `CTL.IAM.ESCALATE.SNSADDPERM.001`, `CTL.IAM.ESCALATE.SQSADDPERM.001`, `CTL.IAM.ESCALATE.STARTBUILD.001`, `CTL.IAM.ESCALATE.STARTSESSION.001`, `CTL.IAM.ESCALATE.UPDATEDEVENDPOINT.001`, `CTL.IAM.ESCALATE.UPDATEFUNCTIONCONFIG.001`, `CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001`, `CTL.IAM.ESCALATE.UPDATETRUST.001`, `CTL.IAM.NEP.ESCALATION.001`, `CTL.IAM.POLICY.ESCALATION.001` | One of 42 per-technique controls covering the aggregated Prowler check. |
| 9 | `iam_inline_policy_no_administrative_privileges` | COVERED | `CTL.IAM.POLICY.ADMIN.001`, `CTL.IAM.POLICY.INLINE.001`, `CTL.IAM.POLICY.INLINE.003` | POLICY.ADMIN catches *:*; POLICY.INLINE enforces no-inline-on-users as structural hygiene. |
| 10 | `iam_inline_policy_no_full_access_to_cloudtrail` | COVERED | `CTL.IAM.POLICY.SERVICEWILDCARD.001` | cloudtrail is in the default denied_service_wildcards list. |
| 11 | `iam_inline_policy_no_full_access_to_kms` | COVERED | `CTL.IAM.POLICY.SERVICEWILDCARD.001` | kms is in the default denied_service_wildcards list. |
| 12 | `iam_inline_policy_no_wildcard_marketplace_subscribe` | COVERED | `CTL.IAM.POLICY.SERVICEWILDCARD.001` | aws-marketplace is in the default denied_service_wildcards list. |
| 13 | `iam_no_custom_policy_permissive_role_assumption` | COVERED | `CTL.IAM.POLICY.ASSUMEROLE.001` | Both require sts:AssumeRole to be scoped to specific role ARNs. |
| 14 | `iam_no_expired_server_certificates_stored` | COVERED | `CTL.IAM.CERT.EXPIRED.001` | Both check IAM server certificate expiry. |
| 15 | `iam_no_root_access_key` | COVERED | `CTL.IAM.ROOT.ACCESSKEY.001` | Both check identity.root.has_access_keys. |
| 16 | `iam_password_policy_expires_passwords_within_90_days_or_less` | COVERED | `CTL.IAM.PASSWORD.EXPIRATION.001`, `CTL.IAM.PASSWORD.ROTATION.001` | Prowler checks the policy-level expiration setting. CTL.IAM.PASSWORD.ROTATION.001 covers per-user stale passwords; this control covers the account-level policy enforcement. |
| 17 | `iam_password_policy_lowercase` | COVERED | `CTL.IAM.PASSWORD.COMPLEXITY.001` | Stave's complexity control checks all four character classes in one; Prowler splits them. |
| 18 | `iam_password_policy_minimum_length_14` | COVERED | `CTL.IAM.PASSWORD.LENGTH.001` | Both enforce minimum 14. |
| 19 | `iam_password_policy_number` | COVERED | `CTL.IAM.PASSWORD.COMPLEXITY.001` | Same complexity umbrella covers numeric class. |
| 20 | `iam_password_policy_reuse_24` | COVERED | `CTL.IAM.PASSWORD.REUSE.001` | Both enforce reuse prevention of last 24. |
| 21 | `iam_password_policy_symbol` | COVERED | `CTL.IAM.PASSWORD.COMPLEXITY.001` | Same complexity umbrella covers symbol class. |
| 22 | `iam_password_policy_uppercase` | COVERED | `CTL.IAM.PASSWORD.COMPLEXITY.001` | Same complexity umbrella covers uppercase class. |
| 23 | `iam_policy_allows_privilege_escalation` | COVERED | `CTL.IAM.ESCALATE.ADDLAYER.001`, `CTL.IAM.ESCALATE.ADDUSERTOGROUP.001`, `CTL.IAM.ESCALATE.ASSUMEROLE.001`, `CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001`, `CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001`, `CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001`, `CTL.IAM.ESCALATE.CHAIN.001`, `CTL.IAM.ESCALATE.CREATEACCESSKEY.001`, `CTL.IAM.ESCALATE.CREATEACCOUNT.001`, `CTL.IAM.ESCALATE.CREATEGRANT.001`, `CTL.IAM.ESCALATE.CREATEINSTANCEPROFILE.001`, `CTL.IAM.ESCALATE.CREATELOGINPROFILE.001`, `CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001`, `CTL.IAM.ESCALATE.DELETEBOUNDARY.001`, `CTL.IAM.ESCALATE.ECRTOKEN.001`, `CTL.IAM.ESCALATE.EDITLAMBDA.001`, `CTL.IAM.ESCALATE.EXECUTECOMMAND.001`, `CTL.IAM.ESCALATE.GETPASSWORDDATA.001`, `CTL.IAM.ESCALATE.KMSKEYPOLICY.001`, `CTL.IAM.ESCALATE.LAMBDAADDPERM.001`, `CTL.IAM.ESCALATE.MODIFYINSTANCE.001`, `CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEENDPOINT.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEJOB.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATENOTEBOOK.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEPIPELINE.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATEPROCESSINGJOB.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001`, `CTL.IAM.ESCALATE.PASSROLE.CREATETRAININGJOB.001`, `CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001`, `CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001`, `CTL.IAM.ESCALATE.PUTBUCKETPOLICY.001`, `CTL.IAM.ESCALATE.PUTGROUPPOLICY.001`, `CTL.IAM.ESCALATE.PUTROLEPOLICY.001`, `CTL.IAM.ESCALATE.PUTUSERPOLICY.001`, `CTL.IAM.ESCALATE.RESYNCMFADEVICE.001`, `CTL.IAM.ESCALATE.SAGEMAKER.PRESIGNEDURL.001`, `CTL.IAM.ESCALATE.SENDSSHPUBLICKEY.001`, `CTL.IAM.ESCALATE.SERVICELINKEDROLE.001`, `CTL.IAM.ESCALATE.SNSADDPERM.001`, `CTL.IAM.ESCALATE.SQSADDPERM.001`, `CTL.IAM.ESCALATE.STARTBUILD.001`, `CTL.IAM.ESCALATE.STARTSESSION.001`, `CTL.IAM.ESCALATE.UPDATEDEVENDPOINT.001`, `CTL.IAM.ESCALATE.UPDATEFUNCTIONCONFIG.001`, `CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001`, `CTL.IAM.ESCALATE.UPDATETRUST.001`, `CTL.IAM.NEP.ESCALATION.001`, `CTL.IAM.POLICY.ESCALATION.001` | One of 42 per-technique controls covering the aggregated Prowler check. |
| 24 | `iam_policy_attached_only_to_group_or_roles` | COVERED | `CTL.IAM.POLICY.DIRECT.001`, `CTL.IAM.POLICY.INLINE.001` | Stave splits 'no direct managed attach' from 'no inline policies' into two controls; union matches. |
| 25 | `iam_policy_cloudshell_admin_not_attached` | COVERED | `CTL.IAM.POLICY.CLOUDSHELL.001` | Both check the specific AWSCloudShellFullAccess attachment. |
| 26 | `iam_policy_no_full_access_to_cloudtrail` | COVERED | `CTL.IAM.POLICY.SERVICEWILDCARD.001` | Customer-managed variant; same denied-list mechanism. |
| 27 | `iam_policy_no_full_access_to_kms` | COVERED | `CTL.IAM.POLICY.SERVICEWILDCARD.001` | Customer-managed variant for kms. |
| 28 | `iam_policy_no_wildcard_marketplace_subscribe` | COVERED | `CTL.IAM.POLICY.SERVICEWILDCARD.001` | Customer-managed variant for aws-marketplace. |
| 29 | `iam_role_access_not_stale_to_bedrock` | PARTIAL | `CTL.IAM.ROLE.PERMISSIONDRIFT.001` | Generic unused-permissions drift catches the spirit; Bedrock-specific freshness is not explicit. |
| 30 | `iam_role_administratoraccess_policy` | COVERED | `CTL.IAM.POLICY.ADMIN.001` | has_admin_access is principal-kind-agnostic; same control covers user and role cases. |
| 31 | `iam_role_cross_account_readonlyaccess_policy` | NOT COVERED | — |  |
| 32 | `iam_role_cross_service_confused_deputy_prevention` | COVERED | `CTL.IAM.TRUST.CONFUSEDDEPUTY.001`, `CTL.IAM.TRUST.SOURCEARN.001` | Stave splits third-party trust (needs ExternalId) from AWS-service-principal trust (needs SourceArn/SourceAccount); union covers Prowler. |
| 33 | `iam_root_credentials_management_enabled` | NOT COVERED | — |  |
| 34 | `iam_root_hardware_mfa_enabled` | COVERED | `CTL.IAM.ROOT.HWMFA.001` | Both check root account hardware MFA. |
| 35 | `iam_root_mfa_enabled` | COVERED | `CTL.IAM.ROOT.MFA.001` | Both check root MFA presence. |
| 36 | `iam_rotate_access_key_90_days` | COVERED | `CTL.IAM.CRED.ROTATION.001` | Both enforce 90-day rotation. |
| 37 | `iam_securityaudit_role_created` | NOT COVERED | — |  |
| 38 | `iam_support_role_created` | COVERED | `CTL.IAM.SUPPORT.001` | Both check for an existing role with the AWSSupportAccess policy. |
| 39 | `iam_user_access_not_stale_to_bedrock` | PARTIAL | `CTL.IAM.CRED.UNUSED.001`, `CTL.IAM.ROLE.PERMISSIONDRIFT.001`, `CTL.IAM.USER.PERMISSIONDRIFT.001` | Generic staleness; no Bedrock-specific freshness tracking. |
| 40 | `iam_user_accesskey_unused` | COVERED | `CTL.IAM.CRED.UNUSED.001`, `CTL.IAM.CRED.UNUSED45.001` | Stave has two thresholds; Prowler's 45-day matches UNUSED45.001 precisely. |
| 41 | `iam_user_administrator_access_policy` | COVERED | `CTL.IAM.ADMIN.COUNT.001`, `CTL.IAM.POLICY.ADMIN.001` | Per-user admin attach plus account-wide admin-count threshold. |
| 42 | `iam_user_console_access_unused` | COVERED | `CTL.IAM.ACCOUNT.INACTIVE.001`, `CTL.IAM.CRED.UNUSED.001` | Stave splits credential-unused from account-inactive; union matches. |
| 43 | `iam_user_hardware_mfa_enabled` | PARTIAL | `CTL.IAM.MFA.HWKEY.001` | Stave requires hardware MFA for privileged users; Prowler requires it for all users. Posture-policy difference. |
| 44 | `iam_user_mfa_enabled_console_access` | COVERED | `CTL.IAM.CONSOLE.MFA.001` | Both fire when a user has console access without MFA. |
| 45 | `iam_user_no_setup_initial_access_key` | COVERED | `CTL.IAM.CRED.SETUPKEY.001` | Both check access keys that exist from user-setup time. |
| 46 | `iam_user_two_active_access_key` | COVERED | `CTL.IAM.CRED.SINGLEKEY.001` | Both enforce at-most-one active access key per user. |
| 47 | `iam_user_with_temporary_credentials` | COVERED | `CTL.IAM.ZT.SHORTLIVED.001` | Stave's short-lived credentials posture; Prowler's IAM/STS exception is acceptable-use nuance. |

## Source

- Inventory: `data/alternatives/prowler-iam.yaml`
- Coverage annotations: `alternatives:` blocks on individual control YAMLs under `controls/`

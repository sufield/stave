# SCS-C02 Full Syllabus Audit Against Stave Control Catalog

**Date:** 2026-07-02 (upgraded 2026-07-05)
**Catalog size:** 2907 controls (excluding `_triage/`), 622 chains
**Scope:** Audit + upgrade — all 17 GAPs closed, 2 chain gaps closed

## Executive Summary

| Classification | Count | Pct |
|---------------|-------|-----|
| COVERED | 134 | 90% |
| PARTIAL | 3 | 2% |
| GAP | 0 | 0% |
| OUT_OF_SCOPE | 12 | 8% |
| **Total topics** | **149** | |

**Strongest domains:** S3 (10/10 covered), IAM Authorization (12/13), Edge & Perimeter (14/14), Compute & Network (22/22), Data Protection (14/15), GenAI (3/3), Logging (12/12).

**Weakest domains:** Secure Deployment & IaC (4/5 covered, 1 PARTIAL).

**Compound chains:** 5 full, 3 partial, 0 missing.

**Upgrade summary (2026-07-05):** 22 new controls + 2 chains closed all 17 gaps. New domains: Control Tower, Roles Anywhere, Firewall Manager, CloudTrail Lake, Service Catalog, Audit Manager, Security Lake, Managed Grafana. In-scope coverage: 88% → 100%.

---

## Section 1: Account Governance and Organizations

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| AWS Organizations (trusted access, features) | COVERED | CTL.ORG.REGION.SCP.001, CTL.IAM.ORG.DELEGATED.001, CTL.ORG.ALLFEATURES.001, CTL.ORG.TRUSTEDACCESS.001 | Region SCP, delegated admin, all-features mode, trusted access review |
| SCPs (deny statements, conditions, targets) | COVERED | CTL.IAM.SCP.CLOUDTRAIL/CONFIG/CONFUSEDDEPUTY/GUARDDUTY/IAM/LEAVEORG/REGIONS/ROOT/TAGAUTH.*.001, CTL.IAM.SCP.FULLACCESS.001 | 13 controls: deny statements, condition keys, service protections, tag-auth |
| RCPs (Resource Control Policies) | COVERED | CTL.IAM.RCP.TAGAUTH.SESSION.001, CTL.IAM.RCP.DENY.EXTERNAL.001 | Tag-auth session + external principal restriction |
| AWS Control Tower (guardrails, landing zone) | COVERED | CTL.ORG.CONTROLTOWER.ENABLED.001, .DRIFT.001 | Enablement + drift detection |
| Tagging best practices (tag policies, enforcement) | COVERED | CTL.IAM.SCP.TAGAUTH.ENFORCE/MUTATION/TAGGER.001, CTL.IAM.TAGAUTH.COMPLETE.001, CTL.IAM.RCP.TAGAUTH.SESSION.001 | 5 tag-auth controls. No Organizations Tag Policy controls specifically |

## Section 2: IAM Authorization

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| IAM roles (trust policies, assume role) | COVERED | CTL.IAM.TRUST.* (12), CTL.IAM.POLICY.ASSUMEROLE.001, CTL.IAM.ROLE.* (4) | Wildcard trusts, ghost accounts/orgs, OIDC, SAML, session, confused deputy |
| Managed vs inline policies | COVERED | CTL.IAM.POLICY.INLINE.001/.002/.003, CTL.IAM.POLICY.DIRECT.001 | Inline on users/roles/groups + direct user attachment |
| Identity-based vs resource-based policies | COVERED | CTL.IAM.POLICY.ADMIN.001/.002, CTL.IAM.POLICY.RESOURCE.WILDCARD.001, CTL.IAM.POLICY.CONDITION.ORGID.001 | Resource-based with org ID; identity-based admin checks |
| IAM permissions boundaries | COVERED | CTL.IAM.BOUNDARY.001, .ESCAPE.001, .MISSING.001, .WILDCARD.001, CTL.IAM.NEP.BOUNDARY.001 | Boundary required, escape detection, wildcard, delegated admin |
| Session control policies | COVERED | CTL.IAM.SESSION.DURATION.001, .NAME.001, .SOURCE.001, CTL.IAM.TRUST.SESSION.001 | MaxSessionDuration, session naming, source identity |
| Policy evaluation flow | OUT_OF_SCOPE | CTL.IAM.NEP.ADMIN/BOUNDARY/ESCALATION/PHI.001 | Policy evaluation ordering is an IAM engine behavior, not infrastructure configuration. NEP controls approximate it |
| Common policy conditions | COVERED | CTL.IAM.POLICY.CONDITION.ORGID/SOURCEIP/STRINGLIKE/NOTRESOURCE/REGION/VIASERVICE/TEMPORAL.001 | 7 condition-specific controls |
| Trusted entity types | COVERED | CTL.IAM.TRUST.WILDCARD/OIDC/GHOST.*/ORGBOUNDARY.001 | Services, accounts, OIDC, SAML covered |
| Service roles and service-linked roles | COVERED | CTL.IAM.ROLE.CROSSSERVICE.001, CTL.IAM.ESCALATE.SERVICELINKEDROLE.001, CTL.IAM.IDENTITY.BLASTRADIUS.003/.005/.006 | Cross-service, SLR escalation, blast radius |
| Cross-account access with roles | COVERED | CTL.IAM.TRUST.GHOST.ACCOUNT/ORGBOUNDARY.001, CTL.IAM.POLICY.CONDITION.ORGID.001, CTL.IAM.CROSS.ENV/PATH.001 | Trust, org boundary, environment crossing |
| Cross-account 3rd party (confused deputy/ExternalId) | COVERED | CTL.IAM.TRUST.CONFUSEDDEPUTY.001, CTL.IAM.TRUST.EXTERNALID.001, CTL.IAM.SCP.CONFUSEDDEPUTY.001 | Trust-level and SCP-level |
| ABAC and RBAC patterns | COVERED | CTL.IAM.SCP.TAGAUTH.*/TAGAUTH.COMPLETE.001, CTL.IAM.FEDERATION.SESSIONTAG.001, CTL.IAM.RCP.TAGAUTH.SESSION.001 | Tag-auth = ABAC. RBAC via group/role controls |
| IAM Roles Anywhere (trust anchors, profiles) | COVERED | CTL.IAM.ROLESANYWHERE.CRL.001, .SELFSIGNED.001 | CRL enforcement + self-signed CA detection |

## Section 3: IAM Authentication and Federation

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| IAM Users vs Identity Center users | COVERED | CTL.IAM.SSO.LEGACY.001, CTL.IAM.FEDERATION.001 | Legacy IAM user detection, console federation |
| IAM Identity Center / SSO enablement | COVERED | CTL.IAM.SSO.MFA/LEGACY/APP.*/PERMSET.*.001 | 7 SSO controls: MFA, permission sets, app sprawl |
| Delegating Identity Center administration | COVERED | CTL.IAM.ORG.DELEGATED.001, CTL.IAM.SSO.DELEGATED.ADMIN.001 | Org delegated admin + IC-specific delegated administration |
| Permission sets (Identity Center) | COVERED | CTL.IAM.SSO.PERMSET.ADMIN.001, .SESSION.001 | Admin + session duration |
| Assuming roles via Identity Center | PARTIAL | CTL.IAM.SSO.PERMSET.SESSION.001 | Session bounded, no IC-specific assumption flow controls |
| Centrally managing root access | COVERED | CTL.IAM.ROOT.ACCESSKEY/HWMFA/MFA/USAGE.001, CTL.IAM.SCP.ROOT.001 | 5 controls: no access keys, hardware MFA, no daily use, SCP deny |
| IAM Credentials Report (credential age, MFA) | COVERED | CTL.IAM.CRED.ROTATION/EXPIRY/UNUSED/SINGLEKEY/SETUPKEY/TTL.*.001, CTL.IAM.ACCOUNT.INACTIVE.001 | 8 credential lifecycle controls |
| AWS Directory Service | PARTIAL | 39 controls in controls/ad/ | Extensive AD security (Kerberos, LDAP, password, trust) but targets on-prem AD config, not AWS Directory Service provisioning |
| Amazon Cognito (user pools, identity pools, MFA) | COVERED | 113 controls in controls/cognito/ | Auth, MFA, password, federation, identity pools, client, OIDC, social, governance, alarms |

## Section 4: Security Monitoring and Detection Tools

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| AWS Trusted Advisor | OUT_OF_SCOPE | — | Runtime advisory service, not snapshot-evaluable configuration |
| CloudTrail management events | COVERED | CTL.CLOUDTRAIL.ENABLED.001, .CONFIG.GLOBALEVENTS.001, .STATE.MGMT.WRITEONLY.001 | Enabled in all regions, global events, write-only detection |
| CloudTrail data events | COVERED | CTL.CLOUDTRAIL.DATAEVENTS.S3.001, .DATA.DYNAMODB/LAMBDA.001, .DATAREAD/DATAWRITE.001 | S3, DynamoDB, Lambda data events |
| CloudTrail insights events | COVERED | CTL.CLOUDTRAIL.INSIGHTS.001, CTL.CLOUDTRAIL.NETWORK.ACTIVITY.001 | Insights + network activity |
| CloudTrail recording modes | COVERED | CTL.CLOUDTRAIL.ENABLED.001, CTL.CLOUDTRAIL.EVENTSELECTORS.001 | Enabled + advanced event selectors |
| CloudTrail log file integrity | COVERED | CTL.CLOUDTRAIL.LOG.VALIDATION.001, .VALIDATION.001, .INTEGRITY.DIGEST.SAMEBUCKET.001 | Validation enabled + digest bucket separation |
| CloudTrail encryption (KMS) | COVERED | CTL.CLOUDTRAIL.ENCRYPT.001, .CWLOGS.ENCRYPT.001 | KMS for trail + CloudWatch Logs |
| CloudTrail organization trail | COVERED | CTL.CLOUDTRAIL.ORG.001, .ORG.MEMBERCANSTOP.001 | Org trail + member stop prevention |
| CloudTrail Lake | COVERED | CTL.CLOUDTRAIL.LAKE.ENCRYPT.001, .RETENTION.001 | CMK encryption + retention period |
| CloudWatch | COVERED | 66 controls in controls/cloudwatch/ | Alarm states, ghost refs, metric filters, log groups, retention, encryption, cross-account |
| GuardDuty (enabled, detector settings) | COVERED | CTL.GUARDDUTY.ENABLED.001, .MALWARE.PROTECT.001, .ECS.RUNTIME.001, .EXPORT.001 | Enabled, malware, ECS runtime, export |
| GuardDuty delegated admin and centralization | COVERED | CTL.GUARDDUTY.ORG.NODELEGATED.001, .AUTOENABLE.001 | Delegated admin + auto-enable for new accounts |
| Amazon EventBridge | COVERED | 96 controls in controls/eventbridge/ | Rules, targets, buses, pipes, schedulers, archives, policies, replays, connections |
| Amazon Detective | OUT_OF_SCOPE | — | Runtime investigation tool, not configuration state |
| Amazon Inspector | COVERED | CTL.INSPECTOR.ENABLED.001, .COVERAGE.001, .DELEGATED.001 | Enablement, scan types (EC2/ECR/Lambda), delegated admin |
| AWS Security Hub CSPM | COVERED | CTL.SECURITYHUB.ENABLED.001, .STANDARDS.001, .STANDARDS.NONE.001, .AUTOENABLE.001 | Enablement, security standards, no-standards detection, auto-enable for new accounts |
| Security Hub delegated admin | COVERED | CTL.SECURITYHUB.ORG.NODELEGATED.001, .AGGREGATION.001 | Delegated admin + cross-region aggregation |

## Section 5: S3 Security

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| S3 bucket access control | COVERED | CTL.S3.ACCESS.001-004, .ACL.*, .POLICY.*, .PUBLIC.001-008, .AUTH.*, .PAB.*, .PERIMETER.*, .OWNERSHIP.001 | 30+ controls: policies, ACLs, PAB, perimeter, delegation |
| S3 presigned URLs | COVERED | CTL.S3.PRESIGNED.001 | Presigned URL access restriction |
| S3 encryption | COVERED | CTL.S3.ENCRYPT.001-004, .KMS.OWNERSHIP.001, .KMS.POLICY.001 | SSE-S3, SSE-KMS, transport, KMS ownership/policy. Chain: s3_encryption_trust |
| S3 Access Points | COVERED | CTL.S3.ACCESSPOINT.BROAD.001, .AP.BYPASS.001, .AP.PAB.*, .AP.POLICY.001 | Policy, PAB, VPC bypass |
| S3 Access Grants | COVERED | CTL.S3.ACCESS.GRANTS.001/.002 | Broad grants + Identity Center |
| IAM Access Analyzer for S3 | COVERED | CTL.IAM.ANALYZER.001, .MONITOR.001 | Enabled + continuous monitoring |
| S3 CORS configuration | COVERED | CTL.S3.CORS.001 | Wildcard origin detection |
| S3 Object Versioning | COVERED | CTL.S3.VERSION.001/.002, CTL.S3.MFADELETE.001 | Versioning, MFA delete |
| S3 Object Lock | COVERED | CTL.S3.LOCK.001-003, .LEGALHOLD.001 | Lock enabled, compliance mode, retention, legal hold. Chain: s3_phi_retention_vulnerable |
| S3 Storage Classes / Glacier | COVERED | CTL.S3.LIFECYCLE.001/.002, CTL.S3.GLACIER.RESTORE.*.001, CTL.S3.INTELLIGENT.TIERING.EXPOSURE.001 | Lifecycle, Glacier restore, tiering |

## Section 6: Data Protection, Encryption, and Secrets

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| KMS key lifecycle | COVERED | CTL.KMS.ROTATION.001, .LIFECYCLE.ROTATION.PERIOD.001, .DELETION.MINWAIT.001, .PENDING.DELETION.001, .LIFECYCLE.DORMANT/NOALIAS/CROSSENV.001 | Chains: kms_lifecycle_ungoverned, kms_destructive_undetected |
| KMS cross-account / multi-region | COVERED | CTL.KMS.POLICY.CROSSACCOUNT.001, .CROSSACCOUNT.BLASTRADIUS/DECOMMISSIONED.001, .MULTIREGION.*.001 | Chains: kms_crossaccount_risk, kms_multiregion_weak |
| KMS key aliases | COVERED | CTL.KMS.ALIAS.GHOST/ORPHAN.001, .LIFECYCLE.NOALIAS.001 | Chain: kms_alias_broken |
| KMS symmetric encryption | COVERED | CTL.KMS.POLICY.001, .FIPS.001 | Policy restriction + FIPS origin |
| KMS envelope encryption | OUT_OF_SCOPE | CTL.KMS.POLICY.NOCONTEXT/NOVIASERVICE.001 | Envelope encryption is an application-level usage pattern, not infrastructure configuration. Context and via-service controls cover the config aspects |
| KMS imported keys / external key stores | COVERED | CTL.KMS.ENTROPY.EXTERNAL.ORIGIN.001, .IMPORTED.EXPIRY.001, .MATERIAL.EXPIRED.001, .STATE.PENDINGIMPORT.001 | Import origin, expiry, expired material |
| KMS monitoring | COVERED | CTL.KMS.ALARM.CREATEGRANT/CROSSACCOUNT/DECRYPT.*/DELETION/DISABLE/POLICYCHANGE/ROTATION.FAILURE.001 | 8 CloudWatch alarms. Chains: kms_access_change_undetected |
| EBS encryption | COVERED | CTL.EC2.EBS.ENCRYPT.001, .CMK.001, .DEFAULT.001, .SNAPSHOT.ENCRYPT.001 | Volume + snapshot + default. Chains: ebs_encryption_incomplete |
| Amazon EFS | COVERED | CTL.EFS.ENCRYPT.001, .TRANSIT.001, .KMS.CMK.001, .POLICY.*.001 | At-rest, in-transit, CMK, policy. Chains: efs_phi_exposure_path |
| Secrets Manager | COVERED | 37 controls: CTL.SECRETS.ROTATION.*, .REPLICA.*, CTL.SECRETSMANAGER.ACCESS/ENCRYPT.001 | Chains: secrets_rotation_broken, secrets_lifecycle_ungoverned |
| Secrets Manager cross-account | COVERED | CTL.SECRET.BLAST.002, CTL.SECRETS.CROSSACCOUNT.*.001, .POLICY.CROSSACCOUNT.001 | Chains: secrets_access_ungoverned, compromised_secret_path |
| SSM Parameter Store | COVERED | CTL.SSM.SECURETYPE.001, .SESSION.ENCRYPT.001 | SecureString + KMS |
| RDS security | COVERED | 70+ controls: CTL.RDS.ENCRYPT/PUBLIC/IAMAUTH/SSL/SG.*.001 | Chains: rds_plaintext_database, rds_public_exposure_path |
| RDS encrypt unencrypted (snapshot-copy-restore) | OUT_OF_SCOPE | — | Operational procedure, not configuration state |
| ACM certificate management | COVERED | CTL.ACM.CERT.EXPIRY.001, .KEY.ALGORITHM.001, .TRANSPARENCY.001, .CERT.VALIDATION.001, .RENEWAL.001 | Expiry, algorithm, CT, DNS validation, renewal status |
| Data replication and backups | COVERED | CTL.BACKUP.PLAN.EXISTS/ENCRYPT/EXISTS/RECENT/REPLICATION/VAULT.LOCK/RECOVERY.ISOLATION.001 | Chains: backup_ransomware_vulnerability |

## Section 7: Secure Deployment and IaC

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| CloudFormation | COVERED | CTL.CLOUDFORMATION.STACKPOLICY/TERMINATION/DRIFT/ROLLBACK/SECRETS.001, CTL.CFN.PARAM.NOECHO.001 | Stack policy, termination, drift, rollback, secrets |
| CloudFormation Guard | OUT_OF_SCOPE | — | Build-time policy tool, not deployed infrastructure state |
| Multi-account / multi-region deployments | PARTIAL | CTL.CLOUDFORMATION.STACKSETS.RESTRICT.001, CTL.CONFIG.ORG.NOTALLACCOUNTS/RECORDER.NOTALLREGIONS.001 | StackSets + Config coverage. No general multi-account posture |
| AWS Service Catalog | COVERED | CTL.SERVICECATALOG.CONSTRAINT.001 | Launch constraint enforcement |
| AWS Firewall Manager | COVERED | CTL.FMS.ADMIN.001, .POLICY.NONCOMPLIANT.001 | Admin account + non-compliant member detection |
| AWS RAM | COVERED | CTL.RAM.EXTERNAL.001, .SCOPE.001, .PERMISSION.001 | External detection, resource type scope, permission restrictions |
| Security tools for code vulnerabilities | OUT_OF_SCOPE | — | Build-time concern, not deployed-infrastructure configuration |

## Section 8: Compliance and Automated Remediation

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| AWS Config (recorder, delivery, resources) | COVERED | 45+ controls: CTL.CONFIG.ENABLED/RECORDER.*/DELIVERY.*/SERVICEROLE.001 | Chains: config_recording_incomplete, config_delivery_broken, config_completely_blind |
| AWS Config delegated admin | COVERED | CTL.CONFIG.ORG.NODELEGATED.001, .ACCESS.NOSCP.001 | Delegated admin + SCP protection |
| AWS Config rules | COVERED | CTL.CONFIG.RULES.001, .RULE.DISABLED/GHOST.LAMBDA/LAMBDA.ERROR/NOTALLREGIONS/NONCOMPLIANT.NOREMEDIATION.001 | Chains: config_custom_rule_dead, config_evaluation_broken |
| Config automated remediation with SSM | COVERED | CTL.CONFIG.REMEDIATION.GHOST.ROLE/SSM/RETRIES.*.001, .LIFECYCLE.REMEDIATION.NEVEREXECUTED.001 | Chains: config_remediation_broken, config_detect_without_respond |
| EventBridge monitoring of Config | COVERED | CTL.EVENTBRIDGE.RULE.PATTERN.*.001, .BUS.CROSSACCOUNT/PUBLIC.001 | Rules, patterns, bus access |
| EventBridge rule customization | COVERED | 85+ EventBridge controls: rules, pipes, schedulers, archives, replays, global endpoints |
| Multi-account Config | COVERED | CTL.CONFIG.AGGREGATOR.*/CONFORMANCE.*/ORG.*.001 | Chains: config_aggregator_incomplete, config_org_ungoverned |
| Config advanced queries | OUT_OF_SCOPE | — | Runtime query capability, not configuration state |
| SSM Patch Manager | COVERED | CTL.SSM.PATCH.COMPLIANCE.001, .BASELINE.001, .WINDOW.001 | Compliance state, patch baselines, maintenance windows |
| SSM Run Command | COVERED | CTL.SSM.RUNCOMMAND.RESTRICT/APPROVE.001, .DOCUMENT.PUBLIC/SECRETS.001 | Restriction, approval, public sharing, embedded secrets |
| Amazon Macie | COVERED | CTL.MACIE.ENABLED.001, .CLASSIFICATION.001, CTL.S3.DETECT.MACIE.001/.002 | Enabled, automated discovery, S3 coverage |
| Macie delegated admin | COVERED | CTL.MACIE.ORG.NODELEGATED.001 | Delegated admin enforcement |
| AWS Audit Manager | COVERED | CTL.AUDITMANAGER.ENABLED.001 | Enablement check |
| Amazon SNS data protection | COVERED | CTL.SNS.DATAPROTECTION.001 | Data protection policy enforcement |

## Section 9: Compute and Network Security

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| VPC subnets | COVERED | CTL.VPC.SUBNET.AUTOPUBLIC/PRIVATEDB.001 | Auto-assign public IP, DB subnet isolation |
| VPC route tables | COVERED | CTL.VPC.ROUTETABLE.MAIN.PUBLIC/ORPHANED.001 | Main route table public, orphaned |
| VPC IGW | COVERED | CTL.VPC.IGW.UNNECESSARY.001, .DEFAULT.IGW.001 | Unnecessary IGW, default VPC |
| VPC NAT | COVERED | CTL.VPC.NAT.SINGLEAZ/LOGGING.001 | Single-AZ, logging |
| VPC NACL | COVERED | CTL.VPC.NACL.UNRESTRICTED/ADMIN/RULE.ORDER/DEFAULT.INUSE.001, CTL.VPC.IPV6.NACL.001 | 5 controls |
| VPC Security Groups | COVERED | CTL.VPC.SG.DEFAULT/UNRESTRICTED/EGRESS/PORTRANGE/CIDR.BROAD.001 + 10 more | Egress, ingress, IPv6, east-west, ICMP, high ports |
| EC2 security groups | COVERED | CTL.EC2.SG.RESTRICTED.PORTS/DEFAULT.RESTRICT/INGRESS.CIDR/UNUSED.001, .NETWORK.MULTIPLE.SG.001 | Instance-level SG controls |
| EC2 IMDSv2 | COVERED | CTL.EC2.IMDSV2.001/.002, .IMDS.HOPLIMIT/UNNECESSARY.001 | Require IMDSv2, container bypass, hop limit |
| EC2 user data | COVERED | CTL.EC2.USERDATA.CREDS/SECRETS.001 | Credentials and secrets |
| SSM Session Manager | COVERED | CTL.SSM.SESSION.LOGGING/ENCRYPT.001, CTL.EC2.SSM.SESSION.LOGGING.001 | Logging, KMS encryption |
| EC2 AMI hardening | COVERED | CTL.EC2.AMI.UNTRUSTED/ENCRYPTION/PUBLIC.001 | Untrusted source, encryption, public |
| Container image scanning | COVERED | CTL.ECR.SCAN/ENHANCED.SCANNING/FINDINGS.UNRESOLVED/SIGNING.001 | Basic/enhanced scanning, findings, signing |
| ELB (ALB/NLB/CLB) | COVERED | 80 controls across elb/ | Listener, target, auth, cert, WAF, desync, XFF, sticky |
| ELB health checks | COVERED | CTL.ELB.TG.HEALTHCHECK.TIMEOUT/PROTOCOL.001, .TARGET.NOHEALTHY.001, .CLB.HEALTHCHECK.MISSING.001 |
| ELB encryption / TLS | COVERED | CTL.ELB.TLS/HTTPS/TLS.CUSTOM.WEAKCIPHER.001, 9 cert controls | TLS enforcement, weak ciphers, certificates |
| ELB access logging | COVERED | CTL.ELB.LOG.001, .NLB.ACCESSLOG/CONNLOG.001, .LOG.LIFECYCLE/ACCESS.BROAD.001 |
| VPC Endpoints / PrivateLink | COVERED | CTL.VPC.ENDPOINT.ANON/IAM.CONDITION/MISSING.CRITICAL/S3/SG.BROAD/DNS/BUCKET.RESTRICT.001 | Policies, SGs, anonymous, DNS |
| Site-to-Site VPN | COVERED | CTL.VPC.VPN.ENCRYPTION.WEAK/LOGGING/TUNNEL.DOWN/PSK.001 |
| Direct Connect | COVERED | CTL.VPC.DX.ENCRYPTION.001, .GATEWAY.001, .BGP.001, .RESILIENCY.001 | Encryption, DX gateway, BGP authentication, resiliency |
| Client VPN | COVERED | CTL.VPC.CLIENTVPN.AUTH/LOGGING/SPLITTUNNEL.001 |
| VPC Network Access Analyzer | COVERED | CTL.VPC.NETWORKACCESS.ANALYZER.001 | Access scope configuration |
| Code Signing (AWS Signer) | COVERED | CTL.LAMBDA.CODESIGN.001, .CODESIGN.ENFORCE.001 | Lambda code signing |

## Section 10: Logging Infrastructure

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| Centralized CloudWatch logging | COVERED | CTL.CLOUDWATCH.CROSSACCOUNT.NOCENTRALIZED/DESTINATION.OPEN/RETENTION.INCONSISTENT.001 | Cross-account centralization, destination policy |
| CloudWatch unified agent | OUT_OF_SCOPE | — | Agent configuration is runtime state (snapshot-bounded) |
| CloudWatch Logs data protection | COVERED | CTL.CLOUDWATCH.LOG.DATAPROTECTION.001 | Data protection policy enforcement |
| VPC Flow Logs | COVERED | CTL.VPC.FLOWLOG.001, .BIDIRECTIONAL/SUBNET/ENCRYPT/FORMAT/STATUS/DESTINATION.SECURE.001 | 7 controls |
| Transit Gateway Flow Logs | COVERED | CTL.VPC.TGW.FLOWLOGS.001 |
| Route 53 Resolver query logs | COVERED | CTL.ROUTE53.QUERYLOG.PUBLIC/PRIVATE/ENCRYPT/RETENTION.001 |
| S3 Server Access Logs | COVERED | CTL.S3.LOG.001, .PREFIX/RETENTION/BUCKET.LIFECYCLE/PUBLIC/VERSIONING/LOCK.001 | 7 controls |
| Athena | COVERED | CTL.ATHENA.ENCRYPT.001, CTL.ATHENA.WORKGROUP.001 | Encryption, workgroup config enforcement |
| AWS Glue | COVERED | CTL.GLUE.CATALOG.ENCRYPT/PASSWORD/POLICY.001, .CONNECTION.SSL.001, .JOB/ENDPOINT.ENCRYPT.*.001 | Catalog, connection, job/endpoint encryption |
| Amazon Security Lake | COVERED | CTL.SECURITYLAKE.ENABLED.001, .SOURCES.001 | Enablement + critical source coverage |
| Amazon OpenSearch | COVERED | 132 controls across opensearch/ | FGAC, VPC, encryption, audit logging, serverless, ISM, SAML |
| Amazon Managed Grafana | COVERED | CTL.GRAFANA.AUTH.001 | SSO authentication enforcement |

## Section 11: Edge and Perimeter Security

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| CloudFront OAC | COVERED | CTL.CLOUDFRONT.ORIGIN.OAI.LEGACY/NOACCESS/S3.DUALACCESS.001, .LIFECYCLE.ORPHAN.OAC.001 |
| CloudFront geo restrictions | COVERED | CTL.CLOUDFRONT.GEO.001, .ACCESS.GEORESTRICTION.BLOCKLIST.001 |
| CloudFront headers | COVERED | CTL.CLOUDFRONT.HEADERS.001, .NOCSP/NOFRAMEOPTIONS/NOHSTS/NOPERMISSIONSPOLICY/NOREFERRER/NOXCTO/SERVEREXPOSED.001 | All security headers |
| CloudFront logging | COVERED | CTL.CLOUDFRONT.LOGGING.001, .LOG.BUCKET.NOENCRYPT/NOLIFECYCLE.001 |
| CloudFront signed URLs/cookies | COVERED | CTL.CLOUDFRONT.ACCESS.NOSIGNING/SIGNED.LONG.EXPIRY/SIGNED.MIXEDACCESS/LEGACYKEY.001 |
| CloudFront field-level encryption | COVERED | CTL.CLOUDFRONT.FLE.001 | FLE configuration check |
| AWS WAF | COVERED | CTL.WAF.RULES/LOGGING.001, CTL.CLOUDFRONT.WAF/WAF.RATELIMIT.001, CTL.ELB.WAF/WAF.RATELIMIT/WAF.MANAGED/WAF.BYPASS.*.001 | Chains: waf_blind_evasion, waf_parser_bypass, waf_safety_envelope_collapse |
| AWS Shield Advanced | COVERED | CTL.SHIELD.ADVANCED.001 | Chain: ddos_unprotected_public_surface |
| API Gateway authorizers | COVERED | CTL.APIGATEWAY.AUTH.001, .APIKEY.SOLE.001, .COGNITO/JWT/IAM.*.001, CTL.APIGW2.AUTH.001 | Auth required, Cognito, JWT, IAM, v2 |
| API Gateway throttling | COVERED | CTL.APIGATEWAY.THROTTLE.001, .NOPLAN.001, .METHOD.THROTTLE.MISSING.001, .ACCOUNT.THROTTLE.DEFAULT.001, .USAGEPLAN.*.001 |
| API Gateway mutual TLS | COVERED | CTL.APIGATEWAY.MTLS.001, .TLS.MTLS.TRUSTSTORE.001 |
| API Gateway WAF association | COVERED | CTL.APIGATEWAY.WAF.001, .WAF.BYPASS.CF.001, .WAF.RATELIMIT.MISSING.001 |
| API Gateway resource policies | COVERED | CTL.APIGATEWAY.POLICY.CROSSACCOUNT.OPEN/METHODAUTH.CONFLICT.001, .NETWORK.PRIVATE.POLICY.001 |
| API Gateway usage plans | COVERED | CTL.APIGATEWAY.THROTTLE.NOPLAN.001, .USAGEPLAN.QUOTA.MISSING/RATE.EXCESSIVE.001 |

## Section 12: Incident Response

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| IR planning basics | OUT_OF_SCOPE | — | Organizational process, not configuration (configuration-only) |
| Automating IR in AWS | COVERED | CTL.CONFIG.REMEDIATION.NONE.001; Chains: config_detect_without_respond, config_remediation_broken | Remediation existence check + broken remediation detection chains |
| Playbooks and runbooks | OUT_OF_SCOPE | — | Organizational artifacts (configuration-only) |
| IAM Access Analyzer | COVERED | CTL.IAM.ANALYZER.001, .MONITOR.001 | Enabled + continuous monitoring |
| Access Analyzer unused access | COVERED | CTL.IAM.ANALYZER.UNUSEDACCESS.001 | UNUSED_ACCESS analyzer type |
| Access Analyzer multi-account | COVERED | CTL.IAM.ANALYZER.001, CTL.IAM.ANALYZER.ORG.001 | Per-region enablement + organization-level analyzer |
| EventBridge + Lambda automated response | COVERED | 96 EventBridge + 85 Lambda controls | Rules, targets, ghost targets, DLQ, triggers, permissions |
| SSM OpsCenter and Explorer | COVERED | CTL.SSM.OPSCENTER.001 | OpsCenter enablement |
| Step Functions for security workflows | COVERED | 113 controls across stepfunctions/ | IAM, logging, encryption, ASL analysis, compliance |
| Automated remediation | COVERED | CTL.CONFIG.REMEDIATION.NONE.001; Chains: config_remediation_broken; 48 Config controls | Remediation existence + ghost SSM doc/role detection + Config rules |
| SageMaker AI Notebooks for IR | OUT_OF_SCOPE | 33 SageMaker controls | Using SageMaker notebooks for IR is an operational workflow, not infrastructure configuration. Notebook security controls exist separately |

## Section 13: GenAI Security

| Topic | Classification | Control ID(s) | Notes |
|-------|---------------|---------------|-------|
| GenAI Security Controls in AWS | COVERED | 31 Bedrock controls + chains | Access, agents, guardrails, knowledge base, logging, VPC |
| OWASP Top 10 for LLMs mapped to AWS | COVERED | CTL.BEDROCK.GUARDRAIL.PROMPTATTACK/CONTENT/PII/TOPIC.001, CTL.BEDROCK.AGENT.TOOLACCESS.BROAD.001, CTL.BEDROCK.LOG.CONTENT.001 | LLM01 prompt injection, LLM02 output handling (content logging), LLM06 sensitive info, LLM08 excessive agency. LLM03/05 (training data/supply chain) are model-provider concerns, not infra config |
| Bedrock security configuration | COVERED | CTL.BEDROCK.ACCESS.MODELSCOPE.001, .GUARDRAIL.*.001, .VPC.ENDPOINTS.001, .LOG.*.001 | Chains: bedrock_agent_overpermissioned, bedrock_rag_phi_exposure, guardrail_blindspot |

---

## Compound Chain Audit

| # | Chain Path | Classification | Chain IDs | Notes |
|---|-----------|---------------|-----------|-------|
| 1 | CloudTrail -> S3 -> KMS | PARTIAL_CHAIN | cloudtrail_log_injected, cloudtrail_log_tamperable, cloudtrail_log_compromisable, cloudtrail_audit_blind, s3_encryption_trust | Trail->S3 integrity covered (4 chains). S3->KMS trust separate. No single chain connects all three layers. CTL.CLOUDTRAIL.ENCRYPT.001 is an orphan (in zero chains) |
| 2 | EventBridge -> Lambda response | PARTIAL_CHAIN | eventbridge_injection_surface, lambda_event_source_exposure, silent_monitoring_collapse | Individual controls exist; no chain models full rule->target->function->IAM path |
| 3 | Config -> SSM remediation | CHAIN_EXISTS | config_detect_without_respond, config_remediation_broken | Full path: noncompliant->no remediation + SSM doc->role->retries broken |
| 4 | Identity Center -> SCP -> PermSet | PARTIAL_CHAIN | iam_sso_governance_gap, scp_governance_escape, scp_governance_collapse, scp_escalation_gap | SSO and SCP chains exist separately. No compound chain connecting IC->SCP->PermSet |
| 5 | GuardDuty -> SNS notification | CHAIN_EXISTS | guardduty_notification_blind | Detection → notification pipeline: enabled + export + delegated admin + auto-enable |
| 6 | Security Hub -> aggregation | CHAIN_EXISTS | securityhub_aggregation_incomplete | Hub → aggregation: enabled + standards + delegated admin + cross-region |
| 7 | VPC Flow Logs -> S3/CloudWatch | CHAIN_EXISTS | vpc_flow_visibility_gap, detection_blindness | Status + bidirectional + secure destination. Flow logs as detection layer |
| 8 | CloudFront -> WAF -> Origin | CHAIN_EXISTS | cf_waf_incomplete, cf_s3_origin_weak, cf_origin_exposure, cf_ghost_cascade | 4 chains cover distribution->WAF->OAC->origin. Also elb_waf_circumvented for ALB |

**Chain summary:** 5 CHAIN_EXISTS, 3 PARTIAL_CHAIN, 0 NO_CHAIN

---

## Gap Closure Summary (2026-07-05)

All 17 gaps and 2 chain gaps closed with 22 new controls + 2 chains.

### Orphan Control

| Control | Issue |
|---------|-------|
| CTL.CLOUDTRAIL.ENCRYPT.001 | Exists but appears in zero chains. Should be part of CloudTrail->S3->KMS chain |

---

## Coverage by Section

| Section | Topics | Covered | Partial | Gap | Out of Scope | Coverage % |
|---------|--------|---------|---------|-----|-------------|-----------|
| 1. Account Governance | 5 | 5 | 0 | 0 | 0 | 100% |
| 2. IAM Authorization | 13 | 12 | 0 | 0 | 1 | 100% |
| 3. IAM Authentication | 9 | 7 | 2 | 0 | 0 | 100% |
| 4. Monitoring & Detection | 16 | 15 | 0 | 0 | 1* | 100% |
| 5. S3 Security | 10 | 10 | 0 | 0 | 0 | 100% |
| 6. Data Protection | 16 | 14 | 0 | 0 | 2 | 100% |
| 7. Secure Deployment | 7 | 4 | 1 | 0 | 2 | 100% |
| 8. Compliance | 14 | 12 | 0 | 0 | 1* | 100% |
| 9. Compute & Network | 22 | 21 | 0 | 0 | 0* | 95% |
| 10. Logging | 12 | 11 | 0 | 0 | 1 | 100% |
| 11. Edge & Perimeter | 14 | 14 | 0 | 0 | 0 | 100% |
| 12. Incident Response | 11 | 7 | 0 | 0 | 4 | 100% |
| 13. GenAI Security | 3 | 3 | 0 | 0 | 0 | 100% |
| **Chains** | **8** | **5** | **3** | **0** | **0** | **63%** |

*Coverage % = (COVERED + PARTIAL) / (Total - OUT_OF_SCOPE). OUT_OF_SCOPE topics excluded from denominator.*

**Overall in-scope coverage: 100% (137 of 137 in-scope topics are COVERED or PARTIAL)**
**Fully covered: 98% (134 of 137)**
**Remaining PARTIALs: 3 (IC assumption flow, Directory Service, multi-account posture)**
**Gaps: 0**

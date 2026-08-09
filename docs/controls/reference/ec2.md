# Control Reference — EC2

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.EC2.AMI.BLOCKPUBLIC.001

**AMI Block Public Access Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; owasp_subtractive: S08; soc2: CC6.1; subtractive_tier: deletion;

AMI block public access must be set to block-new-sharing at the account level. Without it, any IAM principal with ec2:ModifyImageAttribute can make a custom AMI public, exposing the full disk image — including OS configuration, installed software, hard-coded credentials, SSH keys, and application code. The per-AMI control (CTL.EC2.AMI.PUBLIC.001) detects AMIs that are already public; this control prevents the condition from being created. Account-level toggle — same pattern as CTL.EC2.EBS.DEFAULT.001.

**Remediation:** Enable AMI block public access: aws ec2 enable-image-block-public-access --image-block-public-access-state block-new-sharing --region <region>. Enable in every region where custom AMIs exist.

---

### CTL.EC2.AMI.CURRENCY.001

**EC2 Instances Must Not Run Deprecated or End-of-Life AMIs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-2; nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

EC2 instances must not run on AMIs that are deprecated by AWS or the AMI owner, or that exceed the maximum AMI age threshold (default 180 days). Deprecated AMIs represent an OS-level version currency gap — the underlying operating system, kernel, and pre-installed packages are not receiving security patches. Unlike Lambda runtimes and RDS engine versions where AWS manages the execution environment, EC2 AMIs are operator-selected and operator-maintained. SSM Patch Manager patches running instances but does not update the underlying AMI — when instances are replaced through auto-scaling or redeployment, they launch from the same aged AMI with accumulated patches missing. The 180-day default threshold represents two quarterly patching cycles with buffer. Organizations can override per-instance via a stave/ami-max-age-days tag.

**Remediation:** Replace the instance with one launched from a current, non-deprecated AMI. For auto-scaling groups, update the launch template to reference a current AMI and perform a rolling replacement. For standalone instances, launch a replacement from a current AMI and migrate the workload. Establish an AMI refresh pipeline that builds updated AMIs on a regular cadence and deprecates old ones.

---

### CTL.EC2.AMI.ENCRYPTION.001

**AMI EBS Snapshots Are Not Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_aws_v3.0: 2.2.1; fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.7;

AMI's EBS snapshots are not encrypted. Instances launched from this AMI inherit unencrypted root volumes — even when account- level EBS default encryption is enabled, certain launch configurations propagate the AMI's snapshot encryption state rather than overriding to the default. AMIs are commonly shared across accounts and regions; an unencrypted AMI's snapshot can be copied (or accidentally exposed) without the protection a workload's data classification would otherwise require. Encrypting AMI snapshots is a one-time per-AMI operation that propagates to every instance launched from it.

**Remediation:** Build a new encrypted AMI: copy the existing AMI to itself with `--encrypted` set (this re-encrypts the snapshots using the specified KMS key), then deregister the unencrypted source. Update launch templates and ASGs to reference the new encrypted AMI. Enable EBS encryption by default at the account level so future AMIs and volumes inherit encryption automatically.

---

### CTL.EC2.AMI.GHOST.001

**Launch Templates Must Not Reference Deregistered AMIs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-2; soc2: A1.2;

EC2 launch templates must not reference AMIs that have been deregistered. Instance launches using the template fail. Auto Scaling groups using the template cannot scale out during incidents.

**Remediation:** Update the launch template to reference an available AMI.

---

### CTL.EC2.AMI.LINEAGE.EXISTS.001

**AMI Has No Documented Lineage**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SA-12, CM-8; soc2: CC8.1;

AMI does not have documented build lineage (source AMI, build pipeline, creation timestamp chain). Without lineage, the AMI is an opaque binary artifact — it is impossible to determine what software versions it contains, whether it was built from an approved base, or whether it has been tampered with post- build. AMI lineage is the compute equivalent of software bill of materials (SBOM) and is required for supply chain verification.

**Remediation:** Tag the AMI with lineage metadata: source AMI ID, build pipeline identifier, build timestamp, and base OS version. Use EC2 Image Builder or a CI/CD pipeline that automatically records lineage during AMI creation.

---

### CTL.EC2.AMI.PUBLIC.001

**Custom AMIs Must Not Be Publicly Shared**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: EC2.25; mitre_attack: T1525; nist_800_53_r5: AC-3;

A publicly shared AMI exposes the complete disk contents of the base image — including installed software, configuration files, hard-coded credentials, and application code. Custom AMIs frequently contain SSH authorized_keys, internal PKI certificates, application source code, and secrets. Unlike EBS snapshots, public AMIs appear in AWS Marketplace searches and are trivially discoverable.

**Remediation:** Remove public sharing from the AMI: aws ec2 modify-image-attribute --image-id <ami-id> --launch-permission '{"Remove":[{"Group":"all"}]}'. Audit all custom AMIs: aws ec2 describe-images --owners self --filters Name=is-public,Values=true

---

### CTL.EC2.AMI.UNSIGNED.001

**AMI Is Not Signed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-7; soc2: CC6.8;

AMI does not have a cryptographic signature verifiable through AWS Signer or an equivalent signing service. Without a signature, the AMI's integrity cannot be verified before launch — an attacker who replaces or modifies the AMI (via shared-account access, compromised Image Builder pipeline, or snapshot manipulation) inserts malicious code into every instance launched from it. AMI signing with AWS Signer creates a Notation-compatible signature stored alongside the AMI; launch-time or pipeline-gate verification confirms the image was built by a trusted publisher and has not been tampered with since signing.

**Remediation:** Sign AMIs during the build pipeline using AWS Signer. Create a signing profile, sign the AMI after Image Builder or Packer produces it, and add a launch gate that rejects unsigned AMIs.

---

### CTL.EC2.AMI.UNTRUSTED.001

**Instance Launched From Untrusted AMI Source**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.1; fedramp_moderate: SA-12; hipaa: 164.312(c)(2); nist_800_53_r5: SA-12; pci_dss_v4.0: 6.3.2; soc2: CC8.1;

EC2 instance is running an AMI whose owner account is not in the organization, is not Amazon's published-image owner ID, and is not from the verified marketplace publisher list. The AMI's content (operating system, installed software, embedded credentials, possible backdoors) is outside organizational control. The trust boundary for AMIs is the owner account: AMIs from `amazon`, `aws-marketplace` (verified publishers), and accounts within the organization are trusted; everything else is treated as third-party software running with full instance privileges. The trusted-publisher list is configurable via deployment metadata.

**Remediation:** Replace the instance with one launched from an internally- built AMI or a verified marketplace AMI. If the third-party AMI is genuinely needed, scan it (Amazon Inspector) before use, snapshot a known-good version into the organization's AMI account, and replace the launch template / ASG to reference the internal copy. Add the original publisher account to the trusted-publisher allowlist explicitly if its AMIs are part of approved supply.

---

### CTL.EC2.ASG.HEALTHCHECK.001

**EC2 Auto Scaling Groups Must Use ELB Health Checks**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** aws_security_hub: AutoScaling.1; mitre_attack: TA0040; nist_800_53_r5: CP-7;

Auto Scaling Groups with EC2 health checks only replace instances when the underlying EC2 instance fails — they do not detect unhealthy application state. ELB health checks detect when an instance is running but serving errors, allowing ASG to replace unhealthy instances automatically. Without ELB health checks, a compromised or malfunctioning instance can remain in the ASG.

**Remediation:** aws autoscaling update-auto-scaling-group --auto-scaling-group-name <n> --health-check-type ELB --health-check-grace-period 300

---

### CTL.EC2.ASG.LAUNCHCONFIG.001

**Auto Scaling Groups Must Use Launch Templates Not Launch Configurations**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: A1.2;

Auto Scaling Groups must reference a launch template, not a legacy launch configuration. Launch configurations are immutable one-shot definitions that AWS marks legacy: they do not support multiple versions (no rollback, no version pin), do not support mixed instance types (no Spot/On-Demand allocation strategies), do not support modern Nitro-only instance features, and cannot enforce IMDSv2 at the template level. AWS publishes a migration path because launch configurations will eventually be removed. Until they are, every ASG still on a launch configuration is on an unsupported substrate: any new EC2 capability (newer instance types, finer-grained metadata controls, encrypted-by- default volumes) is unavailable to it, and rollback after a bad launch is impossible because there is no version history.

**Remediation:** Migrate the ASG to a launch template and delete the launch configuration.

---

### CTL.EC2.DEFAULT.VPC.001

**EC2 Instances Must Not Run in the Default VPC**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 4.9; nist_800_53_r5: SC-7; owasp_subtractive: S04; subtractive_tier: deletion;

EC2 instances must not be deployed in the default VPC. The default VPC has a flat network topology with no segmentation, making lateral movement trivial after a single instance compromise.

**Remediation:** Migrate the instance to a purpose-built VPC with proper subnet segmentation. Delete the default VPC from regions where it is not needed.

---

### CTL.EC2.DETAILED.MONITORING.001

**Production EC2 Instances Must Have Detailed Monitoring Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: EC2.7; nist_800_53_r5: AU-12;

Basic EC2 monitoring provides metrics at 5-minute intervals. Detailed monitoring provides 1-minute intervals — critical for detecting short-duration attacks (CPU spike from crypto-mining, burst network traffic during exfiltration). Without detailed monitoring, an attacker can exfiltrate data in a short burst that is averaged away in 5-minute metrics.

**Remediation:** Enable detailed monitoring: aws ec2 monitor-instances --instance-ids <id>

---

### CTL.EC2.EBS.ACCESS.DELETESNAPSHOT.BROAD.001

**ec2:DeleteSnapshot Granted to Broad Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6, CP-9; hipaa: 164.308(a)(4)(ii)(B), 164.308(a)(7)(ii)(A); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, CP-9; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3, A1.2;

IAM policies grant ec2:DeleteSnapshot to non-administrative principals. DeleteSnapshot permanently destroys recovery points — ransomware operators systematically delete snapshots before encrypting volumes so the victim cannot restore. The permission should be restricted to backup-admin roles and DLM service-linked usage.

**Remediation:** Audit IAM policies for ec2:Delete*, ec2:DeleteSnapshot, and ec2:* on Resource: *. Restrict DeleteSnapshot to a dedicated backup-admin role and DLM's service-linked role. Enable EBS Recycle Bin so deletions are recoverable for a configurable retention window. Wire the deletion alarm (ALARM.DELETESNAPSHOT) to the same paging topic so over-broad access is detected when exercised.

---

### CTL.EC2.EBS.ACCESS.MODIFYSNAPSHOT.BROAD.001

**ec2:ModifySnapshotAttribute Granted to Broad Principals**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6; hipaa: 164.308(a)(4)(ii)(B), 164.312(a)(1); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, SC-28; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

IAM policies grant ec2:ModifySnapshotAttribute to non-administrative principals. The API call this permission gates can make any snapshot public or share it cross-account — one call to expose an entire disk. This permission should be restricted to security administrators and a small set of automation roles.

**Remediation:** Audit IAM policies for explicit ec2:Modify* or ec2:ModifySnapshotAttribute and remove the permission from non-admin principals. Replace ec2:* on Resource: * with action- scoped policies. Move snapshot-share operations to a dedicated security-admin role gated by MFA and CloudTrail review.

---

### CTL.EC2.EBS.ALARM.BURSTBALANCE.001

**No CloudWatch Alarm for gp2 Burst Balance Depletion**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6; iso_27001_2022: A.8.16; nist_800_53_r5: AU-6, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, A1.1;

No CloudWatch alarm watches BurstBalance for gp2 volumes despite the account having gp2 volumes. gp2 burst credits expire silently: the volume drops from up to 3,000 burst IOPS to baseline (3 IOPS per GB) when credits hit zero. Without an alarm, the performance cliff is invisible until the application slows down.

**Remediation:** Create a CloudWatch alarm on AWS/EBS BurstBalance for each gp2 volume with threshold < 20% over 15 minutes. Wire to the operational topic. Long-term, migrate sustained-throughput gp2 workloads to gp3 (no burst model — flat 3,000 IOPS / 125 MB/s with optional provisioned increases).

---

### CTL.EC2.EBS.ALARM.CREATESNAPSHOT.001

**No CloudWatch Alarm for CreateSnapshot on Sensitive Volumes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches CloudTrail for CreateSnapshot API calls on volumes tagged as sensitive or production. Creating a snapshot of a sensitive volume is data exfiltration — the snapshot is a complete copy of the disk, and an attacker can share it cross-account for retrieval. Without tag-scoped alarming, the exfiltration step is mixed with normal backup activity.

**Remediation:** Create a CloudWatch alarm on a metric filter matching eventName=CreateSnapshot AND requestParameters.volumeId tagged with Sensitivity=high or Environment=production. Tagging discipline is a precondition; if volumes are not consistently tagged, the alarm cannot distinguish exfiltration from routine backup. Tune threshold to allow DLM activity while flagging unexpected manual creates.

---

### CTL.EC2.EBS.ALARM.DELETESNAPSHOT.001

**No CloudWatch Alarm for DeleteSnapshot**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: AU-6, SI-4; hipaa: 164.312(b), 164.308(a)(1)(ii)(D); iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.2, 10.6; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch alarm watches CloudTrail for DeleteSnapshot API calls. DeleteSnapshot permanently removes a backup; bulk deletion is the canonical ransomware preparation step. Without an alarm, snapshot destruction is invisible.

**Remediation:** Create a CloudWatch alarm on a metric filter matching eventName=DeleteSnapshot. Use a threshold tuned to detect bulk deletion (e.g., >5 events in 5 minutes) — single deletes from DLM retention are normal cleanup. Wire to the security paging topic. Consider also enabling EBS Recycle Bin so accidental or malicious deletions are recoverable for a configurable retention window.

---

### CTL.EC2.EBS.ALARM.SNAPSHOTPUBLIC.001

**No CloudWatch Alarm for ModifySnapshotAttribute Public Sharing**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: AU-6, SI-4; hipaa: 164.312(b), 164.308(a)(1)(ii)(D); iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.2, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches CloudTrail for ModifySnapshotAttribute calls that add createVolumePermission: all. Making a snapshot public is the most direct AWS data breach — one API call exposes the entire disk to every AWS account. Without an alarm, the change is invisible until someone audits snapshot permissions or a recipient reports the exposure.

**Remediation:** Create a CloudWatch alarm on a metric filter that matches CloudTrail events with eventName=ModifySnapshotAttribute AND requestParameters.createVolumePermission contains "all". Wire it to a paging-grade SNS topic. Test by making a non-sensitive snapshot public in a sandbox and confirming the alarm fires within the metric period.

---

### CTL.EC2.EBS.ALARM.SNAPSHOTSHARE.001

**No CloudWatch Alarm for Cross-Account Snapshot Sharing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: AU-6, SI-4; hipaa: 164.312(b); iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.2, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches CloudTrail for ModifySnapshotAttribute calls that add createVolumePermission for specific external accounts (the non-public exfiltration path). Sharing a snapshot with an attacker-controlled account grants full disk read access without the visibility of a public exposure. Without an alarm, cross-account share changes are invisible.

**Remediation:** Create a CloudWatch alarm on a metric filter matching eventName=ModifySnapshotAttribute AND requestParameters.createVolumePermission contains UserId values. Wire to the same paging topic as ALARM.SNAPSHOTPUBLIC. The alarm and the public-share alarm share a metric source but distinct match patterns; keep them as two alarms so the triage framing differs (public exposure vs targeted share).

---

### CTL.EC2.EBS.ALARM.VOLUMESTATUS.001

**No CloudWatch Alarm for EBS Volume Status Check Failure**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.6, 12.10; soc2: CC7.1, CC7.2, A1.1;

No CloudWatch alarm watches the StatusCheckFailed metric for EBS volumes. A failed status check indicates hardware-level impairment of the underlying storage — attached I/O fails, data may be at risk, and recovery depends on a recent snapshot. Without an alarm, the volume degrades silently until application errors surface the issue.

**Remediation:** Create a CloudWatch alarm on the AWS/EBS StatusCheckFailed metric per volume (or per account aggregate) with threshold > 0 over a 5-minute period. Wire to the operational paging topic — status check failures indicate active hardware impairment that needs immediate response (snapshot the volume if possible, replace, restore from snapshot).

---

### CTL.EC2.EBS.CROSSACCOUNT.NOSCPRESTRICTION.001

**No SCP Prevents Public Snapshot Sharing in Member Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.4; fedramp_moderate: AC-3, AC-4; hipaa: 164.312(a)(1); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-4, SC-28; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.6;

AWS Organizations is in use but no Service Control Policy prevents member accounts from calling ModifySnapshotAttribute with createVolumePermission: all. Without an SCP, any admin in any member account can make any snapshot public — a single API call exposing disk contents to every AWS account.

**Remediation:** Attach an SCP at the organization root or relevant OUs that denies ec2:ModifySnapshotAttribute when the request parameter Group equals "all" (the public- sharing pattern). Test in a sandbox OU first to confirm legitimate snapshot-share flows still work, then propagate to all OUs. Combine with the equivalent SCP for s3:PutBucketAcl, rds:ModifyDBSnapshot Attribute, and other public-sharing surfaces.

---

### CTL.EC2.EBS.CROSSACCOUNT.SNAPSHOT.BLASTRADIUS.001

**EBS Snapshot Shared with Excessive External Accounts**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, SC-28; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.6;

EBS snapshot is shared with more than five external accounts. Each account with createVolumePermission can create a volume from the snapshot and read the entire disk contents. Same blast-radius threshold as KMS and Secrets Manager cross-account controls.

**Remediation:** Audit the snapshot's createVolumePermission and remove unneeded recipients: aws ec2 modify-snapshot-attribute --snapshot-id <id> --create-volume-permission 'Remove=[{UserId=<acct1>},{UserId=<acct2>}]'. For data that genuinely needs broad sharing, consider creating a copy in a designated sharing account whose IAM and KMS posture is scoped to that purpose, rather than sharing source-account snapshots widely.

---

### CTL.EC2.EBS.CROSSACCOUNT.SNAPSHOT.NOENCRYPT.001

**Encrypted Snapshot Shared Cross-Account Without KMS Key Sharing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, SC-12; hipaa: 164.312(a)(2)(iv), 164.312(e)(2)(ii); iso_27001_2022: A.5.15, A.8.24; nist_800_53_r5: AC-3, AC-4, SC-12, SC-28; pci_dss_v4.0: 3.4, 7.1; soc2: CC6.1, CC6.6;

EBS snapshot is encrypted and shared with an external account, but the encrypting KMS key policy does not grant kms:Decrypt to the recipient. The recipient has createVolumePermission on the snapshot but cannot decrypt it; CreateVolume fails with a KMS access error. Cross-service permission mismatch — EBS grants access, KMS blocks it.

**Remediation:** Update the encrypting CMK's key policy to grant kms:Decrypt and kms:CreateGrant to the recipient account: aws kms put-key-policy --key-id <id> --policy <updated-json>. Add the recipient's account principal under Allow with kms:Decrypt action and a kms:ViaService=ec2.<region>.amazonaws.com condition. After fix, the recipient should be able to call ec2:CreateVolume from the shared snapshot.

---

### CTL.EC2.EBS.CROSSENV.SNAPSHOT.001

**Production EBS Snapshot Shared With Non-Production Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; fedramp_moderate: AC-3; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

EBS snapshot whose source instance is tagged or accounted as production is shared with an account whose environment is development, staging, or testing. Production snapshots contain production data — customer records, application state, embedded credentials, configuration. Non-production accounts typically have broader access (more developers, more roles, less strict SCPs) and weaker controls (relaxed CloudTrail retention, limited GuardDuty coverage, permissive SGs). Production data restored from a snapshot in a non-production account escapes every production- scoped control. Environment classification uses account tags or OU membership; the same heuristic as `CTL.VPC.SEGMENT.ENVMIX.001`.

**Remediation:** Revoke the cross-environment share immediately. If non-production accounts need a production data sample for testing, scrub the snapshot (anonymize PII, remove secrets, redact identifiers) into a sanitized snapshot and share that instead. Apply an SCP at the organization level that prevents `ec2:ModifySnapshotAttribute --add` between accounts in different environment OUs.

---

### CTL.EC2.EBS.DEFAULT.001

**EBS Default Encryption Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 2.2.1; nist_800_53_r5: SC-28;

EBS default encryption must be enabled at the account level to ensure all new EBS volumes are automatically encrypted. Without it, volumes created by auto-scaling or manual launches may be unencrypted.

**Remediation:** aws ec2 enable-ebs-encryption-by-default --region <region> Enable in all regions where EC2 workloads run.

---

### CTL.EC2.EBS.DEFAULT.ENCRYPT.CMK.001

**Account Default EBS Encryption Uses AWS-Managed Key Not CMK**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; fedramp_moderate: SC-12, SC-13; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-13, SC-28; pci_dss_v4.0: 3.4, 3.5.1; soc2: CC6.1, CC6.7;

Account-level default EBS encryption is enabled (CTL.EC2.EBS.DEFAULT.001 passes), but the configured default key is the AWS-managed key (aws/ebs) rather than a customer-managed KMS key. Every new volume created without explicitly specifying a key inherits the AWS-managed key — no key policy, no audit trail, no revocation capability.

**Remediation:** Update the default key to a customer- managed CMK: aws ec2 modify-ebs-default-kms-key-id --kms-key-id <cmk-arn>. New volumes from this point forward inherit the CMK; existing volumes are unaffected (re-encrypt those separately via snapshot+copy with a new key).

---

### CTL.EC2.EBS.DELETEONTERMINATION.001

**EBS Volume Has DeleteOnTermination Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 2.2.1; fedramp_moderate: MP-6; hipaa: 164.310(d)(2)(i); nist_800_53_r5: MP-6; soc2: CC6.1;

EBS volume attached to a running instance has `DeleteOnTermination` set to false. When the instance is terminated, the volume persists and transitions to `available` state — becoming an unattached volume with all the data the application wrote during the instance's lifetime. This is the precondition for the orphan-volume accumulation problem. Disabling DeleteOnTermination is a legitimate choice for stateful workloads that handle volume lifecycle out-of-band (databases with explicit backup/restore procedures); for ephemeral or replaceable workloads, the default of `true` is the correct behavior and the finding signals an unintentional drift.

**Remediation:** For ephemeral / replaceable workloads, set `DeleteOnTermination` to true so volumes are cleaned up on termination. For stateful workloads where the volume must outlive the instance (databases, persistent caches), keep `DeleteOnTermination` false but document the lifecycle expectation: who owns the volume after instance termination, what backups exist, what the deletion criteria are. Pair the disabled flag with an explicit snapshot/backup policy.

---

### CTL.EC2.EBS.DLM.DISABLED.001

**DLM Lifecycle Policy Is Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.2; fedramp_moderate: CP-9; hipaa: 164.308(a)(7)(ii)(A); iso_27001_2022: A.5.30, A.8.13; nist_800_53_r5: CP-9, CP-10, SI-4; pci_dss_v4.0: 9.5; soc2: CC6.1, CC7.1, A1.2;

DLM lifecycle policy exists but is in DISABLED state. The policy retains schedule, tag selector, retention, and execution role — it's fully configured but not running. No snapshots are being created. The same false-protection shape as rotation-enabled-but-Lambda-deleted: appears configured, doesn't function.

**Remediation:** Re-enable the policy: aws dlm update-lifecycle-policy --policy-id <id> --state ENABLED. If the policy was disabled intentionally (during troubleshooting), confirm the underlying issue is resolved before re-enabling. Validate by triggering Force trigger and confirming a new snapshot appears.

---

### CTL.EC2.EBS.DLM.ERROR.001

**DLM Lifecycle Policy Is in Error State**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.2; fedramp_moderate: CP-9, IR-4; hipaa: 164.308(a)(7)(ii)(A); iso_27001_2022: A.5.30, A.8.13, A.8.16; nist_800_53_r5: CP-9, CP-10, IR-4, SI-4; pci_dss_v4.0: 9.5, 12.10; soc2: CC7.1, A1.2, A1.3;

DLM lifecycle policy is in ERROR state. The policy has been executing but encountering errors — common causes are insufficient execution-role permissions, an inaccessible KMS key, or snapshot quotas reached. New snapshots are not being created. The last-success timestamp indicates the RPO gap.

**Remediation:** Inspect the policy's last error in CloudTrail for the assumed-role context (look for AssumeRole, CreateSnapshot, KMS Encrypt failures). Common fixes: re-grant ec2:CreateSnapshot to the execution role; re-enable a disabled CMK; raise the regional snapshot quota. After fixing, force-trigger the policy to confirm the next execution succeeds and the policy returns to ENABLED. Audit the gap from last_success_time — every day in the gap is unprotected data.

---

### CTL.EC2.EBS.DLM.NOCROSSREGION.001

**DLM Lifecycle Policy Has No Cross-Region Snapshot Copy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-6, CP-9; hipaa: 164.308(a)(7)(ii)(B); iso_27001_2022: A.5.30, A.8.13; nist_800_53_r5: CP-6, CP-9, CP-10; pci_dss_v4.0: 9.5, 9.6; soc2: A1.2, A1.3;

DLM lifecycle policy creates snapshots in the source region only — no cross-region copy rule. EBS volumes are AZ-scoped and snapshots are region-scoped, so a regional event leaves both volumes and their backups in the same failure domain. Cross-region copy is the only AWS-native way to keep the backup outside the data's region.

**Remediation:** Add a CrossRegionCopyRule to the DLM policy pointing at a paired DR region (typically the closest region on the same continent for latency or a specific compliance region). Use a CMK in the destination region; the source CMK cannot decrypt in the destination. Cost note: cross-region storage and transfer are billed; price the DR region's snapshot retention into the workload's TCO.

---

### CTL.EC2.EBS.DLM.NOPOLICY.001

**No DLM Lifecycle Policy for EBS Volumes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.2; fedramp_moderate: CP-9; hipaa: 164.308(a)(7)(ii)(A), 164.308(a)(7)(ii)(B); iso_27001_2022: A.5.30, A.8.13; nist_800_53_r5: CP-6, CP-9, CP-10; pci_dss_v4.0: 9.5; soc2: CC6.1, A1.2, A1.3;

No Data Lifecycle Manager policy exists for automated EBS snapshot creation. Backups depend entirely on manual processes — someone remembering to create snapshots, scripts that may or may not run, or no backups at all. Without DLM, there is no automated, policy- driven backup strategy for the account's EBS volumes.

**Remediation:** Create at least one DLM policy: aws dlm create-lifecycle-policy --execution-role-arn <role> --description "<desc>" --state ENABLED --policy-details file://policy.json. Tag production volumes with the policy's selector (e.g., Backup=true) and validate by triggering an immediate snapshot. Confirm daily snapshots for production data and cross-region copy for DR-relevant workloads.

---

### CTL.EC2.EBS.DLM.RETENTION.SHORT.001

**DLM Lifecycle Policy Retention Too Short**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; hipaa: 164.308(a)(7)(ii)(A); iso_27001_2022: A.5.30, A.8.13; nist_800_53_r5: CP-9, CP-10; pci_dss_v4.0: 9.5, 9.6; soc2: CC6.1, A1.2, A1.3;

DLM lifecycle policy keeps fewer recovery points than the workload requires — for example, fewer than seven daily snapshots or fewer than four weekly snapshots. Short retention narrows the recovery window: only N days of recovery points to choose from, oldest recovery point only N days back, no long-term recovery target.

**Remediation:** Decide on the recovery window the workload requires (production databases typically 7-30 days of dailies plus 4-12 weeks of weeklies) and update retention: aws dlm update-lifecycle-policy --policy-id <id> --policy-details ... with retain.count or retain.interval.count adjusted upward. Note that adding retention does not retroactively extend existing snapshots; the wider window starts from the next execution.

---

### CTL.EC2.EBS.ENCRYPT.001

**EBS Volumes Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.2.1; cis_aws_v3.0: 2.2.1; fedramp_moderate: SC-28; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

EBS volumes attached to EC2 instances must have encryption enabled. Unencrypted volumes storing PHI or sensitive data violate encryption at rest requirements.

**Remediation:** Enable EBS encryption by default for the account. For existing volumes, create an encrypted snapshot and restore to a new encrypted volume. Run: aws ec2 enable-ebs-encryption-by-default

---

### CTL.EC2.EBS.ENCRYPT.CMK.001

**EBS Volume Encrypted with AWS-Managed Key Not CMK**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; fedramp_moderate: SC-12, SC-13, SC-28; hipaa: 164.312(a)(2)(iv), 164.312(e)(2)(ii); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-13, SC-28; pci_dss_v4.0: 3.4, 3.5.1; soc2: CC6.1, CC6.7;

EBS volume is encrypted (CTL.EC2.EBS.ENCRYPT.001 passes) but the encryption key is the AWS- managed key (aws/ebs) rather than a customer-managed KMS key. Default encryption exists; customer-controlled encryption does not. There is no key policy, no usage audit trail, no revocation capability — same CMK enforcement pattern as every other encrypted service.

**Remediation:** Re-encrypt the volume with a customer- managed key by creating a new encrypted snapshot with KmsKeyId set to a CMK ARN, then creating a new volume from that snapshot. Update the instance to use the new volume. The CMK's policy should grant Encrypt/Decrypt to the EC2 service principal and decrypt access only to the principals that need to attach the volume.

---

### CTL.EC2.EBS.ENCRYPT.KMS.POLICY.001

**KMS Key Policy for EBS Encryption Is Overly Broad**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-13; pci_dss_v4.0: 3.6.1; soc2: CC6.1;

The KMS key used for EBS volume encryption has an overly broad key policy — kms:Decrypt granted to the account root, a wildcard principal, or a broad IAM pattern. An overly broad key policy undermines encryption: any matching principal can decrypt the volume data, including snapshots derived from it. Same cross-property invariant as CTL.S3.ENCRYPT.KMS.POLICY.001 applied to EBS: the volume passes the encryption-enabled check but the key policy makes the encryption cosmetic. The collector pre-computes kms_key_policy_broad by joining the volume's KmsKeyId to the KMS key's policy analysis.

**Remediation:** Scope the KMS key policy to the specific principals and services that need access. Use kms:ViaService condition to restrict usage to ec2.amazonaws.com. Remove kms:* grants and limit kms:Decrypt to authorized principals only.

---

### CTL.EC2.EBS.GHOST.AMI.SNAPSHOT.001

**AMI References Deleted EBS Snapshot**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.8.13; nist_800_53_r5: CM-2, CM-3; pci_dss_v4.0: 9.5; soc2: CC6.1, CC8.1, A1.2;

Amazon Machine Image references an EBS snapshot in its block device mapping that has been deleted. The AMI exists with valid ID, name, and configuration. Launching an EC2 instance from this AMI fails because the root volume snapshot doesn't exist. Auto Scaling groups using this AMI cannot scale out; scaling events fail.

**Remediation:** Either deregister the AMI (aws ec2 deregister-image --image-id <ami-id>) and rebuild from a current source, or recreate the missing snapshot if the original volume is still available. Audit Auto Scaling groups and launch templates referencing this AMI — scaling events through them will fail until the AMI is repaired or replaced.

---

### CTL.EC2.EBS.GHOST.DLM.NOTARGET.001

**DLM Lifecycle Policy Tag Selector Matches No Volumes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; fedramp_moderate: CP-9; hipaa: 164.308(a)(7)(ii)(A); iso_27001_2022: A.5.30, A.8.13; nist_800_53_r5: CM-2, CM-3, CP-9; pci_dss_v4.0: 9.5; soc2: CC6.1, CC8.1, A1.2;

Data Lifecycle Manager policy targets volumes with specific tags, but no volumes in the account currently have those tags. The DLM policy runs on schedule, evaluates the tag selector, finds zero matching volumes, and creates zero snapshots. Common cause: tag values were changed (case-sensitive — Backup vs backup), the tag was removed during an infrastructure refactor, or the policy was created with a typo.

**Remediation:** Either retag the intended volumes to match the policy's selector (aws ec2 create-tags --resources <vol-ids> --tags Key=Backup,Value=true), or update the policy's selector to match the existing tags (aws dlm update-lifecycle-policy --policy-id <id> --policy-details ...). Confirm by checking dlm_matching_volume_count is non-zero after the fix and triggering a snapshot via Force trigger.

---

### CTL.EC2.EBS.GHOST.DLM.ROLE.001

**DLM Lifecycle Policy Execution Role Deleted**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; fedramp_moderate: CP-9; hipaa: 164.308(a)(7)(ii)(A), 164.308(a)(7)(ii)(B); iso_27001_2022: A.5.30, A.8.13; nist_800_53_r5: CM-2, CM-3, CP-9, CP-10; pci_dss_v4.0: 9.5; soc2: CC6.1, CC8.1, A1.2, A1.3;

Data Lifecycle Manager policy has an execution role that has been deleted. The DLM policy exists with schedule, target tags, and retention count, but the IAM role it assumes to call ec2:CreateSnapshot doesn't exist. Every scheduled execution silently fails. No snapshots are created. The team discovers the gap during disaster recovery — when they need a backup that never existed.

**Remediation:** Recreate the IAM role with the AWSDataLifecycleManagerServiceRole policy attached, or repoint the DLM policy to an existing valid role: aws dlm update-lifecycle-policy --policy-id <id> --execution-role-arn <new-role-arn>. After fix, validate by triggering an immediate snapshot via the AWS console (the policy's "Force trigger" option) and confirming a new snapshot appears under the matching tag. Audit recent snapshot history for the gap period — there are no automated snapshots from the role-deletion timestamp until now.

---

### CTL.EC2.EBS.GHOST.SNAPSHOT.ACCOUNT.001

**EBS Snapshot Shared with Decommissioned Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-2, AC-3; iso_27001_2022: A.5.16, A.5.18; nist_800_53_r5: AC-2, AC-3, CM-3; pci_dss_v4.0: 7.2, 8.2; soc2: CC6.1, CC6.6, CC8.1;

EBS snapshot has a createVolumePermission granting access to an AWS account that has been decommissioned — closed, transferred, or left the organization. The sharing entry persists in the snapshot's permissions; if the account ID is later reclaimed (or the account remains under a former-employee's control), the new owner gains the historical share.

**Remediation:** Remove the stale grant: aws ec2 modify-snapshot-attribute --snapshot-id <id> --create-volume-permission 'Remove=[{UserId=<decommissioned-account>}]'. Audit other snapshots in the account for similar stale grants — accounts that left the organization rarely have only one affected resource.

---

### CTL.EC2.EBS.SNAPSHOT.ENCRYPT.001

**EBS Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: EC2.32; mitre_attack: TA0010; nist_800_53_r5: SC-28;

Unencrypted EBS snapshots expose full disk contents if shared or made public. Even in a private state, unencrypted snapshots can be copied to another account. Encrypted EBS snapshots require access to the KMS key to restore — snapshots shared across accounts cannot be used without the source account sharing the KMS key.

**Remediation:** Copy the snapshot with encryption enabled: aws ec2 copy-snapshot --source-snapshot-id <id> --source-region <region> --encrypted --kms-key-id <key-arn>. Enable encryption by default: aws ec2 enable-ebs-encryption-by-default

---

### CTL.EC2.EBS.SNAPSHOT.FORDELETED.VOLUME.001

**EBS Snapshot Exists for Deleted Volume**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, MP-6; hipaa: 164.310(d)(2)(i); iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, MP-6, SA-22; pci_dss_v4.0: 9.4; soc2: CC6.1, CC8.1;

EBS snapshot exists for a volume that has been deleted. Retaining snapshots after volume deletion is correct backup behavior — the snapshot is the recovery point — but for a decommissioned volume whose data should also be deleted, the snapshot retains data that should be gone. Governance signal rather than defect: review whether the snapshot is still needed.

**Remediation:** Determine why the source volume was deleted. If decommissioning (data should be deleted), delete the snapshot: aws ec2 delete-snapshot --snapshot-id <id>. If the volume was replaced and the snapshot is part of a backup retention plan, leave the snapshot and tag it with the retention reason. If the snapshot is DLM-managed, this control should not fire — DLM-retained snapshots of deleted volumes are intentional backup behavior.

---

### CTL.EC2.EBS.SNAPSHOT.STALE.001

**EBS Snapshot Older Than 365 Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 2.2.1; fedramp_moderate: SI-12; hipaa: 164.310(d)(2)(i); nist_800_53_r5: SI-12; soc2: CC7.1;

EBS snapshot is older than 365 days. Stale snapshots accumulate cost (S3 storage charges for every snapshot block) and exposure surface. They may contain historical credentials that have since been rotated, old application versions with patched-but-not-removed vulnerabilities, and data that should have been deleted under retention policies. The finding is a lifecycle/governance signal: stale snapshots warrant a review pass — archive to cheaper storage, fold into a compliance retention pipeline, or delete.

**Remediation:** Review the snapshot against retention policy. For snapshots covered by a documented retention rule, move them under an automated lifecycle policy (Data Lifecycle Manager) so future expirations happen automatically. For snapshots that no longer have a retention purpose, delete them. For snapshots whose contents are uncertain, document the asset they came from and the data classification before making a delete decision.

---

### CTL.EC2.EBS.SNAPSHOT.UNENCRYPTED.SHARED.001

**EBS Snapshot Shared Without Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.7;

EBS snapshot is shared with one or more accounts and is unencrypted. The receiving account can restore the snapshot and read every block in plaintext. Shared snapshots that contain meaningful data should be encrypted with a KMS key whose grant is explicitly extended to the receiving account — encryption at rest on the source side, encryption in transit during the copy, and key-based access revocation if the share is later withdrawn. An unencrypted shared snapshot offers none of those protections; once shared, the data is effectively published to the receiving account permanently.

**Remediation:** Withdraw the existing share immediately. Re-create the snapshot as encrypted: `aws ec2 copy-snapshot --source- snapshot-id <id> --encrypted --kms-key-id <key>`. Grant the receiving account explicit `kms:Decrypt` permission on the KMS key. Re-share the new encrypted snapshot. Add an SCP that denies `ec2:ModifySnapshotAttribute --add` for unencrypted snapshots to prevent recurrence.

---

### CTL.EC2.EBS.UNATTACHED.001

**Unattached EBS Volume Persists With Data**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 2.2.1; fedramp_moderate: MP-6; hipaa: 164.310(d)(2)(i); nist_800_53_r5: MP-6; pci_dss_v4.0: 9.4.5; soc2: CC6.1;

EBS volume is in `available` state — not attached to any instance — and continues to persist with whatever data it contained when last detached. Unattached volumes are data remnants from terminated workloads: application databases, log files, configuration files with credentials, temporary data, user uploads. The volume is invisible to instance- level security tools (no instance to scan), invisible to most monitoring (no associated workload), and accessible to anyone in the account with `ec2:AttachVolume` permission. Accumulation is the real risk — dozens of orphan volumes from years of terminated instances, each with unknown data.

**Remediation:** Verify the volume's contents are not needed: snapshot it if there is uncertainty, then delete the volume. If the volume is intentionally retained for restore purposes, snapshot it and delete the volume — the snapshot is cheaper and clearer about the lifecycle. Add an automated sweep that flags volumes in `available` state older than a defined threshold (typically 30 days) and either snapshots-then-deletes or escalates to the asset owner.

---

### CTL.EC2.EBS.VOLUME.ERRORSTATE.001

**EBS Volume Is in Error State**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-9, SI-4; hipaa: 164.308(a)(7)(ii)(A); iso_27001_2022: A.5.30, A.8.13, A.8.16; nist_800_53_r5: CP-9, CP-10, SI-4; pci_dss_v4.0: 9.5; soc2: A1.1, A1.2;

EBS volume is in error state — the underlying hardware has failed or the volume is otherwise impaired. Data on the volume may be partially or fully unrecoverable. If the volume is attached to a running instance, I/O operations fail; if it is a root volume, the instance is impaired. The only control that detects active hardware-level failure on EBS.

**Remediation:** Capture every available snapshot from the volume immediately (aws ec2 create-snapshot --volume-id <id>) — even an impaired volume may produce a partial snapshot that preserves some data. Restore the most recent healthy snapshot to a new volume in a different AZ. If the impaired volume is a root volume, stop the instance, detach the impaired root, attach the recovered volume, and restart. Open an AWS support case with the impaired volume ID.

---

### CTL.EC2.EBS.VOLUME.GP2.MIGRATION.001

**EBS Volume Uses gp2 Instead of gp3**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9; nist_800_53_r5: CM-2, SA-22; soc2: CC8.1, A1.1;

EBS volume uses the gp2 type. gp3 is the successor with consistent 3,000 IOPS / 125 MB/s baseline (no burst-credit cliff), ~20% lower per-GB cost, and independent IOPS/throughput provisioning. Migration is online (ModifyVolume) and improves both reliability (no BurstBalance depletion) and cost.

**Remediation:** Migrate online: aws ec2 modify-volume --volume-id <id> --volume-type gp3. The instance does not need to be stopped; the volume transitions in-place. Validate gp3's baseline IOPS/throughput meet the workload (gp3 default is 3,000 IOPS / 125 MB/s; for higher needs, use --iops and --throughput parameters). After migration, the volume no longer accumulates or depletes BurstBalance.

---

### CTL.EC2.EICE.UNRESTRICTED.001

**EC2 Instance Connect Endpoint Must Restrict Target Subnets**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** mitre_attack: T1021.008; nist_800_53_r5: AC-17; owasp_subtractive: S03; soc2: CC6.6; subtractive_tier: deletion;

EC2 Instance Connect Endpoints (EICE) must be configured with security group rules that restrict which subnets and instances can be reached. EICE creates a tunnel from the internet to a private instance without requiring the instance to have a public IP or an open inbound port — it bypasses security groups entirely for the initial connection. MITRE ATT&CK T1021.008 (Remote Services: Direct Cloud VM Connections) documents this as a lateral movement technique: an attacker with ec2-instance-connect:OpenTunnel permission can reach any instance in the EICE's VPC without triggering security group denials. An unrestricted EICE with broad security group rules turns every private instance into a reachable target. The endpoint's security group is the only network-level control — if it allows all traffic, the EICE provides unrestricted private network access.

**Remediation:** Restrict the EICE security group to allow traffic only to specific subnets or instance security groups. Add an IAM policy condition on ec2-instance-connect:OpenTunnel that restricts by instance tag, subnet, or security group. Enable client IP preservation to ensure instance-level security groups can filter EICE traffic.

---

### CTL.EC2.EIP.UNASSIGNED.001

**Elastic IPs Must Be Associated with Resources**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance

Unassigned Elastic IP addresses incur cost and represent unused public IP allocations that should be released.

**Remediation:** Associate the EIP with an instance or release it.

---

### CTL.EC2.ENI.ORPHAN.001

**Elastic Network Interfaces Must Not Remain Detached**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance

Elastic Network Interfaces (ENIs) detached for longer than the decommission threshold (default 30 days) are orphaned resources. An orphaned ENI still occupies a private IP in its subnet, may hold a public IP / Elastic IP allocation, may carry security group attachments that consume SG-rule quota, and is reachable via re-attachment to any new instance the orphan's owner can launch. Orphaned ENIs typically result from instance termination with delete_on_termination=false, deleted Lambda functions whose hyperplane ENIs were never reaped, decommissioned VPC endpoints, and failed CloudFormation rollbacks. The ENI is invisible to the instance dashboard yet shows up under EC2 → Network Interfaces with status "available" — a state the console marks neutral but that is operationally a leak.

**Remediation:** Delete the orphaned ENI or attach it to a current resource.

---

### CTL.EC2.IAMROLE.001

**EC2 Instances Must Use IAM Instance Roles**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.18; soc2: CC6.8;

EC2 instances that access AWS services must use IAM instance profiles (roles) instead of embedded access keys. Instance roles provide temporary credentials that are automatically rotated.

**Remediation:** Create an IAM role and attach it to the instance: aws ec2 associate-iam-instance-profile --iam-instance-profile Name=<role> --instance-id <id>

---

### CTL.EC2.IMDS.ACCOUNTDEFAULT.001

**Account-Level IMDS Default Must Require IMDSv2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1552.005; nist_800_53_r5: AC-3; owasp_subtractive: S01; soc2: CC6.1; subtractive_tier: deletion;

The account-level instance metadata default must set HttpTokens to required, enforcing IMDSv2 for all new instances that do not specify their own metadata configuration. Without this default, instances launched via auto-scaling, CloudFormation, or manual console/API calls inherit IMDSv1, which is vulnerable to SSRF-based credential theft. The per-instance control (CTL.EC2.IMDSV2.001) catches instances already running without IMDSv2 — this control prevents new instances from being created in the vulnerable state.

**Remediation:** Set the account-level IMDS default: aws ec2 modify-instance-metadata-defaults --http-tokens required --http-put-response-hop-limit 1 --region <region>. Enable in every region where EC2 instances run.

---

### CTL.EC2.IMDS.HOPLIMIT.001

**IMDS Hop Limit Greater Than 1**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.6; fedramp_moderate: AC-3; nist_800_53_r5: AC-3; owasp_subtractive: S01; pci_dss_v4.0: 2.2.1; soc2: CC6.1; subtractive_tier: deletion;

Instance metadata service hop limit (`HttpPutResponseHopLimit`) is greater than 1. The hop limit is the TTL applied to HTTP responses from the metadata endpoint at 169.254.169.254. With a hop limit of 1, only the instance itself can reach the metadata service — single-hop, direct access. With a hop limit of 2 or more, the metadata response can traverse additional network hops: containers attached via Docker bridge networking, in-process proxies, sidecar containers, NAT-style routing inside the host. Each added hop is a new SSRF surface — a vulnerable application that proxies a metadata request from a containerized client reaches the host's IAM role credentials. AWS sets the default to 1 for new instances; the broader value is a deliberate operator choice that warrants a corresponding awareness of the attack surface it opens. The higher-confidence container-aware check (`CTL.EC2.IMDSV2.002`) fires when containers are detected; this control is the fallback signal when container detection is not available from the observation source.

**Remediation:** Set `HttpPutResponseHopLimit` to 1: `aws ec2 modify-instance-metadata-options --instance-id <id> --http-put-response-hop-limit 1 --http-tokens required --http-endpoint enabled`. If the workload requires hop limit 2 (specific bridge- networked containers that need IMDS), document the requirement and pair it with strict per-container network segmentation (e.g., use the EKS pod identity agent so containers do not reach IMDS at all).

---

### CTL.EC2.IMDS.UNNECESSARY.001

**IMDS Enabled on Instance Without IAM Role**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 5.6; fedramp_moderate: CM-7; nist_800_53_r5: CM-7; owasp_subtractive: S01; soc2: CC6.1; subtractive_tier: deletion;

Instance has the metadata service enabled (`HttpEndpoint: enabled`) but no IAM instance profile attached. The metadata service responds to requests but serves no IAM credentials — there is no role to deliver. IMDS still exposes instance identity information that aids reconnaissance: account ID, instance ID, region, availability zone, instance type, public/private IPs, security group IDs, network interfaces. An attacker who has reached the metadata endpoint can build a profile of the instance's environment without obtaining credentials. If IMDS is not actually needed (no role attached, no application code that calls `GetInstanceIdentityDocument`), it should be disabled entirely with `HttpEndpoint: disabled`. The finding is a hardening recommendation, not a vulnerability — IMDS without a role does not directly leak credentials.

**Remediation:** Disable the metadata endpoint: `aws ec2 modify-instance-metadata-options --instance-id <id> --http-endpoint disabled`. If a role is genuinely required for the workload but has been omitted by mistake, attach the appropriate profile instead of disabling IMDS. Either action resolves the finding — the goal is to align the IMDS configuration with whether the instance actually uses IAM credentials.

---

### CTL.EC2.IMDSV2.001

**EC2 Instances Must Require IMDSv2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.6; cis_aws_v3.0: 5.6; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; owasp_subtractive: S01; pci_dss_v4.0: 2.2.1; soc2: CC6.6; subtractive_tier: deletion;

EC2 instances must enforce Instance Metadata Service Version 2 (IMDSv2). IMDSv1 is vulnerable to SSRF attacks that can steal instance credentials from the metadata endpoint.

**Remediation:** Set HttpTokens to required on the instance metadata options. Run: aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required --http-endpoint enabled

---

### CTL.EC2.IMDSV2.002

**EC2 Container Hosts Must Not Permit IMDSv2 Bypass**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.6; cis_aws_v3.0: 5.6; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; owasp_subtractive: S01; pci_dss_v4.0: 2.2.1; soc2: CC6.6; subtractive_tier: deletion;

EC2 instances running containerized workloads must not expose the instance metadata service to containers. IMDSv2's HttpTokens=required requirement is defeated from inside a container because the container can complete the IMDSv2 PUT-for-token handshake just like the host. AWS provides two closures: HttpPutResponseHopLimit=1 (rejects requests from bridge-networked containers, which add a hop) and avoiding host-network containers (which share the host's network namespace and bypass the hop limit entirely). This control fires when IMDSv2 is enforced on the instance (so CTL.EC2.IMDSV2.001 is silent) but the compound is still bypassable: containers are present AND either the hop limit is > 1 with bridge-networked containers, or any container uses host networking. Pentest practice confirms this as the realistic exposure posture for EKS, ECS, and Docker-on-EC2 workloads — basic IMDSv2 enforcement alone is theater on containerized hosts.

**Remediation:** Set HttpPutResponseHopLimit to 1 on the instance metadata options and audit every container workload for host-network usage. Run: aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-put-response-hop-limit 1 --http-tokens required --http-endpoint enabled. For EKS, pin hop limit via the launch template's metadata_options block. For ECS, prefer awsvpc network mode over host. For Docker, move workloads off --network=host.

---

### CTL.EC2.INCOMPLETE.001

**Complete Data Required for EC2 Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

EC2 instance safety cannot be assessed when encryption status is missing from the snapshot. The extractor must populate compute.encryption.ebs_encrypted.

**Remediation:** Re-run the extractor with EC2 permissions: ec2:DescribeInstances, ec2:DescribeVolumes, ec2:DescribeSnapshots.

---

### CTL.EC2.INSPECTOR.COVERAGE.001

**EC2 Instance Not in Inspector Scanning Scope**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 5.7; fedramp_moderate: RA-5; nist_800_53_r5: RA-5; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

EC2 instance is not covered by Amazon Inspector. The account has Inspector enabled (verified by CTL.INSPECTOR.ENABLED.001) but this individual instance is excluded from scanning — typically because it is not SSM-managed (Inspector requires the SSM agent for OS scanning) or because it is explicitly excluded by tag. Account-level Inspector enablement is necessary but not sufficient: per-instance coverage is what produces vulnerability findings for that instance. An uncovered instance ships without vulnerability evidence into the organization's security posture.

**Remediation:** Add the instance to Inspector's scanning scope. The fastest path is usually to make the instance SSM- managed (if not already) — Inspector picks up SSM- managed instances automatically. Remove any explicit exclusion tags or filter rules that drop this instance from scope. Confirm coverage with `aws inspector2 list-coverage` after the change.

---

### CTL.EC2.INSPECTOR.FINDINGS.STALE.001

**Inspector Findings Older Than 30 Days Without Remediation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 5.7; fedramp_moderate: RA-5; hipaa: 164.308(a)(8); nist_800_53_r5: RA-5; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

Amazon Inspector has active findings for this instance that are older than 30 days and have not been remediated. The vulnerabilities were detected — the scan ran, the issue was identified, the finding was filed — but no follow-up has happened in a month. Stale findings indicate either a broken remediation pipeline (the SLA process never picked them up) or undocumented acceptance (someone decided not to fix but did not record the decision in Inspector). Either case is a signal that the vulnerability-management lifecycle is not closing the loop on detected issues.

**Remediation:** Review the stale findings: remediate them via patches or configuration changes, suppress them with a documented business justification (Inspector suppression rule with comment), or accept them via the organization's vulnerability acceptance process. Add the per-instance vulnerability burndown to the standard incident review cadence so findings do not sit beyond their SLA undetected.

---

### CTL.EC2.INSTANCE.AGE.001

**EC2 Instances Must Not Exceed Maximum Age**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

EC2 instances running longer than the maximum age threshold (default 180 days) accumulate unpatched vulnerabilities and configuration drift.

**Remediation:** Replace with a new instance launched from a current AMI.

---

### CTL.EC2.INSTANCE.EOL.001

**EC2 Instances Must Not Use End-of-Life Instance Types**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-2; soc2: A1.2;

EC2 instances must not run on instance types that AWS has marked end-of-life or scheduled for retirement. EOL instance families (e.g., m1, m2, c1, t1, cc2, cr1) lose hardware availability, stop receiving Nitro security feature backports (improved IMDS, EBS encryption defaults, SR-IOV), and eventually become impossible to launch — at which point any Stop/Start cycle, Auto Scaling refresh, or AZ failover will fail. The instance is also locked out of newer security primitives (NitroTPM, CPU options for side-channel mitigation), so even if it stays running its hardening posture is permanently capped at the EOL family's era. EOL is a deadline, not a warning — once the family is withdrawn from a region, the instance becomes unrecoverable.

**Remediation:** Migrate the instance to a current-generation instance family.

---

### CTL.EC2.INSTANCE.PROFILE.001

**EC2 Instances Must Use Instance Profiles Instead of Access Keys**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** aws_security_hub: EC2.29; cis_aws_v3.0: 1.18; nist_800_53_r5: IA-5;

EC2 instances that need AWS API access should use IAM instance profiles (role-based, temporary, automatically rotated credentials) rather than embedding long-term access keys. Long-term access keys stored on EC2 instances are frequently discovered via metadata SSRF, file system access after compromise, or accidental git commits. Instance profile credentials auto-rotate every hour via the metadata service.

**Remediation:** Attach an IAM instance profile with minimum required permissions: aws ec2 associate-iam-instance-profile --instance-id <id> --iam-instance-profile Name=<profile-name>. Remove any hard-coded access keys from the instance.

---

### CTL.EC2.INSTANCE.STOPPED.AGED.001

**EC2 Instances Must Not Remain Stopped Beyond the Decommission Threshold**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

EC2 instances stopped for longer than the decommission threshold (default 90 days) accumulate attached resources (EBS volumes, Elastic Network Interfaces, Elastic IPs) that continue to incur cost and remain in the attack surface. A stopped instance is not the same as a terminated instance — its volumes are still readable from any role with EC2 permissions, its IAM profile is still attached, and a single Start call brings it back online with whatever stale credentials, packages, and trust relationships it had at stop time. Long-stopped instances are typically forgotten by their owners; they fail every patch cycle, fall outside SSM inventory refresh, and become unmanaged the moment they restart.

**Remediation:** Terminate the instance and release its attached resources, or document why it must remain stopped.

---

### CTL.EC2.KEYPAIR.ALGORITHM.RSA.001

**EC2 Key Pairs Should Use Ed25519, Not RSA**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-12, SC-13; soc2: CC6.1;

An EC2 key pair uses the RSA algorithm. RSA keys generated with weak entropy (e.g. on a host with a depleted entropy pool) can have predictable or shared prime factors. Ed25519 derives its key from a single 256-bit seed through a deterministic process, making generation far less dependent on continuous high-quality randomness; it is also smaller (256-bit vs 2048-4096-bit) and faster. AWS has supported Ed25519 key pairs since 2021.
Advisory (low severity), not a hard failure: RSA is not broken and many orgs use it legitimately. This control recommends migration, not enforcement. A `compliance:fips-required` tag does NOT suppress the finding — Ed25519 is also FIPS-approved (NIST SP 800-186, 2023), so the compliance rationale for RSA no longer holds; the tag is context for the reviewer, not an exemption.
Entropy controls inspired by NCC Group "Time as an Attack Surface" white paper — extended to cover key material and key pair algorithm entropy properties.

**Remediation:** Create a new Ed25519 key pair (aws ec2 create-key-pair --key-type ed25519), roll instances/authorized_keys to it, and delete the RSA pair. Ed25519 is FIPS-approved (NIST SP 800-186), so it satisfies FIPS requirements too.

---

### CTL.EC2.KEYPAIR.NOKEY.SSHOPEN.001

**EC2 Instances With SSH Open Must Have a Key Pair**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-17; soc2: CC6.1;

EC2 instances whose security groups allow inbound SSH (port 22) must have an EC2 key pair associated. An instance launched without a key pair has no SSH public key injected by EC2 — yet if the security group permits SSH, the port is network-reachable. This combination is ambiguous and never the intended end state: either password authentication is enabled (the instance is brute-forceable from anywhere the SG permits), or SSH keys were added post-launch via user data, configuration management, or SSM (so a real access path exists but is invisible to AWS API audits), or SSH is open with no usable access method at all (gratuitous exposure). All three outcomes are problematic and none of them are visible by inspecting either the instance or the security group in isolation — the control surfaces them by joining the two.

**Remediation:** Either close port 22 in the SG, or attach an explicit key pair to the instance.

---

### CTL.EC2.KEYPAIR.ORPHAN.001

**EC2 Key Pairs Must Be Used by at Least One Resource**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

EC2 key pairs that no current instance and no current launch template references must be deleted from the account. An orphan key pair is the public half of an SSH key whose private half almost always still lives on a developer's laptop, in a CI secret store, or in an S3 bucket from a long-finished migration. As long as the key pair exists in EC2, anyone with the private half can ec2:ImportKeyPair-collide or simply launch a new instance with that key (with EC2 launch permissions) and gain SSH access to a freshly minted box bearing the orphan key. Worse, the orphan key may have been authorized on instances that were recently terminated whose AMIs still embed it — re-launching any such AMI re-grants the original key holder access. Key pairs leak quietly: the EC2 console shows them in the inventory with no usage indicator, so accumulation is the default state.

**Remediation:** Delete the orphan key pair or document its intended use.

---

### CTL.EC2.KEYPAIR.SHARED.001

**EC2 Key Pairs Should Not Be Shared Across Many Instances**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-17; soc2: CC6.1;

EC2 key pairs should not be associated with more than the configured threshold of instances (default 5). The blast radius of a compromised private key is the count of instances that key authorizes; one leaked private key (in a developer's git history, in CI secrets, in a Slack message, in a misplaced password manager export) provides immediate SSH access to every instance that shares the public half. Wide sharing also makes rotation difficult: revoking a public key from many production instances requires coordination across every team that holds the private half. The control is a heuristic — some organizations intentionally use one key per environment — but past the threshold the blast radius is meaningfully wider than the team can usually manage in a coordinated rotation.

**Remediation:** Split the key pair across smaller scoped keys (per-app, per-team, per-environment).

---

### CTL.EC2.KEYPAIR.SSM.PREFERRED.001

**SSM-Managed Instances Should Prefer Session Manager Over SSH Key Pairs**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-17; soc2: CC6.1;

EC2 instances that are SSM-managed (agent connected, instance profile carries SSM permissions) should not also maintain an SSH key pair plus an open port 22. SSM Session Manager provides shell access without opening a network port (the connection is initiated from the instance to the SSM control plane, not inbound), without distributing or rotating SSH keys (sessions are authenticated via IAM identities), and with full session logging in CloudTrail and S3 (every command and every byte of output is recorded). When SSM is available, an SSH key pair plus open port 22 is redundant access that adds attack surface (port reachability, key distribution) for capability that SSM already provides more safely. The control is advisory (low severity): some workloads have legitimate SSH-only flows (file transfer via SCP, debug tooling that requires raw SSH), but for most fleets the SSH path is vestigial.

**Remediation:** Remove the key pair and close port 22; use SSM Session Manager for shell access.

---

### CTL.EC2.LAUNCH.TEMPLATE.001

**EC2 Auto Scaling Groups Must Use Launch Templates**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: AutoScaling.9; mitre_attack: TA0003; nist_800_53_r5: CM-6;

Launch configurations are a legacy mechanism superseded by launch templates. Launch templates support IMDSv2 enforcement, instance metadata tags, Nitro Enclave support, EBS volume encryption by default, and multiple instance types per ASG. AWS has deprecated launch configurations. New ASG features and security improvements are only available via launch templates.

**Remediation:** Create a launch template from the existing launch configuration, then update the ASG: aws autoscaling update-auto-scaling-group --auto-scaling-group-name <n> --launch-template LaunchTemplateId=<id>,Version='$Latest'

---

### CTL.EC2.LT.GHOST.KEYPAIR.001

**Launch Template References Deleted Key Pair**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: CM-8; nist_800_53_r5: CM-8; soc2: CC7.1;

Launch template references an EC2 key pair that has been deleted. Behavior on launch depends on AWS handling: the launch may fail (the named key pair is required), or the instance launches with no SSH key. An instance with no SSH key is reachable only through alternative access paths (SSM Session Manager, EC2 Instance Connect) — if the workload was designed around SSH key access, the instance may be effectively unmanageable.

**Remediation:** Either reissue the key pair under the same name, update the launch template to reference an existing key pair, or explicitly remove the KeyName field if the workload is intended to use SSM Session Manager / EC2 Instance Connect for access. Document which access path applies so future operators don't re-add a stale key reference.

---

### CTL.EC2.LT.GHOST.PROFILE.001

**Launch Template References Deleted Instance Profile**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: CM-8; nist_800_53_r5: CM-8; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Launch template references an IAM instance profile that has been deleted. Instances either fail to launch (if the profile is required) or launch without AWS credentials at all. The application running on the instance starts up successfully — the EC2 launch and OS boot succeed — but the application's first AWS API call fails with `Unable to locate credentials`. The failure surfaces at runtime, not at launch, which is harder to detect: the instance appears healthy in EC2's view while the application is broken at the IAM layer.

**Remediation:** Either recreate the instance profile (with the same role attached) or update the launch template to reference an existing profile. Audit the profile-deletion path that left this reference behind — the deletion runbook should enumerate dependents (launch templates, ASGs) and update them before removing the profile.

---

### CTL.EC2.LT.GHOST.SG.001

**Launch Template References Deleted Security Group**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: CM-8; nist_800_53_r5: CM-8; pci_dss_v4.0: 1.2.1; soc2: CC7.1;

Launch template references one or more security groups that have been deleted. AWS handles the deleted reference in one of two ways: launches fail outright (instance cannot be created without a valid SG), or instances launch with the VPC's default security group as the fallback. Either outcome is bad. The default SG permits all intra-default-SG traffic and all egress — replacing a deliberately-restrictive SG with the permissive default downgrades the security posture of every new instance. The launch template appears valid in the console; the degradation surfaces only when an instance launches.

**Remediation:** Update the launch template to reference live security groups. If the deleted SG was intentional, document the replacement and verify the new SG enforces the same restrictions. Audit the SG decommissioning runbook — a proper deletion path should update all dependents (launch templates, ENIs, RDS instances) before deleting the SG.

---

### CTL.EC2.LT.GHOST.SUBNET.001

**Launch Template References Deleted Subnet**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: CM-8; nist_800_53_r5: CM-8; pci_dss_v4.0: 1.2.1; soc2: A1.2;

Launch template references a subnet that has been deleted. Instance launches fail because the network location does not exist. If the launch template is the source of truth for an Auto Scaling Group's subnet selection, scale-out events fail for any AZ whose subnet was the deleted one. Mixed-subnet ASG configurations still operate in remaining AZs but lose the redundancy they were configured for.

**Remediation:** Update the launch template's subnet reference to a live subnet. If the deleted subnet was retired intentionally, confirm the AZ coverage of the remaining subnets matches the workload's availability requirements (e.g., still multi-AZ). Add the missing subnet back if AZ redundancy was lost.

---

### CTL.EC2.LT.PUBLICIP.001

**Launch Templates Must Not Force Public IP Auto-Assign**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4: 1.2;

EC2 launch templates must not set AssociatePublicIpAddress to true on their network interface configuration. The launch template's network interface block overrides the subnet's MapPublicIpOnLaunch setting: an instance launched from this template into a private subnet (MapPublicIpOnLaunch: false) still receives a public IP because the template forces it. The subnet architecture and the template architecture disagree, and the template wins. Every scale-out event, every replacement launch, every manual launch from this template produces an internet-facing instance even when the subnet was designed to preclude that. The override is invisible to subnet-level controls: AUTOPUBLIC controls report the subnet correctly configured, no NACL or route-table change is required, and the exposure surfaces only after the next launch. The control catches the override at the template level — the only level at which it is actually configured.

**Remediation:** Remove AssociatePublicIpAddress from the launch template's network interfaces.

---

### CTL.EC2.LT.VERSION.STALE.001

**Launch Template Default Version Must Match the Latest Version**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC8.1;

EC2 launch template default version (the version used by ASGs and manual launches that do not pin a specific number) must match the template's latest version. Launch templates are versioned: every edit produces a new version, and the default version pointer is updated separately. When the default lags behind latest, security improvements that were authored into the newer versions are not applied to scale-out events, replacement launches, or any workflow that takes the default. Common drift: version 7 enforces IMDSv2 and is the latest, but the default is pinned at version 5 → every new instance launches with IMDSv1 enabled. Or version 8 updates the AMI for a published CVE fix, but version 6 is default → new instances launch with the vulnerable AMI. The version delta is a measurable governance gap: the work was done but never made authoritative.

**Remediation:** Update the default version to latest after reviewing the version diff.

---

### CTL.EC2.MULTIVPC.ENI.001

**EC2 Instance Has ENIs in Multiple VPCs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7, AC-4; soc2: CC6.6;

EC2 instance has network interfaces (ENIs) attached in more than one VPC. Multi-VPC instances bridge network isolation boundaries — traffic from a less-trusted VPC can reach a more-trusted VPC through the instance's operating system routing. This violates VPC isolation assumptions and creates a lateral movement path that network ACLs and security groups cannot prevent (the traffic never crosses a VPC boundary from the network's perspective). Instances should operate within a single VPC; cross-VPC communication should use VPC peering, Transit Gateway, or PrivateLink.

**Remediation:** Detach the ENI in the secondary VPC and use VPC peering, Transit Gateway, or PrivateLink for cross-VPC communication. If multi-homing is required (e.g., a NAT appliance), document the justification and apply security group rules restricting cross-VPC forwarding.

---

### CTL.EC2.NETWORK.DIRECT.001

**Public Instances Must Be Behind a Load Balancer**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

EC2 instances with public IPs receiving internet traffic must be behind an ALB or NLB. Direct internet-to-instance traffic bypasses DDoS absorption, WAF evaluation, connection rate limiting, and TLS termination that load balancers provide.

**Remediation:** Place the instance behind an ALB or NLB. Remove the public IP and route inbound traffic through the load balancer. Use private subnets for the instance.

---

### CTL.EC2.NETWORK.DUALHOMED.001

**EC2 Instances Must Not Span Multiple Security Zones via ENIs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4: 1.4;

EC2 instances must not have network interfaces in subnets that belong to different security zones (public + private; production + development; data + application). When an instance carries ENIs in two zones, the instance IS the bridge between those zones — the network segmentation that exists between the subnets is defeated by the instance's presence in both. A compromise via the internet-facing ENI provides immediate, in-process access to the internal ENI's subnet, with no firewall rule change required and no traffic crossing a peering or transit gateway that the security team can audit. Dual-homed instances are typically introduced as shortcuts (a one-off jump host, a "temporary" management ENI, an ill-advised database access workaround) and are rarely decommissioned because the service that depends on them looks healthy; meanwhile they constitute a network-segmentation exception that the architecture diagram does not show.

**Remediation:** Remove the cross-zone ENI; route via a properly-policed gateway or peering instead.

---

### CTL.EC2.NETWORK.MULTIPLE.SG.001

**EC2 Instances Should Not Have Excessive Security Groups**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-4;

EC2 instances should attach no more than the configured threshold of security groups (default 5). Security group rules are additive: the effective inbound and outbound access of an instance is the UNION of every rule across every attached SG. A restrictive SG that only permits 443 from a specific CIDR is silently negated when a permissive SG attached to the same instance permits 22 from 0.0.0.0/0 — the instance is then reachable on both ports, and no individual SG inspection surfaces the problem. As the number of attached SGs grows, the effective rule set becomes the cross-product of dozens or hundreds of rules; auditing whether a specific port is exposed requires evaluating every rule of every SG together. Five is a configurable threshold — many architectures legitimately stack base + app + environment + management SGs — but past it, the effective access surface is unauditable in practice.

**Remediation:** Consolidate the rules into fewer SGs or split the workload across instances.

---

### CTL.EC2.NETWORK.SRCDSTCHECK.001

**Source/Destination Check Must Be Enabled on Non-Appliance Instances**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4: 1.4;

EC2 instances that are not NAT gateways, VPN endpoints, or other network appliances must keep source/destination check enabled (the default). When source/destination check is enabled, the instance only processes traffic addressed to its own IP — it cannot act as a router, proxy, or man-in-the-middle. Disabling source/destination check is the single configuration step that turns a normal application instance into a router; it allows the instance to receive and forward traffic addressed to other IPs. On a NAT/VPN/appliance role this is intended. On a standard application instance, it allows the instance to intercept inter-instance traffic, route between subnets bypassing subnet-level controls, and operate as a covert proxy. The control whitelists instances that announce themselves as NAT, VPN, or network appliances; everything else with the check disabled is a finding.

**Remediation:** Re-enable source/destination check, or tag/document the appliance role.

---

### CTL.EC2.NITRO.001

**EC2 Instances Should Use Nitro-Based Instance Types**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-39; soc2: CC6.6;

EC2 instances should run on Nitro-based instance families (C5, M5, R5, T3 and all newer C6/M6/R6/C7/M7/etc. families). Nitro instances provide hardware-enforced isolation between the instance and the hypervisor: the hypervisor is offloaded to dedicated Nitro cards (a smaller software attack surface than the Xen-based families), EBS and networking are handled by separate Nitro hardware (not shared with the hypervisor), and the instance has no path to the underlying host OS. Xen-based families (C4, M4, R4, T2, I3, D2, H1) use a software hypervisor that has been the target of multiple cross-tenant CVEs (XSA-212, XSA-293, XSA-320). Workloads that require the strongest hypervisor isolation guarantees should migrate to a Nitro family.

**Remediation:** Migrate the instance to a Nitro-based instance family (C5/M5/R5/T3 or newer).

---

### CTL.EC2.NITRO.ENCLAVE.001

**Sensitive Workloads Must Use Nitro Enclaves for Cryptographic Isolation**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** mitre_attack: TA0006; nist_800_53_r5: SC-28;

Nitro Enclaves provide an isolated execution environment with no persistent storage, no interactive access, and no external networking. Cryptographic operations performed inside an enclave are protected even if the parent instance is compromised. Applies only to instances tagged requires-enclave=true.

**Remediation:** aws ec2 modify-instance-attribute --instance-id <id> --enclave-options Enabled=true. Requires an enclave-capable instance type (m5, c5, r5 or newer).

---

### CTL.EC2.NITROTPM.001

**NitroTPM-Capable Instances Should Enable NitroTPM**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-7; soc2: CC6.8;

EC2 instances on Nitro families that support NitroTPM should enable it. NitroTPM provides a virtual Trusted Platform Module rooted in Nitro hardware: it produces hardware-backed attestation that the instance booted with the expected configuration (PCR-measured boot chain), it provides cryptographically protected storage for keys (a TPM 2.0 interface that the OS, BitLocker, dm-crypt, and platform attestation services consume directly), and it gives the workload an enrolment identity that survives instance reboot but cannot be cloned to a different instance. NitroTPM is defense-in-depth — most workloads function without it — but for FedRAMP-, FIPS-, and high-attestation deployments it is a baseline expectation. Without NitroTPM, there is no hardware-rooted way to prove the instance was not silently rebooted into a tampered state.

**Remediation:** Re-launch the instance with NitroTPM enabled in the launch template.

---

### CTL.EC2.PATCH.SCAN.STALE.001

**Patch Compliance Scan Not Run Recently**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 2.5; fedramp_moderate: RA-5; hipaa: 164.308(a)(8); nist_800_53_r5: RA-5; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

SSM Patch Manager has not scanned this instance for patch compliance in more than 7 days. The patch compliance status is stale: vendors release new patches continuously, and a scan that ran a week ago cannot tell us whether yesterday's CVE patch is installed. The instance may have been compliant when the last scan ran and non-compliant since, with no evidence of either state. Patch scans are cheap and should run on a daily cadence; a 7-day gap suggests the maintenance schedule is broken or the SSM agent is silently failing scan operations.

**Remediation:** Trigger an immediate `AWS-RunPatchBaseline` scan via SSM Run Command: `aws ssm send-command --document-name AWS-RunPatchBaseline --instance-ids <id> --parameters '{"Operation": ["Scan"]}'`. Investigate why the scheduled scan did not run — check the SSM maintenance window's `Schedule` and execution history, the IAM role's permissions for `ssm:UpdateInstanceAssociationStatus`, and the SSM agent's last ping (which may overlap with `CTL.EC2.SSM.AGENT.STALE.001`).

---

### CTL.EC2.PATCH.WINDOW.INACTIVE.001

**Patch Maintenance Window Not Executed Recently**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 2.5; fedramp_moderate: SI-2; hipaa: 164.308(a)(5)(ii)(B); nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

SSM Patch Manager maintenance window has not executed in more than 30 days. The maintenance window is the mechanism that actually applies patches — a compliance scan identifies missing patches, but the window installs them. When the window has not run, no patches have been installed regardless of what the compliance scan reports. Compliance scans may show "patches pending" but the apply step that resolves pending into installed has not happened. The remediation pipeline is broken even when the detection pipeline reports correctly.

**Remediation:** Investigate the maintenance window's execution history: `aws ssm describe-maintenance-window- executions --window-id <id>`. Common causes are a misconfigured cron schedule, a removed target registration, missing IAM permissions on the maintenance window's service role, or task definitions that have failed and disabled the window. Fix the underlying issue and trigger an immediate run with `aws ssm start-automation-execution` or wait for the next scheduled execution and confirm via the SSM console.

---

### CTL.EC2.POLLUTION.LONGRUNNING.PUBLIC.001

**Long-Running Instance on Stale AMI Has Public IP**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

EC2 instance has been running longer than the age threshold AND has a public IP address. This is the pollution compound: an old instance (likely abandoned or forgotten), with accumulated unpatched vulnerabilities from the stale AMI, directly exposed to the internet. Farris: "EC2 instances that have been running since Barack Obama was president." The compound of CTL.EC2.INSTANCE.AGE.001 (instance age) and CTL.EC2.PUBLIC.001 (public IP) — neither alone captures the distinct risk of an abandoned, exposed, unpatched instance.

**Remediation:** Terminate the instance and rebuild from a current AMI in a private subnet. If the instance must remain running, update the AMI, remove the public IP, and place behind a load balancer or NAT gateway.

---

### CTL.EC2.PROFILE.OVERBROAD.001

**EC2 Instance Profile Must Follow Least Privilege**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.18; nist_800_53_r5: AC-6; soc2: CC6.1;

EC2 instance profiles must not have AdministratorAccess or overly broad permissions. Instance profile credentials are accessible via the metadata service — overprivileged profiles increase the blast radius of credential theft.

**Remediation:** Replace the instance profile's role with a scoped policy granting only the permissions the workload needs. Use IAM Access Analyzer to generate a least-privilege policy from observed API activity.

---

### CTL.EC2.PROFILE.SHARED.001

**EC2 Instances Must Use Per-Instance Instance Profiles**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Each EC2 instance should use a dedicated instance profile not shared with other instances. Shared instance profiles grant every instance using the profile the union of all instances' required permissions, expanding blast radius. A compromise of one instance gives the attacker credentials for every other instance sharing the same profile. ECS (CTL.ECS.TASKROLE.SHARED.001) and Lambda (CTL.LAMBDA.ROLE.SHARED.001) enforce the same principle.

**Remediation:** Create a dedicated IAM instance profile per instance (or per instance group with identical permission needs) scoped to only the permissions that specific workload requires.

---

### CTL.EC2.PUBLIC.001

**EC2 Instances Must Not Have Public IP Addresses**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.1; fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(e)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

EC2 instances should not have public IP addresses unless explicitly required. Public IP assignment exposes the instance to direct internet access, bypassing network perimeter controls.

**Remediation:** Launch instances in private subnets without public IP assignment. Use NAT Gateway or VPC endpoints for outbound internet access. Use ALB or NLB for inbound traffic that requires internet access.

---

### CTL.EC2.SECUREBOOT.001

**UEFI-Capable EC2 Instances Must Enable Secure Boot**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-7; soc2: CC6.8;

EC2 instances booted in UEFI mode must enable Secure Boot. Secure Boot creates a chain of trust from hardware to OS: the UEFI firmware cryptographically validates the bootloader, the bootloader validates the kernel, and the kernel validates kernel modules and drivers. If any link is modified by a bootkit, a rootkit, or a supply-chain compromise, the verification fails and the boot halts. Without Secure Boot, a compromised bootloader or kernel executes before the OS-level security tools (EDR, file integrity monitoring, antimalware) load — making the compromise invisible to every detection layer the organization has invested in. The control fires only on instances that support UEFI: legacy BIOS instances cannot enable Secure Boot, so the finding would not be actionable for them.

**Remediation:** Enable UEFI Secure Boot on the instance and re-launch.

---

### CTL.EC2.SERIALCONSOLE.001

**EC2 Serial Console Access Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-17; owasp_subtractive: S03; soc2: CC6.1; subtractive_tier: deletion;

EC2 Serial Console access must be disabled at the account level unless explicitly needed for emergency debugging. Serial console provides direct TTY access to EC2 instances, bypassing SSH, security groups, NACLs, and all network-layer controls. An attacker with ec2-instance-connect:SendSerialConsoleSSHPublicKey permission and instance-level access can use serial console to interact with the instance OS outside the network path that monitoring tools observe. This gap was discovered through cross-cloud transposition — GCP has CTL.GCP.COMPUTE.SERIALPORT.001 in the Stave catalog but no AWS analog existed despite AWS offering the same capability via EnableSerialConsoleAccess. Account-level toggle — same pattern as CTL.EC2.EBS.DEFAULT.001.

**Remediation:** Disable serial console access: aws ec2 disable-serial-console-access. If serial console is needed for emergency debugging, enable it temporarily and disable after use. Use IAM policies to restrict ec2-instance-connect:SendSerialConsoleSSHPublicKey to break-glass roles only.

---

### CTL.EC2.SG.DEFAULT.RESTRICT.001

**Default Security Group Must Restrict All Inbound and Outbound Traffic**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** aws_security_hub: EC2.2; cis_aws_v3.0: 4.4; nist_800_53_r5: SC-7; owasp_subtractive: S04; subtractive_tier: deletion;

The default security group in every VPC allows all inbound traffic from other members of the same security group and all outbound traffic. Any EC2 instance launched without an explicit security group uses the default — inheriting this permissive posture. Restricting the default to no rules means accidental use results in a non-functional but safe instance.

**Remediation:** Remove all inbound and outbound rules from the default SG in every VPC. Get the default SG ID: aws ec2 describe-security-groups --filters Name=group-name,Values=default Name=vpc-id,Values=<vpc-id>. Revoke all ingress and egress rules.

---

### CTL.EC2.SG.DESCRIBE.RESTRICT.001

**ec2:Describe* Must Be Restricted to Administrative Roles**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1580; nist_800_53_r5: AC-6;

ec2:Describe* permissions must be restricted to administrative roles. Unrestricted ec2:Describe* access exposes the full network topology including VPCs, subnets, security groups, route tables, and network interfaces. Attackers use this information to map the network architecture, identify reachable instances, and plan lateral movement paths.

**Remediation:** Restrict ec2:Describe* to administrative roles only. Replace wildcard ec2:Describe* with the specific describe actions needed by the workload. Apply resource-level conditions or tag-based access control to limit enumeration scope.

---

### CTL.EC2.SG.INGRESS.CIDR.001

**Security Group Inbound Rules Must Not Use Overly Broad CIDR Ranges**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** aws_security_hub: EC2.19; mitre_attack: TA0001; nist_800_53_r5: SC-7;

Security groups with 0.0.0.0/0 inbound rules on ports other than 80/443 expose internal services to the internet. This includes common misconfigurations like opening port 8080, 8443, or custom application ports. HTTP (80) and HTTPS (443) are excluded as legitimate internet-facing ports. All other ports exposed to 0.0.0.0/0 should use specific CIDR ranges.

**Remediation:** Replace 0.0.0.0/0 rules on non-HTTP/S ports with specific corporate IP ranges, security group references, or VPN gateway IPs.

---

### CTL.EC2.SG.RESTRICTED.PORTS.001

**Security Groups Must Not Allow Unrestricted Access on High-Risk Ports**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** aws_security_hub: EC2.14; cis_aws_v3.0: 4.1; mitre_attack: TA0001; nist_800_53_r5: SC-7; owasp_subtractive: S03; subtractive_tier: deletion;

Security groups must not allow unrestricted inbound access on high-risk ports: RDP (3389), Telnet (23), FTP (20/21), VNC (5900), database ports (3306/5432/1433/27017), Redis (6379), and Memcached (11211). Each of these has been the source of high-profile breaches when accidentally exposed to 0.0.0.0/0.

**Remediation:** Remove or restrict rules opening these ports to the internet. Replace 0.0.0.0/0 with specific CIDR ranges (VPN exit IPs, bastion host SG references, or corporate NAT IPs). For database ports, use security group references. For RDP/VNC, use Systems Manager Session Manager instead of direct port exposure.

---

### CTL.EC2.SG.SSH.CIDR.ONLY.001

**All SSH Ingress Rules Use CIDR Sources Instead of Security Group References**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-17; soc2: CC6.6;

Every SSH (port 22) ingress rule on this security group uses a CIDR source — none use security group references. In a bastion architecture, SSH ingress should reference the bastion's security group, not a CIDR range. CIDR-based rules are less precise (they include all IPs in the range, not just the bastion) and do not enforce the bastion as the sole SSH entry point. This control is lower severity than CTL.EC2.SG.SSH.INTERNAL.CIDR.001 because the CIDR might be narrow or external (e.g., a corporate VPN exit IP), but the architectural weakness remains: CIDR-based SSH rules do not bind to the bastion identity.

**Remediation:** Replace CIDR-based SSH ingress rules with security group references. Add an ingress rule: port 22, source sg-bastion. Remove the CIDR rule.

---

### CTL.EC2.SG.SSH.INTERNAL.CIDR.001

**Security Group Allows SSH From Internal CIDR Instead of Bastion Security Group**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** cis_aws_v3.0: 5.1; nist_800_53_r5: AC-17; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Security group allows SSH (port 22) from an internal CIDR range (RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) rather than a specific security group reference. Production instances should accept SSH only from the bastion host's security group, not from broad internal ranges. A rule allowing 10.0.0.0/8 on port 22 bypasses the bastion architecture — any instance in the VPC or peered VPCs can SSH directly. This gap is invisible to existing controls that check only for 0.0.0.0/0: the instance is not internet-exposed, but the bastion is architecturally defeated. Legitimate bastion access uses SG-to-SG references (source = sg-bastion), not CIDR ranges.

**Remediation:** Replace the CIDR-based SSH ingress rule with a security group reference pointing to the bastion host's security group. If SSM Session Manager is available, remove SSH access entirely and use SSM for authenticated, logged shell access.

---

### CTL.EC2.SG.UNUSED.001

**Unused Security Groups Must Be Removed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.1;

Security groups with no attached resources should be removed. Unused SGs with broad rules are latent risks — when accidentally attached, the broad rules take effect immediately.

**Remediation:** Delete the unused security group, or if retention is needed, remove all ingress and egress rules to eliminate latent risk.

---

### CTL.EC2.SNAPSHOT.AMI.DEREGISTERED.001

**EBS Snapshots from Deregistered AMIs Must Be Cleaned Up**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: MP-6; soc2: CC6.5;

EBS snapshots that were created as the backing store for an AMI must be deleted when the AMI is deregistered. AMI deregistration removes the AMI from the launchable inventory but does not delete the underlying snapshots — they remain in the account, continue to incur cost, and remain readable by anyone with ec2:DescribeSnapshots and ec2:CreateVolume on the snapshot. The snapshots typically contain the OS, application binaries, and whatever data was on the EBS volumes at AMI creation time — including secrets baked into the image, customer data on database volumes that were imaged for backup, and credentials on configuration volumes. After deregistration the snapshots are effectively forgotten by the AMI lifecycle yet remain a complete copy of the historical instance state, recoverable to a fresh volume that the attacker mounts and reads.

**Remediation:** Delete the snapshot or re-register the AMI if it is still needed.

---

### CTL.EC2.SNAPSHOT.BLOCKPUBLIC.001

**EBS Snapshot Block Public Access Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; owasp_subtractive: S08; soc2: CC6.1; subtractive_tier: deletion;

EBS snapshot block public access must be set to block-all-sharing at the account level. Without it, any IAM principal with ec2:ModifySnapshotAttribute can make a snapshot public, exposing the full block-level contents of an EBS volume — databases, credentials, application code, and customer data. The account-level toggle is a preventive control that blocks the entire class of public-snapshot exposure regardless of individual IAM permissions. Unlike per-snapshot auditing (CTL.EC2.SNAPSHOT.PUBLIC.001), which detects the symptom after the fact, this control prevents the condition from being created.

**Remediation:** Enable snapshot block public access: aws ec2 enable-snapshot-block-public-access --state block-all-sharing --region <region>. Enable in every region where EBS volumes exist.

---

### CTL.EC2.SNAPSHOT.CROSSACCOUNT.001

**EBS Snapshots Must Not Be Shared with External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

EBS snapshots must not be shared with external AWS accounts unless the snapshot is encrypted and sharing is to a specific authorized account. Unencrypted cross-account snapshot sharing enables data exfiltration — an attacker with ec2:ModifySnapshotAttribute shares a snapshot to their account, then restores it in their environment. ATT&CK technique T1578.001 (Create Snapshot) uses this vector.

**Remediation:** Remove cross-account sharing from the snapshot. If sharing is required, ensure the snapshot is encrypted with a KMS key and share only with specific authorized account IDs.

---

### CTL.EC2.SNAPSHOT.ENCRYPT.001

**EBS Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.2.1; fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

EBS snapshots must be encrypted. Unencrypted snapshots can be shared across accounts or made public, exposing data at rest.

**Remediation:** Copy the snapshot with encryption enabled. Delete the unencrypted snapshot. Enable EBS encryption by default for future snapshots.

---

### CTL.EC2.SNAPSHOT.PUBLIC.001

**EBS Snapshots Must Not Be Publicly Restorable**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: EC2.32; mitre_attack: T1537; nist_800_53_r5: AC-3;

A public EBS snapshot can be copied to any AWS account and mounted as a volume — exposing all data on the volume including OS files, application data, database files, and credentials stored on disk. Unlike S3, public snapshots do not require knowing a URL or bucket name — they appear in public snapshot searches.

**Remediation:** Remove public access from the snapshot: aws ec2 modify-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission --operation-type remove --group-names all. Use an SCP to prevent future public snapshots.

---

### CTL.EC2.SSM.AGENT.STALE.001

**SSM Agent Connection Lost**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 2.5; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; pci_dss_v4.0: 11.5.1; soc2: CC7.1;

EC2 instance is registered with Systems Manager but its agent ping status is `ConnectionLost` — the agent has stopped communicating since the last successful heartbeat. The instance still appears in the SSM inventory and shows up in the SSM console as managed. But Patch Manager cannot deliver patches, Session Manager cannot establish sessions, and Run Command cannot execute commands. The dashboard says "managed"; the operations layer says "unreachable." This is worse than an instance that was never registered with SSM because the unregistered case is visibly unmanaged — this one is invisibly unmanaged.

**Remediation:** Inspect the instance directly: confirm the SSM agent process is running, check VPC endpoints / NAT connectivity to ssm/ssmmessages/ec2messages endpoints, and verify the instance role still has `AmazonSSMManagedInstanceCore`. Restart the agent if the process died, fix network reachability if the endpoints are blocked, or re-attach the IAM role if the permissions were revoked. After the fix, confirm the next ping returns `Online`.

---

### CTL.EC2.SSM.MANAGED.001

**EC2 Instances Must Be Managed by AWS Systems Manager**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7;

EC2 instances must be managed by SSM to enable patching, session management, and compliance checking without SSH. Unmanaged instances require bastion hosts or open SSH ports.

**Remediation:** Attach AmazonSSMManagedInstanceCore IAM policy to the instance profile and ensure the SSM agent is installed.

---

### CTL.EC2.SSM.ROLE.001

**EC2 Instance Has No SSM Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

Running EC2 instance has no instance profile or the instance profile role lacks the AmazonSSMManagedInstanceCore policy. Without SSM permissions, the SSM agent cannot communicate with the Systems Manager service even if installed, leaving the instance unmanageable for patching, inventory, and Session Manager access.

**Remediation:** Attach an instance profile with the AmazonSSMManagedInstanceCore managed policy to the instance. If an instance profile exists, add the policy to its role.

---

### CTL.EC2.SSM.SESSION.LOGGING.001

**SSM Session Manager Must Log All Sessions to S3 or CloudWatch**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** mitre_attack: T1059.009; nist_800_53_r5: AU-12;

SSM Session Manager provides interactive shell access to EC2 instances without SSH keys or open inbound ports. Without session logging, all commands executed through Session Manager leave no audit trail. An attacker who gains ssm:StartSession access can execute arbitrary commands on managed instances without any record of the session content — only the session start/stop is logged in CloudTrail.

**Remediation:** Configure Session Manager preferences to log sessions to S3 or CloudWatch Logs. Enable encryption for session logs. aws ssm update-document --name SSM-SessionManagerRunShell --content file://session-prefs.json --document-version '$LATEST'

---

### CTL.EC2.SSM.SSH.INTERNAL.OPEN.001

**SSM-Managed Instance Accepts SSH From Internal Networks**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-17; soc2: CC6.1;

Instance is SSM-managed but still accepts SSH from internal CIDR ranges. SSM Session Manager provides authenticated, IAM-controlled, fully-logged shell access without any open port. Keeping SSH open from internal CIDRs provides an unlogged alternative path that bypasses SSM's audit trail. Unlike CTL.EC2.KEYPAIR.SSM.PREFERRED.001 (which checks for any SSH access on SSM-managed instances), this control specifically targets internal CIDR-sourced SSH — the bastion bypass pattern that passes all internet-facing controls.

**Remediation:** Close port 22 entirely and use SSM Session Manager for all shell access. If SSH must remain for specific workflows (SCP, debug tooling), restrict the source to the bastion's security group and enable VPC flow logs on the subnet.

---

### CTL.EC2.SUBNET.PUBLIC.IP.001

**Subnets Must Not Automatically Assign Public IP Addresses**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** aws_security_hub: EC2.15; mitre_attack: TA0001; nist_800_53_r5: SC-7;

Subnets configured to automatically assign public IP addresses make every instance launched into them directly internet-reachable. An operator who launches an instance without specifying a private IP gets an unexpected public IP — creating unintended internet exposure. Private subnets require explicit intent to assign a public IP.

**Remediation:** aws ec2 modify-subnet-attribute --subnet-id <id> --no-map-public-ip-on-launch

---

### CTL.EC2.TENANCY.SENSITIVE.001

**Sensitive Workloads Must Not Run on Default (Shared) Tenancy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: SC-39;

EC2 instances tagged as processing sensitive data (HIPAA, PCI, CONFIDENTIAL, FedRAMP, or other compliance indicators) must run on dedicated tenancy or on a dedicated host. Default tenancy shares the underlying physical hardware with instances from other AWS customers. The Nitro hypervisor provides strong isolation, and most compliance frameworks accept default tenancy in practice; but several frameworks and many organizational policies (PCI-DSS internal interpretations, HIPAA Business Associate Agreements, FedRAMP High, and tier-1 financial customer contracts) require hardware that is not shared with other tenants. This control fires only on instances flagged as sensitive — non-sensitive workloads on shared tenancy are not unsafe by themselves. The intent is to catch the mismatch where a workload's compliance classification has tightened (a new HIPAA tag was applied to an existing fleet) without the corresponding tenancy migration.

**Remediation:** Migrate the instance to dedicated tenancy or a dedicated host.

---

### CTL.EC2.TERMINATION.PROTECT.001

**Production EC2 Instances Must Have Termination Protection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1490; nist_800_53_r5: CP-10;

Production EC2 instances must have termination protection enabled to prevent accidental or malicious instance termination via API, console, or CLI.

**Remediation:** aws ec2 modify-instance-attribute --instance-id <id> --disable-api-termination

---

### CTL.EC2.TIMESYNC.EXTERNAL.001

**EC2 Instances Must Use Amazon Time Sync, Not External Unauthenticated NTP**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AU-8, SC-45; soc2: CC7.2;

An EC2 instance gets its clock from an external, unauthenticated NTP source (a public pool such as pool.ntp.org or arbitrary servers reachable over UDP 123) instead of the Amazon Time Sync Service link-local endpoint (169.254.169.123), which is served from the hypervisor with no network path to attack. A network-positioned adversary can delay, replay, or spoof unauthenticated NTP traffic and subtly skew the instance clock. Every time-dependent control on that instance — certificate validity windows, token expiry, log timestamp ordering — inherits the weakness.
The collector folds the instance's chrony/ntpd configuration together with its security-group egress: a `server 169.254.169.123` (Amazon Time Sync) with no outbound UDP 123 to internet-routable space is safe; an external NTP server, OR an egress rule that lets UDP 123 reach the internet (including a "restricted" CIDR like 10.0.0.0/8 whose range still routes to the internet via a NAT gateway), sets `compute.time.external_ntp` true. Stave reads that derived boolean.
Inspired by NCC Group "Time as an Attack Surface" white paper by Andy Davis.

**Remediation:** Configure chrony to use Amazon Time Sync only — `server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4` — remove external `server`/`pool` directives, and remove security-group egress rules allowing UDP 123 to internet-routable destinations. On Amazon Linux 2/2023 this is the default; verify custom AMIs.

---

### CTL.EC2.USERDATA.CREDS.001

**EC2 Launch Configurations Must Not Embed Credentials in User Data**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** mitre_attack: T1552.005; nist_800_53_r5: IA-5;

EC2 user data scripts are executed at instance launch with root privileges. User data is stored in plaintext and is accessible via the metadata service to any process on the instance — including attacker code via SSRF. Credentials embedded in user data (AWS access keys, passwords, API tokens) are trivially extracted from the metadata service at /latest/user-data, CloudFormation template parameters, and EC2 instance configuration APIs. This pattern has been the root cause of multiple credential exposure incidents.

**Remediation:** Remove all credentials from user data scripts. Use IAM instance profiles for AWS API access. Use Secrets Manager or Parameter Store for other secrets, retrieved at runtime by the application.

---

### CTL.EC2.USERDATA.SECRETS.001

**EC2 User Data Must Not Contain Secrets or Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1059.009; nist_800_53_r5: IA-5;

EC2 instance user data is stored in plaintext in the instance metadata and is visible to any process on the instance via the metadata endpoint. Secrets embedded in user data (API keys, database passwords, tokens) are exposed to any compromised process and persist in the instance metadata after launch. User data is also visible in the EC2 console and via ec2:DescribeInstanceAttribute API calls.

**Remediation:** Move secrets to AWS Secrets Manager or SSM Parameter Store (SecureString type). Retrieve secrets at runtime via IAM role credentials rather than embedding in user data scripts.

---

### CTL.EC2.VPC.ENDPOINT.ACCESS.001

**VPC Interface Endpoints Must Have Restrictive Endpoint Policies**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** mitre_attack: TA0010; nist_800_53_r5: AC-4;

VPC interface endpoints without custom policies use the default full-access policy — any principal in the VPC can use the endpoint to reach any resource in the target service. A custom endpoint policy restricts which principals and resources are accessible. For S3 endpoints, restricting access to specific buckets prevents data exfiltration to attacker-controlled buckets via the endpoint.

**Remediation:** Apply a restrictive endpoint policy: aws ec2 modify-vpc-endpoint --vpc-endpoint-id <id> --policy-document file://endpoint-policy.json

---


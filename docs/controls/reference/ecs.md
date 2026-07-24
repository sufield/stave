# Control Reference — ECS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ECS.ALARM.FAILEDLAUNCH.001

**No CloudWatch Alarm for ECS Failed Task Launches**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.2;

No CloudWatch alarm watches ECS task launch failures (DesiredTaskCount above RunningTaskCount sustained, or the SERVICE_TASK_PLACEMENT_FAILURE_NO_VALID_CAPACITY_PROVIDER event-bus signal). Repeated launch failures indicate ghost-reference issues (deleted image, secret, role, subnet — see ECS-2 controls), capacity exhaustion (no EC2 instances or insufficient Fargate capacity), or configuration errors (invalid task definition revision promoted to active). Without an alarm, tasks fail to launch silently; the service stays at reduced capacity and the operator's first signal arrives downstream. Distinct from CTL.ECS.ALARM.TASKCOUNT.001 — that catches running count drops below desired (general degradation); this catches the launch-failure signal specifically, so triage can distinguish "tasks are running but unhealthy" from "tasks won't start at all."

**Remediation:** Create a CloudWatch alarm on the SERVICE_DEPLOYMENT or SERVICE_TASK_START_IMPAIRED event from the ECS event bus, or on a derived metric counting SERVICE_TASK_PLACEMENT_FAILURE events. Wire the alarm to the on-call SNS topic alongside the RunningTaskCount alarm so the two signals together distinguish "running but unhealthy" from "will not launch."

---

### CTL.ECS.ALARM.TASKCOUNT.001

**No CloudWatch Alarm for ECS Service Running Task Count**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.7.2; soc2: CC7.2;

No CloudWatch alarm watches the service's RunningTaskCount metric. RunningTaskCount is the most direct signal of ECS service health: when tasks fail (crash loop, health-check failure, OOM kill), are reclaimed (spot termination, capacity-provider scaling), or fail to launch (ghost references, capacity exhaustion), the running count drops below the desired count. A service with desired=4 running at 1 is at 25% capacity, and the gap may persist until the underlying cause clears or someone notices. An alarm on RunningTaskCount < DesiredTaskCount turns "the service is degraded" into a paged signal at the moment of degradation rather than after users complain. The metric is published by ECS automatically; the alarm has to be configured explicitly per service.

**Remediation:** Create a CloudWatch alarm on the AWS/ECS namespace metric RunningTaskCount with dimensions ClusterName=<cluster>, ServiceName=<service>. Threshold typically Less Than DesiredCount; route the alarm to the service's on-call SNS topic. For services with auto-scaling, also alarm on RunningTaskCount falling below the configured minCapacity to catch policy failures rather than legitimate scale-in events.

---

### CTL.ECS.CLUSTER.DOCKERSOCKET.001

**ECS EC2 Cluster Configuration Permits Docker Socket Mount**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 2.2.5; soc2: CC6.6;

ECS cluster's EC2 launch type configuration permits tasks to mount the Docker socket via hostPath volumes — the ECS agent's volume restrictions are not enabled, or the underlying instance configuration allows the mount. A task with /var/run/docker.sock has full control over the Docker daemon on the host: it can create new containers (including privileged ones with pid=host), inspect every other container's filesystem and environment variables, and stop or delete any container on the host. This is container escape with extra steps. Distinct from CTL.ECS.TASKDEF.HOSTMOUNT.001 — that control checks whether a SPECIFIC task definition mounts the socket; this control checks whether the CLUSTER configuration allows any task to mount it. Both findings can fire on the same workload: the cluster permits the mount, AND some task definition exercises that permission.

**Remediation:** Configure the ECS agent to refuse Docker socket mounts: add the path /var/run/docker.sock to the agent's DOCKER_VOLUME_PATH_DENYLIST (or equivalent instance-level configuration). For workloads that genuinely need Docker API access (CI runners, build agents), move them to a dedicated cluster whose purpose is documented and whose access is restricted, rather than allowing the mount on the general-purpose cluster.

---

### CTL.ECS.CONTAINER.SECCOMP.UNCONFINED.001

**ECS Container Must Not Use Unconfined Seccomp Profile**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 7.27; nist_800_53_r5: CM-7; pci_dss_v4.0: 2.2.1; soc2: CC6.6;

An ECS task definition sets the seccomp profile to Unconfined, explicitly disabling syscall filtering. Unlike omitting the profile (which uses the runtime default on Fargate), setting Unconfined is a deliberate opt-out that removes all kernel-level syscall restrictions. The container can make any kernel syscall, including those used in container-escape exploits (unshare, ptrace, mount). This is a semantic inversion: the presence of a seccomp configuration looks like hardening, but the Unconfined value does the opposite — it weakens the security posture below even the default.

**Remediation:** Set the seccomp profile type to RuntimeDefault (uses the container runtime's default profile) or a custom restrictive profile. On Fargate, omitting the profile entirely also applies the default.

---

### CTL.ECS.EPHEMERAL.KMS.001

**ECS Fargate Ephemeral Storage Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

ECS Fargate tasks with ephemeral storage must encrypt that storage with a customer-managed KMS key. Fargate encrypts ephemeral storage by default with an AWS-managed key, but a CMK provides key policy control, decrypt audit trail, and revocation capability. Without CMK encryption, data written to ephemeral storage during task execution (temp files, intermediate processing data, model artifacts) is encrypted but the account has no independent control over the key lifecycle.

**Remediation:** Set ephemeralStorage.kmsKeyId in the task definition to a customer-managed KMS key ARN. Update the task execution role to allow kms:GenerateDataKey and kms:Decrypt on the key.

---

### CTL.ECS.ESCALATION.CHAIN.001

**ECS EC2-Launch Task Enables Task-to-Instance-Role Escalation**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

The ECS variant of the Doyensec Batch escalation chain. The full chain holds: an EC2-launch-type task on a container instance whose host IMDS is reachable, a task role that can author and run tasks (ecs:RegisterTaskDefinition + ecs:RunTask + iam:PassRole), and a container-instance role with sensitive access. A principal runs a malicious task, it reaches the host IMDS, retrieves the instance role credentials, and uses them against the sensitive resource — escalating from the task role to the privileged instance role.
Each condition alone is a finding (CTL.ECS.IMDS.INSTANCEROLE.001 catches IMDS, CTL.IAM.ESCALATE.PASSROLE.RUNTASK.001 catches the combo); this compound proves all hold. Sensitive instance-role access includes direct data, ecs:* (lateral to other task roles), and iam:PassRole (chain extension). Computed by the shared spec examples/batch-escalation-chain/ (Soufflé + Z3).
Inspired by Doyensec CloudsecTidbits No. 3 (the pattern applies to ECS EC2 launch type). Lab: github.com/doyensec/cloudsec-tidbits.

**Remediation:** Break any one link: restrict IMDS (hop limit 1) / use awsvpc, scope iam:PassRole or remove ecs:RegisterTaskDefinition on the task role, or reduce the container-instance role to least privilege. Fargate removes the IMDS link.

---

### CTL.ECS.EXEC.001

**ECS Exec Must Be Disabled on Production Services**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-17; hipaa: 164.312(a)(1); mitre_attack: T1059; nist_800_53_r5: AC-17; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ECS Exec allows running interactive shell commands in running ECS containers via `aws ecs execute-command`. When enabled on a production service, any IAM principal with ecs:ExecuteCommand can run arbitrary commands inside production containers — equivalent to SSH access. The shell session has the container's filesystem, environment variables (including injected secrets), and the task role's AWS credentials. Attackers with IAM access can use it to establish persistence, exfiltrate data, or pivot to other services reachable from the container's network. Intended for debugging, exec on production removes a layer of separation between operator intent and runtime modification.

**Remediation:** Disable ECS Exec on production services: aws ecs update-service --cluster <cluster> --service <service> --no-enable-execute-command --force-new-deployment. Restrict ecs:ExecuteCommand via IAM policy to break-glass roles with MFA enforcement; audit usage with CTL.ECS.EXEC.AUDIT.001.

---

### CTL.ECS.EXEC.AUDIT.001

**ECS Exec Must Have Audit Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

When ECS Exec is enabled on any service — production or non-production — audit logging must be configured to capture every Exec session. ECS Exec provides interactive shell access to running containers, including read access to the task metadata credential endpoint. Without audit logging, an operator or attacker using Exec leaves no trace of commands executed, files read, or credentials accessed. The control fires whenever exec is enabled and audit logging is off, regardless of environment — a compromised non-production container with unaudited exec is still an unaudited compromise, and dev environments are where attackers pivot from when the prod environment is hardened. Distinct from CTL.ECS.EXEC.001, which gates exec on production specifically; this control gates audit on exec itself.

**Remediation:** Configure ECS Exec audit logging on the cluster: aws ecs update-cluster --cluster <name> --configuration executeCommandConfiguration={logging=OVERRIDE,logConfiguration={cloudWatchLogGroupName=...}}. Route the logs to a CloudWatch log group with adequate retention (see CTL.ECS.LOG.RETENTION.001) and KMS encryption (see CTL.ECS.LOG.ENCRYPT.001). Verify that every exec session opens a log stream and that command output is captured.

---

### CTL.ECS.EXECROLE.OVERBROAD.001

**ECS Execution Role Must Not Have Admin or Overly Broad Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

The ECS execution role (used by the ECS agent for image pulls, log writes, and secret retrieval) must not have AdministratorAccess or overly broad policies. The execution role is distinct from the task role — it operates at the infrastructure level, not the application level.

**Remediation:** Replace with a scoped execution role using the AmazonECSTaskExecutionRolePolicy managed policy. Add only the specific ECR, CloudWatch Logs, and Secrets Manager permissions the task requires.

---

### CTL.ECS.FARGATE.VERSION.001

**ECS Fargate Tasks Must Use Latest Platform Version**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2;

ECS Fargate tasks must use the latest platform version. Fargate platform versions determine the runtime environment including the kernel version, container runtime, and networking stack. Older platform versions do not receive security patches — AWS applies fixes only to the latest platform version. A task pinned to an older platform version runs on an environment with known unpatched kernel and runtime vulnerabilities. Unlike EC2 where operators can patch independently, Fargate platform versions are AWS-managed and the only remediation is upgrading to the latest version. Tasks using LATEST resolve to the current platform version automatically but tasks pinned to specific versions accumulate security debt silently.

**Remediation:** Update the task definition to use the latest Fargate platform version. Set the platform version to LATEST in the ECS service or task definition. For services, update the service to force a new deployment with the latest platform version. Verify workload compatibility with the new platform version in a staging environment before updating production services.

---

### CTL.ECS.GHOST.EXECROLE.001

**ECS Task Definition References Deleted Execution Role**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC8.1;

Task definition's executionRoleArn references an IAM role that has been deleted. The execution role is what the ECS agent assumes to perform launch operations: pull the container image from ECR, write to the CloudWatch log group, and retrieve secrets from Secrets Manager or SSM. With the role deleted, every one of those operations fails before the container is even started. Distinct from CTL.ECS.EXECROLE.OVERBROAD.001 — that control checks whether the role's permissions are too broad; this control checks whether the role exists at all. The two findings are orthogonal: an over-privileged role passes EXECROLE.OVERBROAD's check by being scoped down, but if the scoped-down role is then deleted, this control catches it.

**Remediation:** Re-create the execution role with the AmazonECSTaskExecutionRolePolicy managed policy plus any workload-specific permissions, or update the task definition to reference an execution role that exists. Add a deletion guard on IAM roles that cross-references active task definitions before allowing the role to be deleted.

---

### CTL.ECS.GHOST.SSMPARAMETER.001

**ECS Task Definition References Deleted SSM Parameter**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC8.1;

Container definition uses valueFrom to inject an SSM Parameter Store parameter, but the parameter has been deleted. Same delayed-failure pattern as CTL.ECS.SECRET.GHOST.001 (Secrets Manager) — running tasks that already retrieved the value at their launch time keep working; new task launches fail when the ECS agent calls ssm:GetParameter and gets ParameterNotFound. The task definition appears valid in the console, the parameter ARN is intact, and the failure surfaces only on the next deployment, scaling event, or task replacement. Distinct from the existing SECRET.GHOST.001 because that control is Secrets-Manager-only — SSM parameters are a separate API surface with their own deletion path and their own ARN format.

**Remediation:** Re-create the parameter at the expected name with the appropriate type (SecureString for credentials), or update the task definition to point at a parameter that exists. Add a deletion guard on SSM parameters that cross-references active task definitions before allowing the parameter to be deleted.

---

### CTL.ECS.GHOST.SUBNET.001

**ECS Service References Deleted Subnet**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

ECS service running in awsvpc network mode references one or more subnets that have been deleted. New task launches require an ENI placement in one of the configured subnets; if the subnet is gone the placement fails and the task never starts. Existing running tasks that already received an ENI in the deleted subnet keep operating until the underlying ENI is reclaimed by other VPC operations or the task is replaced. Same delayed-failure shape as CTL.LAMBDA.GHOST.VPC.001 — the configuration shows the subnets that were configured, the VPC console shows those subnets are gone, and the failure surfaces only when ECS tries to place a new task. Different from CTL.ECS.NETWORK.PUBLIC.001 (which checks public-subnet placement) — the subnet may be intentionally private, the problem is just that it doesn't exist anymore.

**Remediation:** Update the service's network configuration to use subnets that exist. If the original VPC layout was intentionally decommissioned, redeploy the service into the replacement subnets and verify ENI placement succeeds. Add a deletion guard on subnets that cross-references active ECS services and Lambda VPC configurations before allowing the subnet to be deleted.

---

### CTL.ECS.GHOST.TASKROLE.001

**ECS Task Definition References Deleted Task Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

Task definition's taskRoleArn references an IAM role that has been deleted. The task role is the application's identity for AWS API calls made from inside the container — distinct from the execution role, which is the ECS agent's identity for launch operations. The task starts successfully (the execution role handles launch); the application code begins running. But the moment the application calls any AWS API using its task role credentials, the call fails with InvalidIdentityToken or AccessDeniedException because the assumed role doesn't exist. The failure mode resembles CTL.EC2.LT.GHOST.PROFILE.001: the resource starts, the workload appears healthy, and every AWS API call from inside fails. Distinct from CTL.ECS.TASKROLE.SHARED.001 (which checks reuse) and CTL.ECS.TASKROLE.ADMIN.001 (which checks privilege) — the role's existence is orthogonal to both.

**Remediation:** Re-create the task role with the appropriate trust policy (ecs-tasks.amazonaws.com) and the application-specific permission boundaries, or update the task definition to point at a task role that exists. Add a deletion guard on IAM roles that cross-references active task definitions before allowing the role to be deleted.

---

### CTL.ECS.IMAGE.001

**ECS Container Images Must Not Use the latest Tag**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC8.1;

ECS container images must use specific tags or digest references, not the latest tag. The latest tag is mutable — a compromised pipeline can push a malicious image that automatically deploys on next task restart. Pinned tags or digests provide immutable references for forensic reproducibility.

**Remediation:** Pin container images to specific version tags or use digest references (@sha256:...) for immutability.

---

### CTL.ECS.IMAGE.DIGEST.001

**ECS Container Images Must Be Referenced by Digest**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-7; soc2: CC6.1;

ECS task definitions must reference container images by digest (repo@sha256:...) instead of mutable tags (repo:v1.2). Tags are mutable — the same tag can point to different images over time. Digest pinning ensures the exact image deployed is the one that was tested and approved.

**Remediation:** Replace the tag reference with a digest reference. Example: 123456789012.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc123... Update CI/CD pipelines to output digest references after image push.

---

### CTL.ECS.IMAGE.GHOST.001

**ECS Task Definitions Must Not Reference Deleted Container Images**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC6.1;

ECS task definitions must not reference container images that don't exist in the ECR inventory. A deleted image with a tag-based reference is reclaimable — an attacker who pushes an image with the matching tag controls what code runs in the container with the task role's full IAM permissions.

**Remediation:** Update the task definition to reference an existing image. Use digest-pinned references for immutable images.

---

### CTL.ECS.IMAGE.UNTRUSTED.001

**ECS Task Definitions Must Reference Images from Trusted Registries**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC6.1;

ECS task definitions must reference container images from the organization's trusted registry set (typically the account's own ECR or a curated approved list). Images from Docker Hub, third- party registries, or unknown sources may contain vulnerabilities, backdoors, or cryptocurrency miners.

**Remediation:** Mirror the required image into the organization's ECR and reference the ECR copy in the task definition. Enable image scanning on the ECR repository to detect vulnerabilities in mirrored images.

---

### CTL.ECS.IMDS.INSTANCEROLE.001

**ECS EC2-Launch-Type Task Can Reach Host IMDS and the Instance Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.6; nist_800_53_r5: CM-6, AC-6; pci_dss_v4.0: 2.2.1; soc2: CC6.6;

An ECS task with EC2 launch type runs on a container instance whose host network is reachable, so the task container can query the host instance metadata service at 169.254.169.254 and retrieve the EC2 container-instance role credentials. That instance role is typically more privileged than the task role. This is distinct from the ECS task metadata endpoint (169.254.170.2, covered by CTL.ECS.METADATA.CREDENTIAL.001): here the task reaches the HOST instance role, the same escalation Doyensec documented for AWS Batch. Fargate tasks have no host IMDS and are out of scope.
The collector resolves container.reaches_host_imds with CTL.EC2.IMDSV2.002 logic (host/bridge networking + hop limit > 1, fail-loud on unknown).
Inspired by Doyensec CloudsecTidbits No. 3 — Messing Around With AWS Batch For Privilege Escalations (the article notes the pattern applies to ECS EC2 launch type). Lab: github.com/doyensec/cloudsec-tidbits.

**Remediation:** Set HttpPutResponseHopLimit=1 on the container instances' launch template, prefer awsvpc over host/bridge network mode, or move the task to Fargate. Restrict the container-instance role to least privilege so a reachable IMDS yields minimal credentials.

---

### CTL.ECS.INCOMPLETE.001

**Complete Data Required for ECS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

ECS task definition or service configuration is missing required properties for security assessment. Re-run the extractor with ecs:DescribeTaskDefinition, ecs:DescribeServices, ecs:ListTaskDefinitions, and ecs:ListServices permissions.

**Remediation:** Re-run extractor with full ECS permissions.

---

### CTL.ECS.LOG.001

**ECS Task Definitions Must Have CloudWatch Logging Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

ECS essential containers must have a log driver configured. Without logging, container stdout and stderr are discarded — invocations, errors, and execution output leave no audit trail. A compromised container generating no logs is forensically invisible.

**Remediation:** Configure the awslogs log driver for all essential containers in the task definition.

---

### CTL.ECS.LOG.ENCRYPT.001

**ECS Container Log Group Not Encrypted with CMK**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

Container's CloudWatch log group is not encrypted with a customer-managed KMS key. CloudWatch encrypts log groups by default with an AWS-owned key — the data is encrypted at rest, but the account has no key policy control, no decrypt audit trail, and no revocation lever. For workloads whose containers emit application logs that may contain PII, error messages with embedded secrets, debug output, or compliance-relevant audit records, the CMK upgrade is the typical baseline. Same architectural pattern as CTL.LAMBDA.LOG.ENCRYPT.001 and the broader family of CMK controls (S3, EBS, RDS, ECR, Lambda env). For ephemeral test workloads or intentionally low- sensitivity logs the default may be acceptable and the finding can be acknowledged in a triage override.

**Remediation:** Associate a customer-managed KMS key with the log group via aws logs associate-kms-key. Update the KMS key policy to grant logs.<region>.amazonaws.com use of the key on behalf of the account. The log group must be re-associated for new log events; existing events remain under the previous encryption.

---

### CTL.ECS.LOG.RETENTION.001

**ECS Container Log Group Has Insufficient Retention**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; hipaa: 164.312(b); nist_800_53_r5: AU-11; pci_dss_v4.0: 10.5.1; soc2: CC7.2;

Container's CloudWatch log group has no retention policy (logs retained forever — costly) or retention shorter than 365 days (forensic horizon insufficient). Same baseline pattern as CTL.LAMBDA.LOG.RETENTION.001 and CTL.RDS.LOG.RETENTION.001 — consistent retention floor across compute services. The 365-day floor is the typical audit-and-compliance horizon: incidents discovered late often require reviewing months of activity, and short retention windows force the team to choose between cost and forensic depth at the moment they have the least time to make a good choice. Distinct from CTL.ECS.LOG.001 (driver configured) and CTL.ECS.TASKDEF.LOG.GHOST.001 (group exists) — both of those check that logs reach a destination; this control checks that the destination keeps them long enough.

**Remediation:** Set retentionInDays on the CloudWatch log group to 365 or higher (3653 = 10 years for long-retention compliance workloads). Use put-retention-policy or set the retention via the log group's CloudFormation/Terraform resource. Verify the change applies to historical streams; existing log events retain the stream's creation-time policy until the group setting is updated.

---

### CTL.ECS.LOG.SIDECAR.001

**ECS Task Definition Has Containers Without Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

Task definition has multiple containers but at least one container — typically a sidecar (envoy proxy, monitoring agent, init container, log forwarder) — has no logConfiguration. The main application container has logging configured, so the existing CTL.ECS.LOG.001 driver-configured boolean reports green; the sidecars' stdout and stderr are silently discarded. Sidecar output carries security-relevant signal — proxy access logs showing every request hitting the application, init container logs showing config rendering and secret-fetching steps, monitoring agent logs revealing health-check decisions and capacity events. Distinct from CTL.ECS.LOG.001 — that control answers "does at least one container in the task have a log driver?"; this one answers "do all containers in the task have a log driver?". The two together describe the full coverage surface.

**Remediation:** Add logConfiguration to every container in the task definition, not just the primary. Use a shared awslogs log group with distinct stream prefixes per container (`awslogs-stream-prefix`) so the streams are distinguishable in CloudWatch. Verify by inspecting each container's stream after a deployment and confirming output appears.

---

### CTL.ECS.METADATA.CREDENTIAL.001

**ECS Tasks Must Restrict Credential Endpoint Access to Required Containers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6(5); hipaa: 164.312(a)(1); nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ECS task definitions must restrict task metadata credential endpoint access (169.254.170.2) to only the containers that require AWS API access. Sidecar containers, init containers, and utility containers that do not call AWS APIs should not have credential endpoint access. Without scoping, every container in the task — including those vulnerable to SSRF — can retrieve the task role's IAM credentials from the metadata endpoint. This is the same attack class as EC2 IMDSv1 credential theft (Capital One) but on containers. Unlike EC2 IMDS which has IMDSv2 token requirements, ECS task metadata has no equivalent token mechanism — the mitigation is restricting which containers can reach the endpoint.

**Remediation:** Configure container-level credential scoping in the task definition. Set credentialSpecs or use task role credential isolation to restrict which containers can access the credential endpoint. Sidecar and utility containers that do not require AWS API access should not have credential endpoint access.

---

### CTL.ECS.MONITORING.INSIGHTS.001

**ECS Cluster Does Not Have Container Insights Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.7.1; soc2: CC7.2;

ECS cluster does not have Container Insights enabled at the cluster level. Container Insights is the AWS-supplied monitoring tier that provides aggregated cluster-level, service-level, and task-level metrics: CPU and memory utilization, network and storage I/O, running task count, pending task count, and per-instance metrics on EC2 launch type. Without it, the cluster has no aggregated monitoring — individual tasks may emit application metrics, but the cluster as a whole is a blind spot for capacity, saturation, and health questions. Container Insights also feeds the Application Auto-Scaling target metrics that ECS-4 SCALING.MISSING.001 expects to be available.

**Remediation:** Enable Container Insights on the cluster: aws ecs put-account-setting --name containerInsights --value enabled (account-level default), or aws ecs update-cluster-settings --cluster <name> --settings name=containerInsights,value=enabled (per-cluster). Container Insights publishes to the /aws/ecs/containerinsights/<cluster> log group; verify metrics arrive in CloudWatch within a few minutes of enabling.

---

### CTL.ECS.NETWORK.001

**ECS Task Definitions Must Not Use Host Network Mode**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

ECS task definitions must not use host network mode. Host networking removes network isolation between the container and the EC2 host — the container shares the host network namespace, can bind to any host port, and can access services on localhost including the ECS agent and metadata endpoint. Use awsvpc mode for per-task network isolation.

**Remediation:** Switch to awsvpc network mode for per-task ENI with dedicated security group.

---

### CTL.ECS.NETWORK.PUBLIC.001

**ECS Tasks Must Not Run in Public Subnets with Public IPs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

ECS tasks must not be placed in public subnets with public IP assignment. Public subnet placement makes the container directly reachable from the internet without traversing a load balancer.

**Remediation:** Move the task to a private subnet. Use an ALB or API Gateway for inbound traffic and a NAT gateway for outbound.

---

### CTL.ECS.PRIV.001

**ECS Containers Must Not Run in Privileged Mode**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-7; hipaa: 164.312(a)(1); nist_800_53_r5: CM-7; pci_dss_v4.0: 2.2.1; soc2: CC6.6;

ECS container definitions must not enable privileged mode. A privileged container has full host device access and kernel capabilities — effectively root on the underlying host. Container escape gives access to EC2 instance role, host networking, and all other containers.

**Remediation:** Remove privileged: true from container definitions. If host device access is required, use specific Linux capabilities instead.

---

### CTL.ECS.ROOT.001

**ECS Containers Must Not Run as Root User**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-7; nist_800_53_r5: CM-7; pci_dss_v4.0: 2.2.1; soc2: CC6.6;

ECS containers must set the user field to a non-root UID. An empty user field means the container runs as whatever user the image defines — frequently root. Running as root inside a container means a process breakout gives root access to the host.

**Remediation:** Set the user field to a non-root UID in the container definition. Build images with a non-root USER directive.

---

### CTL.ECS.SECRET.GHOST.001

**ECS Task Definitions Must Not Reference Deleted Secrets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(d); nist_800_53_r5: IA-5; soc2: CC6.1;

ECS task definitions must not inject secrets from Secrets Manager that have been deleted. A missing secret causes either container startup failure or silent fallback to insecure defaults — hardcoded credentials, unauthenticated connections, or disabled TLS.

**Remediation:** Recreate the secret or update the task definition to reference an active secret.

---

### CTL.ECS.SECRETS.001

**ECS Task Definitions Must Not Pass Secrets as Plaintext Environment Variables**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-5; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: IA-5; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

ECS container definitions must not pass credentials as plaintext environment variables. Plaintext env vars are stored in the task definition, visible in the ECS console, logged in CloudTrail, and accessible to any process in the container. Use Secrets Manager or SSM Parameter Store references via the secrets field instead.

**Remediation:** Move secrets to Secrets Manager or SSM Parameter Store. Reference them via the secrets field in the container definition.

---

### CTL.ECS.SECURITY.CAPABILITIES.001

**ECS Containers Must Not Have Dangerous Linux Capabilities**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.1;

ECS task definitions must not add dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_RAWIO, DAC_OVERRIDE, NET_RAW) and should drop all unnecessary capabilities. Dangerous capabilities grant kernel-level access enabling container escape.

**Remediation:** Remove added capabilities from the task definition. Use linuxParameters.capabilities.drop = ["ALL"] and only add the specific capabilities the application requires.

---

### CTL.ECS.SECURITY.ROOTFS.MOUNT.BYPASS.001

**ECS Container Read-Only Root Filesystem Bypassed by Writable Host Mount**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.1;

ECS container has readonlyRootFilesystem set to true but mounts a host volume with readOnly unset or false. The read-only root filesystem is intended to prevent an attacker who gains code execution from writing malware, modifying binaries, or persisting across restarts — but a writable host volume mount bypasses this protection entirely. The attacker writes to the host path instead of the root filesystem, achieving the same persistence. The container appears hardened (passes CTL.ECS.TASKDEF.READONLY.001) but the mount configuration silently defeats the purpose. The collector pre-computes readonly_root_bypassed_by_mount when readonlyRootFilesystem is true and at least one host-sourced mountPoint has readOnly false or unset.

**Remediation:** Set readOnly to true on all host volume mountPoints, or replace host volumes with ephemeral Docker volumes that are scoped to the container lifecycle. If the container needs a writable path, use tmpfs mounts (which are memory-backed and do not persist to the host).

---

### CTL.ECS.SERVICE.CIRCUITBREAKER.001

**ECS Service Has No Deployment Circuit Breaker**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

ECS service does not have a deployment circuit breaker enabled. Without one, a deployment with a broken task definition (image pull failure, configuration error, application crash loop) keeps trying: ECS replaces healthy old tasks with failing new tasks until the deployment timeout fires — a window that can run hours. During that window the service is degraded, and the broken state is visible in metrics but not stopped automatically. The circuit breaker watches consecutive task launch and health-check failures and halts the deployment when the failure rate breaches a threshold. With auto-rollback enabled (separate setting; see CTL.ECS.SERVICE.CIRCUITBREAKER.NOROLLBACK.001) the service automatically reverts to the previous working task definition.

**Remediation:** Enable the deployment circuit breaker on the service via deploymentConfiguration.deploymentCircuitBreaker.enable=true. Set rollback=true to revert automatically when the breaker fires; without rollback the service is left partially deployed until manual intervention. Verify by deploying a deliberately-broken task definition in a non-prod environment and confirming the breaker stops the rollout.

---

### CTL.ECS.SERVICE.CIRCUITBREAKER.NOROLLBACK.001

**ECS Deployment Circuit Breaker Without Auto-Rollback**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-10; nist_800_53_r5: CP-10; soc2: A1.2;

ECS service has the deployment circuit breaker enabled but auto-rollback is not configured. The breaker will stop a failed deployment — but it leaves the service in a partially-deployed state: some tasks running the old revision, some running the new (failing) revision. Manual intervention is required to roll back to the working revision. Auto-rollback flips that to "breaker fires → service automatically reverts to the previous working task definition." The control fires only when the breaker IS enabled but rollback is off; if the breaker itself is off the more general CTL.ECS.SERVICE.CIRCUITBREAKER.001 fires instead. Both should not fire on the same service at the same time.

**Remediation:** Enable rollback on the deployment circuit breaker: deploymentConfiguration.deploymentCircuitBreaker.rollback=true. The next time a deployment fails the threshold check, ECS will automatically revert to the previous task definition rather than waiting for manual cleanup.

---

### CTL.ECS.SERVICE.MINHEALTHY.001

**ECS Service Minimum Healthy Percent Is Zero**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-10; nist_800_53_r5: CP-10; soc2: A1.2;

ECS service deploymentConfiguration.minimumHealthyPercent is set to 0. During every deployment — successful or failed — the deployment can stop all existing tasks before any new tasks are running. The service goes to zero healthy tasks while the rolling update transitions, which means complete outage during every routine deployment, not just during failures. The default is 100% for both Fargate and EC2 rolling-update deployments — the service maintains at least the desired task count throughout. minimumHealthyPercent of 0 is sometimes set deliberately for stateful services that cannot run in parallel (singleton workers, batch jobs that hold a global lock) — those cases should record the rationale in a triage override on this control rather than leaving the finding unacknowledged.

**Remediation:** Set minimumHealthyPercent to 100 (default) on the service deploymentConfiguration. ECS will keep at least the desired task count healthy throughout deployments. For services that genuinely require singleton execution (workers holding a global lock, batch jobs that cannot run in parallel), document the constraint in a triage override on this finding so the rationale is visible rather than implicit.

---

### CTL.ECS.SERVICE.NETWORKMODE.BRIDGE.001

**ECS Task Definition Uses Bridge Networking**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.4.2; soc2: CC6.6;

Task definition uses networkMode: bridge — the legacy Docker default — instead of awsvpc. Bridge mode shares one host ENI across every container on the instance and exposes container ports through dynamic host port mappings. Two consequences follow. First, the security group attached to the host applies to every container on it; the SG rule that opens port 8080 opens it for every container that maps to that port. Second, all containers share the host's source IP for outbound traffic — VPC flow logs, downstream IP allowlists, and audit attribution can't tell which container made which call. awsvpc mode gives each task its own ENI with its own IP and SG, restoring per-task identity and per-task network control. Distinct from CTL.ECS.NETWORK.001 (host network mode); this control fires on bridge mode specifically and only on EC2 launch type — Fargate requires awsvpc and rejects bridge structurally.

**Remediation:** Change the task definition's networkMode to awsvpc and configure networkConfiguration on the service with the intended subnets and security group. Verify the workload still binds to its ports (awsvpc removes host port mapping; the container port is the listening port).

---

### CTL.ECS.SERVICE.SCALING.MINZERO.001

**ECS Service Auto-Scaling Minimum Is Zero**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-10; nist_800_53_r5: CP-10; soc2: A1.2;

ECS service has Application Auto-Scaling configured with a minimum capacity of 0. The service is allowed to scale to zero running tasks during low-traffic windows. A request that arrives while the service is at zero hits no task and fails — there is nothing to handle it. Scale-from-zero is not instant: a cold start requires task provisioning, image pull, container startup, application warm-up, and health check passing — typically tens of seconds even on Fargate. During that window all incoming requests fail. min=0 is appropriate for genuinely interruptible workloads (test environments, batch consumers that wake on schedule) but not for any service that needs to respond to ad-hoc requests. Severity is high because the failure mode is silent in scaling configuration — the operator sees "auto- scaling configured" without noticing the service can drop to zero.

**Remediation:** Raise minCapacity on the scalable target to at least 1 (preferably 2 for high availability across AZs). For test or batch services that genuinely need to scale to zero, document the rationale in a triage override on this finding rather than leaving the gap implicit.

---

### CTL.ECS.SERVICE.SCALING.MISSING.001

**ECS Service Has No Auto-Scaling Configuration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; soc2: A1.1;

ECS service runs with a fixed desiredCount and no Application Auto-Scaling target tracking, step scaling, or scheduled scaling configured. Two operational consequences follow. Under a traffic spike the fixed count serves all requests and either degrades (queues build, latency rises, errors start) or fails outright depending on the workload's saturation curve; ECS will not add tasks because no scaling policy tells it to. Under low traffic the fixed count keeps running unchanged, accumulating cost for capacity that isn't serving load. For services behind a load balancer, ALB request-count target tracking is the most operationally useful policy; for non-LB services CPU or custom CloudWatch metric tracking is appropriate. Severity is medium because the consequence is operational rather than directly exploitable; for services with strict SLOs or unpredictable load patterns it is worth treating as high.

**Remediation:** Register the service as a scalable target with Application Auto-Scaling and attach a target-tracking policy on a metric the workload responds to — ALBRequestCountPerTarget for LB-backed services, ECSServiceAverageCPUUtilization for compute-bound workloads, or a custom CloudWatch metric for queue-depth-driven services. Set minCapacity above 0 (see SCALING.MINZERO.001) and maxCapacity high enough to absorb realistic spikes.

---

### CTL.ECS.SERVICE.SG.LBONLY.001

**ECS Service Security Group Allows Traffic Beyond Load Balancer**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.4.2; soc2: CC6.6;

ECS service is fronted by a load balancer, but the task security group accepts inbound traffic from sources other than the load balancer's security group — typically the whole VPC CIDR or 0.0.0.0/0. The intended access path is client → LB → task; the LB enforces the WAF, TLS termination, health checking, and request-rate controls that protect the task. When the task SG accepts traffic from anywhere else, every one of those LB-layer protections can be bypassed: an attacker with VPC access reaches the task directly, the LB sees nothing, and the WAF rules don't apply. The control fires only when the service IS behind a load balancer; for services without an LB the SG IS the primary access control and this finding doesn't apply.

**Remediation:** Replace the broad inbound rule on the task SG with a rule referencing the LB's security group as the source. Remove any 10.0.0.0/8, VPC CIDR, or 0.0.0.0/0 inbound rules on the task port. Verify the workload still functions — requests through the LB still arrive, requests bypassing the LB now fail.

---

### CTL.ECS.TASK.NOEXEC.001

**ECS Task Definitions Must Not Use Privileged Mode with Host Network**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1610; nist_800_53_r5: AC-6;

ECS task definitions with both privileged mode and host networking allow container escape to the host instance with full network access. A compromised container with these settings can access the instance metadata service, other containers' network traffic, and the host filesystem — providing arbitrary code execution on the host. This combination is equivalent to running untrusted code directly on the EC2 instance.

**Remediation:** Remove privileged mode from the container definition. Use awsvpc network mode instead of host mode. If root capabilities are required, use specific Linux capabilities instead of full privileged mode.

---

### CTL.ECS.TASKDEF.HEALTHCHECK.MISSING.001

**ECS Container Has No Health Check**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: A1.1;

Container definition has no healthCheck configured. ECS has no in-container signal for whether the container is healthy. A process that is running but unresponsive — deadlocked, stuck in a GC pause, blocked on a downed dependency, leaking connections — keeps the container in RUNNING state and continues to receive traffic; ECS only replaces the container when the process exits. Load-balancer health checks (ALB/NLB) provide partial coverage: they probe the container's listening port from outside and replace the task if the port stops responding. They do not catch in-process problems that don't manifest as port-level failures (slow but successful responses, internal queue backup, lost background workers). The task-level healthCheck runs inside the container and can test deeper invariants. Severity is medium because LB health checks usually catch the worst cases; the in-container check is defense-in-depth.

**Remediation:** Add a healthCheck command to the container definition that tests the application's actual readiness — a curl against an in-process /health endpoint, a CLI subcommand that probes background workers, or a deeper smoke test depending on the workload. Set interval, timeout, retries, and startPeriod appropriately. If a load balancer already health-checks this container at the port level and the team has decided that's sufficient, document that decision in a triage override on this control rather than leaving the finding unacknowledged.

---

### CTL.ECS.TASKDEF.HOSTMOUNT.001

**ECS Container Mounts Sensitive Host Path**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 2.2.5; soc2: CC6.6;

Container definition mounts a host path that exposes the host control plane or kernel interfaces — the Docker socket (/var/run/docker.sock), the process filesystem (/proc), the kernel sysfs (/sys), the device tree (/dev), or the host root (/). The Docker socket case is the worst: a container with /var/run/docker.sock can call the Docker API and create new privileged containers, exfiltrate files from any other container, or stop critical workloads. The proc/sys/dev mounts give direct kernel access from inside the container, and the host-root mount makes the entire host filesystem reachable. The control's heuristic flags any of those specific paths; legitimate hostPath mounts (a known data directory, for example) do not match and do not fire. Fargate does not support hostPath volumes at all, so the predicate cannot match Fargate task definitions.

**Remediation:** Remove the dangerous hostPath mount from the task definition. If the workload genuinely needs Docker API access (a CI runner, a build agent), move that workload to a dedicated host or use a Docker-in-Docker pattern that does not expose the host's control socket. For monitoring agents that need /proc or /sys, use the AWS-supplied container insights agent rather than a hostPath mount, or constrain access via read-only mounts plus a strict capabilities drop.

---

### CTL.ECS.TASKDEF.LOG.GHOST.001

**ECS Container Log Configuration References Deleted Log Group**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

Container definition uses the awslogs log driver with a specific CloudWatch log group name (awslogs-group), but the named log group does not exist. The container starts successfully — ECS does not validate the log group at task start — and the container writes its stdout/stderr to a destination that silently discards every record. The task definition shows logging configured. The CloudWatch console shows no log streams for the container. Operators looking for "is logging on?" see "yes." Operators looking for actual logs find nothing. Same ghost-reference pattern as the other ghost-reference controls — the configuration is intact, the referenced resource has been deleted, the failure mode is silence rather than an error.

**Remediation:** Re-create the missing log group with appropriate retention and KMS encryption settings, or update the task definition to point at a log group that exists. Add a deletion guard on log groups that cross-references active task definitions so the next accidental delete is caught at change time rather than discovered when an investigation needs the logs that no longer exist.

---

### CTL.ECS.TASKDEF.NOMEMLIMIT.001

**ECS Container Has No Memory Limit**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; pci_dss_v4.0: 6.4.1; soc2: A1.1;

Container definition specifies neither memory (hard limit) nor memoryReservation (soft limit). Without a limit, the container is allowed to consume all memory available to the task, and on EC2 launch types, all memory available to the host. A memory leak, a deliberate resource-exhaustion attack, or unexpected load can drive the container's RSS up until the kernel OOM killer activates. Without per-container limits the OOM killer has no way to single out the misbehaving container; it picks a victim by score and frequently kills neighboring containers whose memory was unrelated to the original problem. Setting at least memoryReservation creates a soft floor; setting memory caps the container's hard ceiling. Production task definitions should set both. Severity is medium because the failure mode is operational (one container's bad day kills others) rather than directly enabling exploitation.

**Remediation:** Set memoryReservation (soft limit) and memory (hard limit) on each container in the task definition. Choose values based on observed steady-state memory usage plus headroom — typical pattern is memoryReservation at the p95 RSS and memory at 1.5x to 2x of that. For Fargate, the task-level memory size effectively caps the container as well, but setting per-container memoryReservation still gives the scheduler a hint and improves bin-packing predictability.

---

### CTL.ECS.TASKDEF.READONLY.001

**ECS Container Root Filesystem Is Writable**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-7; nist_800_53_r5: CM-7; pci_dss_v4.0: 2.2.5; soc2: CC6.6;

Container definition has readonlyRootFilesystem set to false or not specified (the AWS default is false). A writable root filesystem lets a compromised container drop new binaries, modify shipped application files, and persist changes — if the filesystem is backed by a volume, the persistence survives container restarts. Read-only root forces the container to use explicitly mounted tmpfs or volumes for everything that must be writable, which both narrows the attack surface for malware drop and makes attacker-introduced state easy to spot. Severity is medium because many applications legitimately need scratch write space (caches, temp files, logs); the operational remediation is readonlyRootFilesystem: true with explicit tmpfs mounts for those needs, not a blanket "never write to disk."

**Remediation:** Set readonlyRootFilesystem: true on the container definition. Identify the directories the application legitimately needs to write to (typically /tmp, /var/log, the app's cache directory) and add explicit tmpfs mounts for each. Re-test the container's startup and main paths to confirm nothing breaks; some images write to /tmp during process startup and need the tmpfs mount before the read-only flag is safe to enable.

---

### CTL.ECS.TASKDEF.REVISION.STALE.SECRETS.001

**ECS Task Definition Old Revisions Contain Plaintext Credentials**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-5; hipaa: 164.312(d); nist_800_53_r5: IA-5; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

Task definition has one or more inactive (older) revisions whose container env vars include plaintext credentials. The current active revision may have been migrated to valueFrom — credentials moved out of env into Secrets Manager or SSM — but ECS task definition revisions are immutable. The plaintext credentials that were in the earlier revisions are still there, visible to anyone with ecs:DescribeTaskDefinition on the older revision ARNs, and preserved in CloudTrail history of past UpdateTaskDefinition events. Migration is incomplete until the credentials are rotated and the affected revisions are deregistered (or treated as compromised). Distinct from CTL.ECS.SECRETS.001 — that control fires on the current state of any revision; this one fires when the *current* state is clean but the *history* is not.

**Remediation:** Treat the credentials in stale revisions as compromised and rotate them — change the database password, regenerate the API token, rotate the access key. Once the old values no longer work, deregister the affected task definition revisions so they cannot be referenced. Update IAM policy on the task definition family to deny ecs:DescribeTaskDefinition on the deregistered revisions if your IAM model allows revision-level granularity.

---

### CTL.ECS.TASKDEF.SECRET.BROKEN.REF.001

**ECS Task Definition Secret Reference Inaccessible to Execution Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Container definition uses valueFrom to reference a Secrets Manager secret or SSM parameter, but the task execution role does not have IAM permission to retrieve that specific resource. The task definition is correctly structured (the operator chose valueFrom over plaintext, the right intent), but the policy attached to the execution role doesn't grant secretsmanager:GetSecretValue or ssm:GetParameter against the named ARN. The task fails at launch with AccessDeniedException. Same cross-resource shape as CTL.LAMBDA.SECRETS.BROKEN.REF.001 — the reference exists, the resource exists, the permission to bridge them does not. Distinct from CTL.ECS.SECRET.GHOST.001 (secret deleted) and CTL.ECS.GHOST.SSMPARAMETER.001 (parameter deleted) — here the resource is fine, the permission is the gap.

**Remediation:** Add the appropriate Get permission to the execution role's policy, scoped to the specific resource ARN(s) referenced by valueFrom — secretsmanager:GetSecretValue for Secrets Manager, ssm:GetParameter (and kms:Decrypt against the parameter's KMS key for SecureString) for SSM. Avoid blanket "*" grants; the cost of scoping the permission to the ARN is small and matches the cost of having created the valueFrom in the first place.

---

### CTL.ECS.TASKDEF.SSM.INSECURE.001

**ECS Task Definition References SSM Parameter as String Type**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

Container definition uses valueFrom to inject an SSM Parameter Store parameter that is stored as String type rather than SecureString. String parameters are stored in plaintext and retrieved in plaintext — no KMS encryption, no audit trail for decrypts, no separation between "who can read the parameter" and "who can read the secret it contains." For parameters carrying credentials, tokens, or any sensitive configuration, SecureString is the correct type. Same detection pattern as CTL.LAMBDA.SECRETS.SSM.INSECURE.001 on a different surface. The task definition's valueFrom is correct in shape; the type of the underlying parameter is the problem.

**Remediation:** Re-create the parameter as SecureString with a customer-managed KMS key (preferred) or the AWS-managed alias/aws/ssm key. Update the execution role's policy to add kms:Decrypt against the parameter's KMS key. Verify the task launches and retrieves the value correctly. Then delete the original String parameter and update the valueFrom reference if the name changed.

---

### CTL.ECS.TASKMETADATA.001

**ECS Task Role Must Follow Least Privilege**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ECS task definitions must not have over-privileged task IAM roles. The task metadata endpoint (TMDEv4) exposes the task role credentials to every container in the task via a link-local HTTP endpoint with no session-based protection. An SSRF vulnerability in any container can retrieve valid short-lived AWS credentials in a single HTTP request. The blast radius of a credential theft is defined entirely by the task role's permissions — wildcard actions or wildcard resources on data-plane services (S3, DynamoDB, RDS, Secrets Manager, KMS) make the credential theft equivalent to account-wide lateral movement. This is the container equivalent of the EC2 IMDS vulnerability that CTL.EC2.IMDSV2.001 addresses, but structurally more exposed because the ECS metadata endpoint has no IMDSv2-style session token protection.

**Remediation:** Scope the task role to only the specific actions and resource ARNs the task requires. Replace managed policies like AmazonS3FullAccess with inline policies scoped to specific resources. Use IAM Access Analyzer to generate a least-privilege policy from actual task activity. If the task does not need AWS API access, remove the task role entirely.

---

### CTL.ECS.TASKMETADATA.002

**PHI ECS Tasks Must Have Scoped Task Roles**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ECS task definitions tagged with data-classification phi or pii must have task roles scoped exclusively to the services required for the task's declared function. For PHI workloads, the task role defines the blast radius of any SSRF exploit — a task processing PHI with a role granting broad S3 access is one SSRF vulnerability away from a HIPAA breach. The task metadata endpoint exposes credentials to every container in the task with no session-based protection. Cross-service access beyond the PHI data path increases the regulatory exposure from a credential theft without providing functional value.

**Remediation:** Scope the task role to only the services in the PHI data path. Remove access to services the task does not require. For PHI tasks accessing S3, restrict to specific bucket ARNs. For tasks accessing DynamoDB, restrict to specific table ARNs. Ensure no wildcard resource ARNs exist on data-plane actions.

---

### CTL.ECS.TASKROLE.SHARED.001

**ECS Task Definitions Must Use Per-Service Task Roles**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Each ECS task definition should have its own dedicated IAM task role. Shared task roles grant every service using the role the union of all services' permissions, expanding blast radius.

**Remediation:** Create a dedicated IAM role per task definition scoped to only the permissions that specific service needs.

---


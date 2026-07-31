# Control Reference — SAGEMAKER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SAGEMAKER.DOMAIN.AUTH.001

**SageMaker Studio Domain Must Use IAM Identity Center Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2, IA-5; soc2: CC6.1;

SageMaker Studio domain uses IAM authentication mode instead of IAM Identity Center (SSO). IAM authentication mode assigns Studio access based on IAM users and roles, which lacks centralized identity governance — no single sign-on, no session duration controls, no MFA enforcement at the identity provider level, and no automatic deprovisioning when a user leaves the organization. IAM Identity Center provides federated access with organization- managed lifecycle controls.

**Remediation:** Recreate the SageMaker Studio domain with AuthMode set to SSO (IAM Identity Center). Note: AuthMode cannot be changed on an existing domain — the domain must be deleted and recreated. Migrate user profiles to the new SSO-backed domain.

---

### CTL.SAGEMAKER.DOMAIN.SHAREDROLE.001

**SageMaker Studio Domain Must Not Use a Single Shared Execution Role**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1), 164.312(a)(2)(i); nist_800_53_r5: AC-2, AC-6; owasp_nhi: NHI5, NHI6; soc2: CC6.1;

SageMaker Studio domain assigns a single execution role to every user profile in the domain. Every data scientist and ML engineer in the domain operates with identical IAM permissions — there is no per-user or per-team scoping. A compromise of any user's Studio session grants the attacker the same blast radius as the broadest user in the domain (typically the role's full s3:* / sagemaker:* / iam:PassRole footprint). The shared-role model is the default Studio onboarding pattern and is almost always a leftover from early platform setup.

**Remediation:** Create per-user-profile execution roles (or per-team roles) scoped to the buckets and services each user's workload requires. Update each UserProfile's ExecutionRole via UpdateUserProfile. Add a permissions boundary at the domain level that caps any per-user role's permissions to the domain's intended scope.

---

### CTL.SAGEMAKER.ENDPOINT.DATACAPTURE.001

**SageMaker Endpoint Must Have Data Capture Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-2, AU-3; soc2: CC7.2;

SageMaker endpoint configuration does not have data capture enabled. Data capture records inference requests and responses to S3, providing the audit trail for model behavior analysis, drift detection, and incident investigation. Without data capture, there is no record of what the model received or returned — making it impossible to detect adversarial inputs, investigate model misbehavior, or demonstrate compliance with data processing requirements.

**Remediation:** Add a DataCaptureConfig to the endpoint configuration with EnableCapture set to true. Configure the destination S3 URI and specify which data to capture (Input, Output, or both).

---

### CTL.SAGEMAKER.ENDPOINT.ENCRYPT.001

**SageMaker Endpoint Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

SageMaker endpoint configuration does not specify a customer- managed KMS key for encrypting data on the ML instances. Without a customer-managed key, data at rest on the endpoint instances uses AWS-managed encryption, which does not allow key rotation control, key policy restrictions, or CloudTrail logging of key usage. For endpoints processing sensitive data, customer-managed KMS keys provide the audit trail and access control required for compliance.

**Remediation:** Specify a KmsKeyId on the endpoint configuration. Use a customer-managed KMS key with a key policy scoped to the SageMaker service principal and authorized administrators.

---

### CTL.SAGEMAKER.ENDPOINT.ENCRYPT.CMK.001

**SageMaker Endpoint Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

SageMaker endpoint configurations with encryption must use a customer-managed KMS key, not the AWS-managed default. Endpoints serve inference on potentially sensitive inputs — the AWS-managed key has a key policy the customer cannot edit and cannot be revoked or rotated on the customer's schedule. Customer-managed keys provide per-tenant key-policy control and per-incident key-revocation capability for data at rest on inference instances.

**Remediation:** Create a new endpoint configuration with a customer-managed KMS key specified via KmsKeyId. SageMaker does not allow changing the encryption key on an existing endpoint configuration.

---

### CTL.SAGEMAKER.ENDPOINT.ISOLATION.001

**SageMaker Endpoint Configuration Must Enable Network Isolation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker endpoint configuration must enable network isolation to prevent model containers from making outbound network calls during inference. Without isolation, a compromised or malicious model container can exfiltrate inference data, cached training data, or model weights to external endpoints. Network isolation at the endpoint level is independent of VPC placement — an endpoint can be in a VPC but still allow outbound calls if isolation is not enabled.

**Remediation:** Set EnableNetworkIsolation to true on the endpoint configuration. This prevents all outbound network access from model containers.

---

### CTL.SAGEMAKER.ENDPOINT.MONITOR.001

**SageMaker Endpoint Configuration Must Have Model Monitoring**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-2, CM-3; owasp_nhi: NHI8; soc2: CC7.2;

SageMaker endpoint configuration has no model monitoring schedule attached. Without a monitoring schedule (data quality, model quality, bias drift, or feature attribution), a deployed endpoint can drift, be silently replaced, or serve adversarial inputs without detection. Model monitoring is the equivalent of CloudTrail for ML inference: the audit surface that distinguishes "the model is doing what it promised" from "the model is doing something useful enough for the dashboard to look healthy."

**Remediation:** Attach a monitoring schedule via CreateMonitoringSchedule targeting the endpoint. At minimum, configure a data- quality monitor with a baseline statistics file. For production endpoints serving regulated data, also attach model-quality and bias-drift monitors.

---

### CTL.SAGEMAKER.ENDPOINT.OVERPERM.S3.001

**SageMaker Endpoint Execution Role Must Scope S3 Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

SageMaker endpoint execution role grants s3:GetObject or s3:* on Resource: * — the inference container can read any object in any bucket in the account. An endpoint processes untrusted input (inference requests from callers) and runs model code that may include custom inference scripts. Broad S3 access lets a compromised endpoint exfiltrate data from any bucket the role can reach.

**Remediation:** Restrict the role's s3:GetObject permission to the specific bucket ARN(s) containing model artifacts. Use resource-level conditions so the endpoint container cannot access data beyond its model artifact bucket.

---

### CTL.SAGEMAKER.ENDPOINT.REDUNDANCY.001

**SageMaker Endpoint Must Use Multiple Instances**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

SageMaker endpoint configurations must use at least two instances per production variant for multi-AZ redundancy. Single-instance endpoints are single points of failure.

**Remediation:** Set InitialInstanceCount to at least 2 per production variant.

---

### CTL.SAGEMAKER.ENDPOINT.STALE.001

**SageMaker Endpoint Must Not Be Idle Beyond Threshold**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-2(3), CM-7; owasp_nhi: NHI1; soc2: CC6.1;

SageMaker inference endpoint has not received traffic within the observation window (default 30 days). Stale endpoints consume compute resources (each instance billed per hour), retain their execution role + KMS-key access, and stay reachable from any caller still holding the endpoint name — a cost liability and a security liability with no active workload. Same shape as CTL.SAGEMAKER.NOTEBOOK.IDLE.001 + CTL.BEDROCK.AGENT.STALE.001 applied to the inference surface.

**Remediation:** DeleteEndpoint + delete the corresponding endpoint configuration if the workload is abandoned. If the endpoint must remain for compliance or warm-restore reasons, UpdateEndpoint to a single t2.medium instance and document the expected idle duration with a reviewed_at tag.

---

### CTL.SAGEMAKER.ENDPOINT.VPC.001

**SageMaker Endpoint Must Use VPC Configuration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker endpoint configuration does not deploy inference containers in a VPC. Without VpcConfig, inference traffic routes through the public AWS network rather than staying within the customer's VPC. Model and training VPC controls exist (CTL.SAGEMAKER.MODEL.VPC.001, CTL.SAGEMAKER.TRAINING.VPC.001) but an endpoint without VPC configuration leaves the inference path exposed even when the model artifact was trained and stored in-VPC. An attacker with network access can intercept model input/output or exfiltrate inference results.

**Remediation:** Add VpcConfig with subnets and security groups to the endpoint configuration. Use CreateEndpointConfig with VpcConfig parameter specifying at least two subnets in different AZs and a security group that restricts inbound to authorized callers only.

---

### CTL.SAGEMAKER.GHOST.MODEL.001

**SageMaker Endpoint Must Not Reference Deleted Model Artifact**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2, CM-8, SI-7; owasp_nhi: NHI1; soc2: CC8.1;

SageMaker endpoint's model configuration references an S3 model-artifact path (ModelDataUrl) that no longer exists. The endpoint may serve stale predictions from a cached model, fail on cold start when the artifact is pulled, or — most dangerously — be silently re-pointed to an attacker- staged artifact if the bucket is later re-created. Same shape as CTL.BEDROCK.AGENT.GHOST.LAMBDA.001 (deleted Lambda in agent action group) applied to SageMaker model artifacts. The collector pre-computes the has_ghost_model_artifact boolean by joining the endpoint configuration's ModelDataUrl against the live S3 object inventory.

**Remediation:** Either (1) UpdateEndpoint to a new endpoint configuration pointing at a live, signed model artifact, or (2) delete the endpoint if the workload is abandoned. Add S3 object- lock to the model-artifact bucket so deleted artifacts cannot be silently overwritten by future writes.

---

### CTL.SAGEMAKER.GHOST.OUTPUT.S3.001

**SageMaker Training Output S3 Bucket Deleted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, SC-28; soc2: CC6.1;

SageMaker training job output is configured to write to an S3 bucket that has been deleted. Training output — model weights, evaluation metrics, training data samples — is lost or, if the bucket is re-registered, exfiltrated to attacker-controlled storage.

**Remediation:** Update the training job or model configuration to use an existing S3 output path. For new jobs: --output-data-config S3OutputPath=s3://<bucket>/.

---

### CTL.SAGEMAKER.MLFLOW.ENCRYPT.001

**SageMaker MLflow App Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-12, SC-28; soc2: CC6.7;

SageMaker managed MLflow tracking server uses AWS-managed default encryption instead of a customer-managed KMS key. MLflow stores experiment metadata, model parameters, and artifact references. Without a customer KMS key, the organization cannot enforce key rotation schedules, audit key usage via CloudTrail KMS events, or revoke access by disabling the key. Default encryption provides at-rest protection but no key governance.

**Remediation:** Create a customer-managed KMS key and configure the MLflow App to use it for artifact encryption.

---

### CTL.SAGEMAKER.MLFLOW.NETWORK.001

**SageMaker MLflow App Must Use VPC-Only Network Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker managed MLflow tracking server is configured with PublicInternetOnly network access. The MLflow UI and API are reachable over the public internet rather than restricted to VPC-internal traffic. MLflow stores experiment metadata, model parameters, metrics, and artifact references — an attacker with network access can enumerate experiments, read hyperparameters (which may encode data characteristics), and discover artifact S3 paths. The tracking server inherits its network access type from the parent SageMaker Domain — if the Domain is PublicInternetOnly, so is MLflow. Switching to VpcOnly requires recreating the Domain.

**Remediation:** Recreate the SageMaker Domain with AppNetworkAccessType set to VpcOnly, then redeploy the MLflow App. All Studio apps inherit the Domain's network access type.

---

### CTL.SAGEMAKER.MODEL.ISOLATION.001

**SageMaker Models Must Enable Network Isolation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker model containers must enable network isolation to prevent outbound network calls during inference. Without isolation, a model container can exfiltrate inference data, training data cached in the model artifact, or model weights to external endpoints.

**Remediation:** Set EnableNetworkIsolation to true on the model.

---

### CTL.SAGEMAKER.MODEL.VPC.001

**SageMaker Models Must Use VPC Configuration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker models must define VpcConfig with subnets and security groups so inference containers communicate through a VPC rather than the public internet.

**Remediation:** Define VpcConfig with subnets and security groups.

---

### CTL.SAGEMAKER.NOTEBOOK.ASSUMEROLE.001

**SageMaker Notebook Execution Role Must Not Have Unscoped sts:AssumeRole**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

SageMaker notebook execution role grants sts:AssumeRole on Resource: * (or on a role outside the notebook's declared cross-account/cross-environment list). A notebook is an interactive, hand-driven identity used by data scientists. Letting the notebook role assume arbitrary other roles is a privilege-escalation primitive: a researcher in a development notebook can step into a production role and access customer data, audit logs, or financial systems without any approval gate. Distinct from CTL.SAGEMAKER.NOTEBOOK.OVERPERM.PASSROLE.001 (which checks iam:PassRole — passing a role to a service the notebook invokes); this control checks sts:AssumeRole — the notebook's identity stepping into another role's identity directly. The collector stamps the assumable target ARN on the asset for chain composition with environment markers.

**Remediation:** Either remove sts:AssumeRole from the notebook role, or restrict the action's Resource to a specific list of non-production role ARNs the research workflow legitimately requires. Add a permissions-boundary on the notebook role that denies sts:AssumeRole for any role tagged environment=production.

---

### CTL.SAGEMAKER.NOTEBOOK.ENCRYPT.001

**SageMaker Notebook EBS Volume Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

SageMaker notebook instances must encrypt the ML storage volume at rest with KMS. Unencrypted volumes expose notebook code, datasets, model artifacts, and credentials cached locally.

**Remediation:** Configure KmsKeyId on the notebook instance.

---

### CTL.SAGEMAKER.NOTEBOOK.ENCRYPT.CMK.001

**SageMaker Notebook Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

SageMaker notebook instances with volume encryption must use a customer-managed KMS key, not the AWS-managed default. The AWS-managed key has a key policy the customer cannot edit and cannot be revoked or rotated on the customer's schedule. Notebook volumes hold code, datasets, model artifacts, and cached credentials — customer-managed keys provide per-tenant key-policy control and per-incident key-revocation capability.

**Remediation:** Create a new notebook instance with a customer-managed KMS key specified via KmsKeyId. SageMaker does not allow changing the encryption key on an existing notebook instance.

---

### CTL.SAGEMAKER.NOTEBOOK.IDLE.001

**SageMaker Notebook Must Not Be Idle Beyond Threshold**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(a)(2)(ii); nist_800_53_r5: AC-2(3); owasp_nhi: NHI1; soc2: CC6.1;

SageMaker notebook instance has been idle for more than 30 days. An idle notebook keeps an interactive identity active with cached credentials, attached EBS volumes containing research data, and any IAM role permissions the notebook carries. The cost is real (notebook compute is billed per running hour) but the security cost is larger: stale notebooks accumulate forgotten data, credentials become unrotated, and the notebook becomes an offboarding gap when the data scientist who owned it leaves. The collector pre-computes the boolean idle assessment from the instance's LastModifiedTime / NotebookInstanceStatus fields.

**Remediation:** StopNotebookInstance now; review the attached lifecycle configuration to enforce auto-stop on future idle periods; delete the notebook + role if the workload is truly abandoned.

---

### CTL.SAGEMAKER.NOTEBOOK.IMDS.001

**SageMaker Notebook Must Require IMDSv2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, SC-7; soc2: CC6.1, CC6.6;

SageMaker notebook instance does not require Instance Metadata Service v2 (IMDSv2). IMDSv1 is vulnerable to SSRF attacks — an attacker who can make the notebook issue HTTP requests (e.g. through a malicious notebook cell or imported library) can steal the notebook's IAM role credentials from the metadata endpoint at 169.254.169.254. IMDSv2 requires a PUT request with a hop-limited token header, blocking most SSRF vectors. AWS added InstanceMetadataServiceConfiguration to CreateNotebookInstance in 2023; notebooks created before that default to IMDSv1.

**Remediation:** Set InstanceMetadataServiceConfiguration.MinimumInstanceMetadataServiceVersion to "2" when creating or updating the notebook instance. For existing notebooks: stop the instance, update with UpdateNotebookInstance setting MinimumInstanceMetadataServiceVersion=2, then restart.

---

### CTL.SAGEMAKER.NOTEBOOK.INTERNET.001

**SageMaker Notebook Must Not Have Direct Internet Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker notebook instances must disable DirectInternetAccess, forcing VPC-only connectivity. An internet-accessible notebook is an interactive Jupyter environment reachable from the public internet with the attached IAM role's credentials available via IMDS.

**Remediation:** Disable DirectInternetAccess and deploy the notebook in a VPC with NAT gateway for outbound connectivity.

---

### CTL.SAGEMAKER.NOTEBOOK.LIFECYCLE.001

**SageMaker Notebook Must Have a Lifecycle Configuration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2, CM-7; owasp_nhi: NHI1; soc2: CC8.1;

SageMaker notebook has no LifecycleConfigName attached. A lifecycle configuration runs scripts at notebook creation/start to enforce hardening (mount restrictions, package allow-listing, idle-timeout enforcement, agent installation). Without one, notebooks come up with stock configuration and cannot be hardened consistently across the team. Lifecycle configurations are also the standard hook for auto-stop and credential rotation; their absence is the upstream cause of several other SageMaker notebook lifecycle failures.

**Remediation:** Create a lifecycle configuration with on-create + on-start scripts that enforce idle-timeout, mount restrictions, and package install policy. Attach it to the notebook via UpdateNotebookInstance.

---

### CTL.SAGEMAKER.NOTEBOOK.OVERPERM.ADMIN.001

**SageMaker Notebook Execution Role Must Not Have Admin Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

SageMaker notebook execution role has AdministratorAccess (or equivalent admin policy) attached. Notebook environments are interactive — root-equivalent permissions on the notebook identity make every Jupyter cell a potential admin operation, and a compromised notebook (stolen credentials, malicious package install, supply-chain attack on a pip dependency) inherits unbounded account access. Notebook roles should be scoped to the specific actions the data-science workflow requires; admin attachment is almost always a leftover from early prototyping.

**Remediation:** Detach AdministratorAccess (and any equivalent customer- managed admin policy) from the notebook execution role. Replace with scoped policies covering only the SageMaker, S3, and IAM:PassRole permissions the research workflow actually needs.

---

### CTL.SAGEMAKER.NOTEBOOK.OVERPERM.PASSROLE.001

**SageMaker Notebook Execution Role Must Not Have Unrestricted iam:PassRole**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

SageMaker notebook execution role grants iam:PassRole on Resource: * — a notebook user can pass any role to AWS services that accept a role parameter (CreateTrainingJob, CreateProcessingJob, CreateEndpoint, Lambda, etc.). The notebook becomes a privilege-escalation primitive: the user attaches a production role to a SageMaker resource the notebook can manipulate. Same shape as CTL.IAM.POLICY.PASSROLE.001 but on the SageMaker notebook's interactive identity, where the blast radius is highest because the notebook is hand-driven.

**Remediation:** Restrict iam:PassRole to a specific list of role ARNs the research workflow needs to assume — typically the SageMaker training/processing-job role and nothing else. Add iam:PassedToService conditions matching only the services the notebook actually invokes (sagemaker.amazonaws.com).

---

### CTL.SAGEMAKER.NOTEBOOK.OVERPERM.S3.001

**SageMaker Notebook Execution Role Must Scope S3 Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

SageMaker notebook execution role grants s3:GetObject (or s3:*) on Resource: * — the notebook user can read any object in any bucket in the account, including production data, secrets, PHI buckets, and audit logs. Notebook execution roles are interactive identities used by data scientists and ML engineers; broad S3 access on these roles is the canonical exfiltration pattern from data-science platforms (one careless boto3 call from a Jupyter cell pulls non-training data into the notebook environment). Scope the role to the specific buckets the research workflow requires.

**Remediation:** Replace Resource: "*" on the role's S3 actions with the explicit list of training-data and model-artifact bucket ARNs the workflow requires. Use s3:prefix conditions to narrow further when only specific prefixes are needed.

---

### CTL.SAGEMAKER.NOTEBOOK.ROOT.001

**SageMaker Notebook Must Disable Root Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.1;

SageMaker notebook instances must disable root access. Root privileges allow users to install arbitrary packages, modify system configuration, and bypass security controls in the notebook environment.

**Remediation:** Set RootAccess to Disabled on the notebook instance.

---

### CTL.SAGEMAKER.NOTEBOOK.VPC.001

**SageMaker Notebook Must Be Deployed in VPC**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker notebook instances must be deployed in a VPC with subnet and security group configuration for private networking.

**Remediation:** Configure the notebook with a subnet_id and security groups.

---

### CTL.SAGEMAKER.PIPELINE.ENCRYPT.001

**SageMaker Pipeline Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.1;

SageMaker pipeline must encrypt artifacts and intermediate data with a customer-managed KMS key. Without CMK encryption, pipeline outputs — trained models, processed datasets, evaluation results — are encrypted only with the default AWS-managed key, which the organization cannot rotate, audit, or revoke independently.

**Remediation:** Configure the pipeline's OutputDataConfig and ProcessingOutputConfig to use a customer-managed KMS key ARN. This gives the organization control over key rotation, access policies, and revocation.

---

### CTL.SAGEMAKER.PIPELINE.ENCRYPT.CMK.001

**SageMaker Pipeline Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

SageMaker pipelines with encryption must use a customer-managed KMS key, not the AWS-managed default. Pipelines chain multiple processing stages, each with its own storage for artifacts, intermediate data, and model outputs. The AWS-managed key has a key policy the customer cannot edit and cannot be revoked or rotated on the customer's schedule. Customer-managed keys provide per-tenant key-policy control and per-incident key-revocation capability across all pipeline stages.

**Remediation:** Configure the pipeline's OutputDataConfig and ProcessingOutputConfig to use a customer-managed KMS key ARN. Update the pipeline definition to reference the CMK.

---

### CTL.SAGEMAKER.PIPELINE.OVERPERM.001

**SageMaker Pipeline Role Must Follow Least Privilege**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

SageMaker pipeline execution roles must be scoped to the minimum permissions required for the pipeline steps. An overprivileged role lets any pipeline step — including steps that process untrusted input — access resources beyond the pipeline's scope: reading secrets, deploying models to production, or modifying IAM policies.

**Remediation:** Scope the execution role to the minimum permissions: S3 read for training data, SageMaker actions for the specific pipeline steps, and CloudWatch for logging. Remove s3:*, sagemaker:*, and iam:PassRole on * from the role policy.

---

### CTL.SAGEMAKER.SPACE.SHARING.001

**SageMaker Space Must Use Private Sharing**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2, AC-6; soc2: CC6.1;

SageMaker Studio space is configured with non-private sharing. A shared space allows multiple user profiles to access the same JupyterLab environment, EBS storage, and running kernels. Code, data, credentials cached in the environment, and any secrets loaded into memory are visible to all users with access to the space. Shared spaces defeat per-user isolation and make it impossible to attribute actions to individual users.

**Remediation:** Set the space's OwnershipSettings.OwnerUserProfileName and SpaceSharingSettings.SharingType to Private. Create per-user spaces instead of shared spaces.

---

### CTL.SAGEMAKER.TRAINING.DATA.CROSSACCOUNT.001

**SageMaker Training Data Source Must Not Cross Account Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: AC-4, AC-6; owasp_nhi: NHI6; soc2: CC6.1, CC6.6;

SageMaker training job's InputDataConfig references an S3 bucket in a different AWS account. Cross-account training data ingestion expands the trust boundary of the model artifacts: the resulting model encodes whatever the source account exposes. If the source bucket is compromised — or legitimately owned by a third party with weaker controls — the model can be poisoned, attribute leakage in inference outputs becomes a cross-account exfil channel, or the trained weights inherit data the local account never approved. Cross-account sources are sometimes legitimate (third-party labelled datasets, partner data exchange) but require explicit scoping that this control surfaces.

**Remediation:** Either replicate the training data into the local account, or pin the source bucket policy to require aws:PrincipalArn matching the training role and add an SCP-level aws:ResourceAccount allow-list for training-data buckets. Document the cross-account dependency in the model card.

---

### CTL.SAGEMAKER.TRAINING.DATA.UNENCRYPTED.001

**SageMaker Training Data Source Must Use Encrypted Reads**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(e)(1), 164.312(e)(2)(ii); nist_800_53_r5: SC-8, SC-13; owasp_nhi: NHI6; soc2: CC6.7;

SageMaker training job ingests its InputDataConfig data source without encryption-in-transit and without explicit KMS encryption-context binding. Distinct from CTL.SAGEMAKER.TRAINING.ENCRYPT.VOLUME.001 (which checks the training instance's local volume encryption at rest) — this control flags the read path between S3 and the training container. Unencrypted training reads expose dataset content on the AWS network path and bind retrieval to the bucket- level KMS key (rather than a job-specific encryption context), so a compromised training role's blast radius spans every bucket the role can decrypt.

**Remediation:** Add aws:SecureTransport=true deny-rule to the source bucket policy. Configure the training job's InputDataConfig with a KmsKeyId and pass an explicit encryption-context entry binding the decrypt to the training-job ARN. Add a key policy permitting only the training role to decrypt with that context.

---

### CTL.SAGEMAKER.TRAINING.ENCRYPT.CMK.001

**SageMaker Training Job Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

SageMaker training job volumes with encryption must use a customer-managed KMS key, not the AWS-managed default. Training jobs process entire datasets — if the training data is PHI, the volume encryption key determines whether the organization can independently rotate, audit, and revoke access. The AWS-managed key has a key policy the customer cannot edit and cannot be revoked on the customer's schedule.

**Remediation:** Specify a customer-managed KMS key via VolumeKmsKeyId in the training job ResourceConfig. Each new training job can use a different key.

---

### CTL.SAGEMAKER.TRAINING.ENCRYPT.INTERCONTAINER.001

**SageMaker Training Must Encrypt Inter-Container Traffic**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

SageMaker distributed training jobs must enable inter-container traffic encryption. Without it, data sent between training containers (gradients, model parameters, training samples) is transmitted in plaintext between nodes.

**Remediation:** Set EnableInterContainerTrafficEncryption to true.

---

### CTL.SAGEMAKER.TRAINING.ENCRYPT.VOLUME.001

**SageMaker Training Job Volumes Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

SageMaker training jobs must encrypt ML storage volumes at rest with KMS. Training volumes contain datasets, intermediate computations, and model checkpoints.

**Remediation:** Set VolumeKmsKeyId in the training job ResourceConfig.

---

### CTL.SAGEMAKER.TRAINING.ISOLATION.001

**SageMaker Training Jobs Must Enable Network Isolation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker training jobs must enable network isolation to prevent training containers from making inbound or outbound network calls. Without isolation, a compromised training container can exfiltrate training data or model artifacts to external endpoints.

**Remediation:** Set EnableNetworkIsolation to true on the training job.

---

### CTL.SAGEMAKER.TRAINING.LOGGING.001

**SageMaker Training Job Must Enable CloudWatch Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-2, AU-3; soc2: CC7.2;

SageMaker training job does not send logs to CloudWatch. Without CloudWatch logging, training job stdout/stderr output is only available during the job's lifetime and is lost after termination. An attacker who tampers with training data or injects malicious code into a training container leaves no persistent audit trail. Bedrock has invocation and agent logging controls (CTL.BEDROCK.LOG.INVOCATION.001, CTL.BEDROCK.AGENT.LOGGING.001) but SageMaker training had no equivalent. The EnableCloudWatchMetrics and CloudWatchLogsGroupName fields on the training job control whether logs persist beyond the job.

**Remediation:** Ensure the training job's IAM role has logs:CreateLogStream and logs:PutLogEvents permissions for the SageMaker log group (/aws/sagemaker/TrainingJobs). SageMaker writes to CloudWatch by default when the role has permissions — verify the role policy does not deny CloudWatch access.

---

### CTL.SAGEMAKER.TRAINING.OUTPUT.ENCRYPT.001

**SageMaker Training Output Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.1;

SageMaker training job output in S3 must be encrypted with a customer-managed KMS key. Training outputs (model artifacts, evaluation metrics, checkpoints) often contain proprietary model weights or derived data. Without CMK encryption, the output is encrypted with the default S3 key but the account has no independent key policy control, no decrypt audit trail, and no ability to revoke access by rotating the key.

**Remediation:** Set OutputDataConfig.KmsKeyId in the training job configuration to a customer-managed KMS key ARN. Update the training role's IAM policy to allow kms:GenerateDataKey and kms:Decrypt on the key.

---

### CTL.SAGEMAKER.TRAINING.OVERPERM.PASSROLE.001

**SageMaker Training Job Role Must Not Have Unrestricted iam:PassRole**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

SageMaker training job execution role grants iam:PassRole on Resource: * — a compromised training container (or a malicious model-framework dependency) can pass any role to AWS services that accept a role parameter. Training workloads should not need iam:PassRole at all in most designs; when they do, the permission should be scoped to the specific roles required (e.g., a downstream HyperParameterTuning role) rather than left open. The attacker-controlled-input + untrusted-code combination on training jobs makes any privilege-escalation primitive here unusually high-impact.

**Remediation:** Remove iam:PassRole from the training job role unless a specific downstream invocation requires it. When required, restrict the action to the specific role ARN and constrain iam:PassedToService to the exact target service.

---

### CTL.SAGEMAKER.TRAINING.OVERPERM.S3.001

**SageMaker Training Job Role Must Scope S3 Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

SageMaker training job execution role grants s3:GetObject (or s3:*) on Resource: * — the training container can read any object in any bucket in the account, not just the declared training data inputs. A training job is the highest-blast- radius non-human identity in an ML platform: it ingests attacker-controlled or attacker-staged data, runs untrusted code (model frameworks, custom scripts), and writes outputs to model-artifact buckets. Scope the training role to the specific input bucket(s) listed in the InputDataConfig and the output bucket listed in the OutputDataConfig.

**Remediation:** Restrict the role's s3:GetObject permission to the bucket ARNs declared in the training job's InputDataConfig + OutputDataConfig. Use s3:prefix conditions matching the declared S3DataSource paths so the training container cannot read sibling prefixes.

---

### CTL.SAGEMAKER.TRAINING.VPC.001

**SageMaker Training Jobs Must Use VPC Configuration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker training jobs must define VpcConfig with subnets so training traffic uses private networking rather than the public internet.

**Remediation:** Define VpcConfig with subnets and security groups.

---

### CTL.SAGEMAKER.USERPROFILE.ROLE.001

**SageMaker UserProfile Must Have Per-User Execution Role**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2, AC-6; owasp_nhi: NHI5, NHI6; soc2: CC6.1;

SageMaker Studio user profile does not specify its own execution role and inherits the domain-level shared role. All actions taken by this user — training jobs, endpoints, S3 access, notebook execution — run with the same IAM permissions as every other user in the domain. Per-user execution roles are the prerequisite for least-privilege in multi-user Studio environments. Without them, CTL.SAGEMAKER.DOMAIN.SHAREDROLE.001 fires at the domain level and this control fires at the user profile level — together they identify both the systemic pattern and the specific user profiles that need role assignment.

**Remediation:** Create a per-user execution role scoped to the user's workload and assign it via UpdateUserProfile --UserSettings ExecutionRole=<arn>.

---


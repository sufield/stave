# Control Reference — EKS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.EKS.ACCESSENTRY.CLUSTERADMIN.BROAD.001

**EKS Access Entry Grants Cluster-Admin Policy To Non-Admin Principal**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EKS Access Entry has the AWS-managed AmazonEKSClusterAdminPolicy or AmazonEKSAdminPolicy associated with a principal that isn't a documented break-glass admin or platform-team role. The policy grants full cluster admin (equivalent to system:masters) at the AWS-side rather than via in-cluster RBAC. Same overprivilege pattern as aws-auth system:masters but on the modern Access Entries surface.

**Remediation:** Replace AmazonEKSClusterAdminPolicy / AmazonEKSAdminPolicy with a custom AccessPolicy scoped to the operations the principal actually needs (read-only, namespace-admin for a specific namespace, etc.). Cluster-admin policies should only attach to principals tagged Purpose=BreakGlass with explicit on-call rotation documented.

---

### CTL.EKS.ACCESSENTRY.GHOST.PRINCIPAL.001

**EKS Access Entry References Deleted IAM Principal**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, CM-2; iso_27001_2022: A.5.15, A.5.16, A.8.32; nist_800_53_r5: AC-3, CM-2, CM-3; soc2: CC6.1, CC8.1, CC7.4;

EKS Access Entries (the modern replacement for aws-auth) bind a principal ARN to a Kubernetes group set and / or policy. When the IAM principal — role or user — is deleted but the Access Entry remains, the entry is a ghost grant. Like aws-auth ghosts, the danger is principal-name reuse: if a future role is created with the same ARN pattern, it silently inherits the original entry's cluster grants.

**Remediation:** Delete the orphan Access Entry via aws eks delete-access-entry --cluster-name <c> --principal-arn <arn>. Audit all Access Entries for the cluster (aws eks list-access-entries) and verify each PrincipalArn still resolves. Add a CloudWatch alarm on DeleteAccessEntry / DeleteUser / DeleteRole correlations so future principal deletions surface their orphan Access Entries.

---

### CTL.EKS.ADDON.GHOST.IRSA.001

**EKS Add-on References Deleted IRSA Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, IA-5; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, IA-5; soc2: CC6.1, CC8.1, CC7.4;

EKS managed add-on (vpc-cni, coredns, kube-proxy, aws-ebs-csi-driver, aws-efs-csi-driver, aws-load-balancer- controller, etc.) has its `serviceAccountRoleArn` pointing at an IAM role that has been deleted. The add-on's pods can't assume the IRSA role on next start / restart; pods running cached credentials continue until they recycle. Same ghost-IRSA pattern as EKS-1 (CTL.EKS.IRSA.OIDC.GHOST.001) but specific to managed add-ons.

**Remediation:** Recreate the IAM role with the documented IRSA trust policy for the add-on (each add-on's docs publish the required policy), or update the add-on configuration via aws eks update-addon --service-account-role-arn <new-arn>. After fixing, restart the add-on's pods to pick up the new role.

---

### CTL.EKS.ADDON.HELMDUAL.001

**EKS Add-on Installed Via Both Helm And EKS Managed Add-ons**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC8.1;

EKS cluster has the same component (vpc-cni, coredns, kube-proxy, aws-load-balancer-controller, ebs-csi-driver, etc.) installed via both EKS managed add-ons and a Helm release. Two reconcile loops contend for the same cluster resources — Helm reconciles to the chart's values, EKS managed-add-on reconciles to the add-on config — and changes from one are silently overwritten by the other on the next reconcile. Configuration drift is constant; troubleshooting becomes "which controller applied this last?"

**Remediation:** Choose one source of truth. EKS managed add-ons are the AWS-recommended path for the core add-ons (vpc-cni, coredns, kube-proxy) — uninstall the Helm release. For other add-ons (aws-load-balancer-controller, cluster-autoscaler), Helm is often preferred — delete the EKS managed add-on. After consolidating to one source, document the choice in cluster IaC.

---

### CTL.EKS.ADDON.SELFMANAGED.001

**EKS Core Add-on Is Self-Managed When Managed Available**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SI-2; iso_27001_2022: A.5.16, A.8.8; nist_800_53_r5: CM-2, SI-2; soc2: CC8.1, A1.2;

EKS cluster's core add-on (vpc-cni, coredns, kube-proxy) is self-managed (installed via Helm / manifests / kubectl apply) instead of via EKS managed add-ons. Self-managed means the team is responsible for tracking compatibility with the cluster version on every upgrade, applying AWS security patches manually, and re-applying after cluster upgrades. EKS managed add-ons handle this automatically and are the AWS-recommended posture for core add-ons specifically.

**Remediation:** Migrate to EKS managed add-ons:
  aws eks create-addon --cluster-name <c> --addon-name
    vpc-cni --addon-version <version>
Use the `--resolve-conflicts OVERWRITE` flag carefully if the cluster already has the self-managed install. After migration, the self-managed Helm release / manifests can be deleted; EKS managed add-ons now own the component.

---

### CTL.EKS.ADDON.VERSION.001

**EKS Managed Addons Must Use the Latest Compatible Version**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: EKS.7; mitre_attack: TA0003; nist_800_53_r5: SI-2;

EKS managed addons (VPC CNI, CoreDNS, kube-proxy, EBS CSI driver) contain the container runtime components that handle pod networking, DNS, and storage. Outdated addon versions may contain known CVEs exploitable for container escape or privilege escalation. The EKS VPC CNI stale NetworkPolicy IP reuse vulnerability demonstrates that addon bugs can silently bypass security controls. Staying current on addon versions is the only mitigation for addon-layer vulnerabilities.

**Remediation:** List available updates: aws eks describe-addon-versions --kubernetes-version <version>. Update each addon: aws eks update-addon --cluster-name <cluster> --addon-name <addon> --addon-version <latest> --resolve-conflicts OVERWRITE

---

### CTL.EKS.ADMISSION.POLICY.MISSING.001

**EKS Cluster Has No Admission Policy Controller**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-7, SI-4; pci_dss_v4.0: 6.3; soc2: CC6.1, CC8.1;

EKS cluster has no admission policy controller deployed (Kyverno, OPA Gatekeeper, ImagePolicyWebhook, or native ValidatingAdmissionPolicy). Without an admission controller, image provenance, CVE blocking, and pod security policies are advisory — the API server admits any pod that passes PSA. Individual image controls detect unsigned or unscanned images after the fact; this control detects the absence of the enforcement mechanism itself.

**Remediation:** Deploy an admission controller. Options: Kyverno (ClusterPolicy resources), OPA Gatekeeper (ConstraintTemplate + Constraint), or native ValidatingAdmissionPolicy (K8s 1.30+). Configure at minimum: image registry allowlist, image signature verification, CVE severity gate. Verify with kubectl get validatingwebhookconfigurations.

---

### CTL.EKS.ALARM.API.ERRORS.001

**EKS Cluster Has No Alarm On API Server Error Rate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4, AU-6; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4, AU-6; soc2: CC7.2, A1.1;

EKS cluster has no CloudWatch alarm on the apiserver_request_total metric scoped to 5xx (server errors) or persistent 4xx (client errors). The API server is the single coordination point for the cluster; degradation there cascades to every controller, scheduler, and operator. Without an alarm, error-rate spikes go unnoticed until downstream symptoms surface (deploys hanging, scaling failures).

**Remediation:** Enable EKS control-plane logs (api type) into CloudWatch Logs, then create a metric filter on apiserver_request_total with code=~"5..". Wire a CloudWatch alarm to SNS for sustained error rate above a threshold (e.g., >1% over 5 minutes). Container Insights enhanced observability also exposes apiserver metrics directly.

---

### CTL.EKS.ALARM.CRASHLOOP.001

**EKS Cluster Has No Alarm On Pod CrashLoopBackOff**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.2, A1.1;

EKS cluster has no CloudWatch alarm on CrashLoopBackOff pod count. CrashLoopBackOff indicates a workload's container can't start — application bug, missing config, deleted dependency, or image-pull failure. Without an alarm, the workload remains unhealthy until someone notices via downstream consumer impact (latency, error rate at the application's consumers).

**Remediation:** Enable Container Insights. Create CloudWatch alarm on pod_status_phase{status="CrashLoopBackOff"} over 5 minutes. Per-namespace dimensions let teams subscribe to alarms scoped to their own workloads.

---

### CTL.EKS.ALARM.ETCD.LATENCY.001

**EKS Cluster Has No Alarm On etcd Request Latency**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.2, A1.1;

EKS cluster has no CloudWatch alarm on etcd_request_duration_seconds p99 latency. etcd serves every API-server read and write; latency there directly determines kubectl + controller responsiveness. AWS-managed control plane handles etcd availability, but tenant-driven cluster shape (large numbers of CRDs, many Secrets, frequent audit-log writes) drives latency that AWS doesn't alert on for the tenant. EKS Container Insights enhanced observability exposes etcd metrics directly.

**Remediation:** Enable Container Insights enhanced observability for the cluster. Create a CloudWatch alarm on etcd_request_duration_seconds p99 above a baseline threshold (typical: >500ms over 5 minutes for healthy clusters). For high-Secret-density clusters, watch the etcd_db_total_size_in_bytes metric — approaching 8GiB triggers etcd compaction issues.

---

### CTL.EKS.ALARM.KUBELET.HEARTBEAT.001

**EKS Cluster Has No Alarm On kubelet Heartbeat Loss**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.2, A1.1;

EKS cluster has no CloudWatch alarm on the kubelet's last-heartbeat-time metric. Kubelet heartbeat loss precedes the node going NotReady (the API server marks the node NotReady after ~40 seconds without heartbeat, by default). An alarm on heartbeat loss gives advance warning before the cluster's documented NotReady-status alarm fires.

**Remediation:** Enable Container Insights enhanced observability plus the kubelet_node_lease_renewal_failure_total metric scrape. Create a CloudWatch alarm on sustained heartbeat-loss rate per node. Pair with the NodeNotReady alarm (which is downstream of heartbeat loss) for layered detection.

---

### CTL.EKS.ALARM.NODE.PRESSURE.001

**EKS Cluster Has No Alarm On Node Memory Disk Or PID Pressure**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.2, A1.1;

EKS cluster has no CloudWatch alarm on per-node MemoryPressure, DiskPressure, or PIDPressure conditions. These conditions trigger pod evictions; by the time they reach steady-state pressure, the node is already evicting workload pods. Operators notice via "why are my pods getting evicted?"; alarms on the leading-indicator pressure conditions give earlier warning.

**Remediation:** Enable Container Insights metrics. Create CloudWatch alarms on each pressure condition: node_memory_pressure, node_disk_pressure, node_pid_pressure (set to >0 over 5 minutes — any node under pressure is operationally significant). PIDPressure especially is rare in healthy clusters; firing PIDPressure typically indicates a fork-bomb-style runaway.

---

### CTL.EKS.ALARM.NODES.NOTREADY.001

**EKS Cluster Has No Alarm On Node-Not-Ready Count**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.2, A1.1;

EKS cluster has no CloudWatch alarm on the count of nodes in NotReady state. Node failures from kubelet crashes, network partitions, kernel issues, or underlying EC2 instance failures show up as NotReady before pods evict. Without an alarm, the cluster loses capacity without notification; pod scheduling hits unscheduable, workloads degrade.

**Remediation:** Enable Container Insights metrics. Create a CloudWatch alarm on cluster_node_count - cluster_node_running_count (the diff is NotReady nodes). Threshold of >1 over 5 minutes catches most node failures while avoiding spurious alarms from rolling node replacements.

---

### CTL.EKS.ALARM.OOMKILLED.001

**EKS Cluster Has No Alarm On Pod OOMKilled Count**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.2, A1.1;

EKS cluster has no CloudWatch alarm on container termination with reason=OOMKilled. OOMKilled indicates the workload exceeded its memory limit (or the node ran out of memory and evicted the pod). Memory leaks, traffic spikes, or undersized limits all manifest as OOMKilled; without an alarm, the workload silently restarts at unpredictable cadence, eating capacity.

**Remediation:** Enable Container Insights. Create CloudWatch alarm on container_termination{reason=OOMKilled} sum over 5 minutes. Dimension by namespace + pod for team-specific routing. Workloads persistently OOMKilling indicate either memory leak (apply heap profiling) or undersized limits (review actual usage and adjust).

---

### CTL.EKS.ALARM.PODEVICTED.001

**EKS Cluster Has No Alarm On Pod Eviction Count**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.2, A1.1;

EKS cluster has no CloudWatch alarm on pod eviction events. Pod evictions occur when a node hits MemoryPressure or DiskPressure (the kubelet evicts to recover capacity), or when preemption fires (a higher-priority pod takes the slot). Persistent evictions indicate capacity sizing problems or scheduler-priority contention; without an alarm, the cluster's effective workload health degrades silently.

**Remediation:** Enable Container Insights. Create CloudWatch alarm on pod_status_phase{status="Failed",reason="Evicted"} over 5 minutes. Persistent evictions point at either capacity issues (scale up nodes / add requests-correctness) or PriorityClass contention (review per-namespace PriorityClass usage).

---

### CTL.EKS.ARGOCD.SPOKE.ADMIN.001

**EKS Hub Argo CD Has Cluster-Admin On All Spoke Clusters**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EKS hub-and-spoke architecture: Argo CD installed on a hub cluster has registered each spoke cluster with cluster-admin credentials (typically via a shared kubeconfig). Compromise of the hub Argo CD yields cluster-admin on every spoke. Per-spoke scoped credentials (AppProject restrictions plus per-cluster ServiceAccount with namespace-scoped RBAC) are the documented pattern; broad shared credentials defeat the multi-cluster security boundary.

**Remediation:** Replace the cluster-admin kubeconfig with per-spoke ServiceAccount credentials. The ServiceAccount should have namespace-scoped permissions matching the apps Argo CD deploys to that spoke. Use AppProject in Argo CD to restrict which apps can target which destinations. Document the per-spoke permission set in the cluster's IaC.

---

### CTL.EKS.AUDIT.RETENTION.SHORT.001

**EKS Control Plane Audit Log Retention Below Compliance Window**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; hipaa: 164.530(j); iso_27001_2022: A.5.33; nist_800_53_r5: AU-11; pci_dss_v4.0: 10.5; soc2: CC7.2;

EKS cluster's control-plane audit logs are stored in a CloudWatch Logs group with retention shorter than the org's regulatory minimum (HIPAA 6 years, PCI-DSS 1 year, SOX 7 years, common generic minimum 13 months). For HIPAA / PCI / SOC2 -scoped clusters, audit logs that age out before the regulatory window create a compliance failure regardless of how thoroughly they were collected.

**Remediation:** Update the CloudWatch Logs group's retention to match the cluster's compliance scope:
  aws logs put-retention-policy
    --log-group-name /aws/eks/<cluster>/cluster
    --retention-in-days 2557
For HIPAA: 2557 days (7 years to be safe). For PCI: 365. For SOC2: 365 minimum. Pair with log archival to S3 Glacier for cost-effective long-retention.

---

### CTL.EKS.AUTH.MIXED.001

**EKS Cluster Has Both aws-auth ConfigMap And Access Entries Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, CM-2; iso_27001_2022: A.5.15, A.8.32; nist_800_53_r5: AC-3, CM-2; soc2: CC6.1, CC8.1;

EKS cluster's authentication mode is set to API_AND_CONFIG_MAP (or has both legacy aws-auth ConfigMap mappings and modern EKS Access Entries) without explicit migration plan. Two sources of truth for cluster authentication is fragile: changes to either surface can change effective access without the operator realizing both must be reviewed; ghost entries can accumulate in either independently; and audits scanning only one surface miss grants from the other. The cluster should commit to one authentication mode and finish the migration.

**Remediation:** Migrate to Access Entries (recommended) or revert to aws-auth-only (rare). For Access Entries migration: (1) audit aws-auth, (2) recreate every mapping as an Access Entry, (3) set authentication_mode to API, (4) clear the aws-auth ConfigMap. Don't switch authentication_mode to API while aws-auth still has mappings — workloads depending on those mappings will lose access.

---

### CTL.EKS.AWSAUTH.GHOST.ROLE.001

**EKS aws-auth ConfigMap References Deleted IAM Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, CM-2; iso_27001_2022: A.5.15, A.5.16, A.8.32; nist_800_53_r5: AC-3, CM-2, CM-3; soc2: CC6.1, CC6.3;

Legacy EKS authentication via the kube-system/aws-auth ConfigMap carries `mapRoles` entries pointing at IAM role ARNs. When an IAM role is deleted but its ARN remains in aws-auth, the mapping is a ghost grant — no live principal can use it, but the ConfigMap records say the cluster trusts it. If the role ARN is later recreated by a different team / account using the same name pattern, the new role inherits the cluster mapping. Same ghost-reference pattern as IAM cross-account principal ghosts; uniquely dangerous on EKS because aws-auth is the historical source-of-truth for cluster-admin mappings.

**Remediation:** Remove the orphan mapping from the cluster's aws-auth ConfigMap (kubectl edit configmap aws-auth -n kube-system). For each mapping, verify the IAM role still exists. Pair with an SCP / IaC drift check that prevents future ghost mappings from accumulating. Long-term, migrate from aws-auth to EKS Access Entries (which surface ghost references via the EKS API rather than only via the in-cluster ConfigMap).

---

### CTL.EKS.AWSAUTH.MASTERS.BROAD.001

**EKS aws-auth Maps Broad IAM Role To system:masters**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EKS aws-auth ConfigMap maps an IAM role to the Kubernetes `system:masters` group via mapRoles. system:masters is the cluster-admin equivalent — full unrestricted access to every resource in every namespace. Mapping broad-scoped IAM roles (workload roles, deployment roles, CI service roles) to this group is the most common path to silent cluster-admin privilege expansion. Should only be reserved for a break-glass admin role, never for service or workload roles.

**Remediation:** Remove the system:masters mapping. Replace with a scoped Kubernetes RBAC group that grants only the operations the role needs (typically a custom ClusterRole for read-only or namespace-scoped access). system:masters should be reserved for break-glass admin roles tagged Purpose=BreakGlass with explicit on-call rotation documented.

---

### CTL.EKS.AWSAUTH.UNTRUSTED.ACCOUNT.001

**EKS aws-auth Maps Role From Account Outside Organization**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-4, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3, CC6.6;

EKS aws-auth ConfigMap (or Access Entry) maps an IAM role from an account outside the AWS Organization. External accounts can authenticate to the cluster as whatever Kubernetes group the mapping grants — often system:masters or another high-privilege group. Same risk as cross-account IAM grants but at the cluster authentication layer; harder to audit because the account ID lives inline in the ConfigMap.

**Remediation:** Remove the cross-org mapping. For legitimate external collaboration, use IAM Identity Center or AWS SSO with org-scoped trust rather than inline cross-account aws-auth mappings. If the mapping is required, document it with a justification annotation in the ConfigMap and pair with a CloudTrail alarm on cluster-config changes for the mapped role's account ID.

---

### CTL.EKS.CLUSTER.VERSION.001

**EKS Cluster Kubernetes Version Must Be Within Support Window**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: EKS.6; mitre_attack: TA0003; nist_800_53_r5: SI-2;

AWS supports each EKS Kubernetes minor version for approximately 14 months. Clusters on end-of-life versions receive no security patches — known CVEs in the Kubernetes control plane remain unpatched indefinitely. Kubernetes releases security patches only for the current and two previous minor versions. A cluster more than 2 minor versions behind cannot receive patches for newly disclosed CVEs. EKS auto-upgrades unsupported versions — often causing unexpected breaking changes.

**Remediation:** Check current version: aws eks describe-cluster --name <cluster> --query 'cluster.version'. Upgrade: aws eks update-cluster-version --name <cluster> --kubernetes-version <target>. Then upgrade node groups.

---

### CTL.EKS.CONTROL.PLANE.AUDIT.001

**EKS Cluster Must Have Audit Logs Enabled and Delivered to CloudWatch**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_eks: 2.1; mitre_attack: TA0005; nist_800_53_r5: AU-2;

EKS audit logs record all Kubernetes API server requests — who called which API, with what arguments, and the result. Without audit logs delivered to CloudWatch, there is no record of kubectl exec sessions, Secret reads and writes, RBAC policy modifications, or ServiceAccount token creations. This control verifies audit log delivery to CloudWatch — logs enabled but not delivered are useless for incident response.

**Remediation:** Enable audit logging: aws eks update-cluster-config --name <cluster> --logging '{"clusterLogging":[{"types":["audit"],"enabled":true}]}'. Verify the log group exists in CloudWatch.

---

### CTL.EKS.COREDNS.AUTOSCALE.001

**EKS CoreDNS Has No Autoscaling Configured On Large Cluster**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.6; nist_800_53_r5: SC-5; soc2: A1.1, CC7.2;

EKS cluster's CoreDNS deployment has the default 2 replicas without HPA / cluster-proportional-autoscaler on a cluster with >50 nodes or >500 pods. CoreDNS serves every pod's DNS lookups; under high cluster density, 2 replicas become a bottleneck. Spike traffic produces DNS resolution timeouts, which manifest as intermittent application failures (cache miss + DNS timeout pattern). AWS publishes cluster-proportional-autoscaler as the documented fix.

**Remediation:** Deploy cluster-proportional-autoscaler for CoreDNS:
  kubectl apply -f
    https://github.com/kubernetes-sigs/
    cluster-proportional-autoscaler/...
Configure scaling parameters (`coresPerReplica: 256, nodesPerReplica: 16`). Alternative: HPA on CoreDNS deployment with CPU target. AWS-recommended for production EKS clusters above 50 nodes.

---

### CTL.EKS.CSI.EBS.NOIRSA.001

**EKS EBS CSI Driver Has No IRSA Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EKS EBS CSI driver's ServiceAccount has no IRSA annotation linking it to an IAM role with EBS permissions. The driver's pods fall back to the node instance profile for AWS credentials — which gives the driver whatever the node role permits, and gives every other pod on the node those same EBS permissions via the IMDS path. Per-driver IAM scope defeated; cross-pod credential leakage on shared node profiles.

**Remediation:** Create an IAM role with the AmazonEBSCSIDriverPolicy (AWS-managed minimal policy). Trust policy must include the cluster's OIDC issuer + sub for the ebs-csi-controller-sa ServiceAccount. Annotate the SA:
  kubectl annotate sa ebs-csi-controller-sa -n
    kube-system
    eks.amazonaws.com/role-arn=<role-arn>
Restart the controller deployment to pick up IRSA.

---

### CTL.EKS.CSI.EFS.NOIRSA.001

**EKS EFS CSI Driver Has No IRSA Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EKS EFS CSI driver's ServiceAccount has no IRSA annotation. Same posture as the EBS variant — pods fall back to the node instance profile, EFS permissions leak across pods on the same node. EFS CSI permissions cover access-point management and mount target operations, both of which can be abused (cross-tenant access-point creation, mount hijacking).

**Remediation:** Create an IAM role with the AmazonEFSCSIDriverPolicy (AWS-managed minimal policy). Trust policy must include the cluster's OIDC issuer + sub for the efs-csi-controller-sa ServiceAccount. Annotate the SA and restart the controller deployment.

---

### CTL.EKS.DELETEPROT.001

**EKS Clusters Must Have Deletion Protection Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

EKS clusters must enable deletion protection to prevent accidental or unauthorized cluster removal. Without protection, automation errors or a compromised administrator can delete the cluster control plane, causing immediate availability loss, orphaned node groups, and data in etcd becoming permanently inaccessible.

**Remediation:** Enable deletion protection via aws eks update-cluster-config --name <cluster> --deletion-protection.

---

### CTL.EKS.DR.KMS.SINGLEREGION.001

**EKS DR Cluster Uses Single-Region KMS Key Without Multi-Region Replication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9, SC-12; iso_27001_2022: A.5.30, A.8.24; nist_800_53_r5: CP-9, SC-12, SC-28; soc2: A1.2, CC6.1;

EKS DR cluster's etcd encryption uses a regional KMS key in the DR region without a corresponding multi-region key linkage to the primary region's CMK. On failover, etcd Secrets restored from the primary cluster's backup were encrypted with the primary region's CMK; without multi-region key replication, the DR cluster can't decrypt them. The restore appears to succeed; pod startup fails because Secrets can't be read.

**Remediation:** Use AWS KMS multi-region keys for etcd encryption: create primary key in source region, replicate to DR region, configure both clusters to use their respective regional replica of the same multi-region key. Backups encrypted with one replica decrypt cleanly with the other. Alternative: use Velero's KMS integration with per-region keys + re-encrypt-on-restore — slower but explicit.

---

### CTL.EKS.DR.WARMUP.001

**EKS DR Cluster Has Zero Workloads**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-7, CP-9, CP-10; iso_27001_2022: A.5.30, A.8.13; nist_800_53_r5: CP-7, CP-9, CP-10; soc2: A1.1, A1.2, CC7.4;

EKS DR (disaster recovery) cluster — typically identified by tag `Purpose=DR` or by being the failover target in Route 53 weighted records — has zero workloads deployed (no Deployments, StatefulSets, DaemonSets serving traffic). When failover triggers, the cluster needs full cold- restore from backups before it can serve any traffic. RTO / RPO assumptions in the DR plan rarely match cold-restore reality.

**Remediation:** Either deploy minimal warm replicas of critical workloads to the DR cluster (typically 1-2 replicas at low resource requests, ready to scale up on failover), or document the cold-restore RTO and validate it against the org's RTO objectives. Cold restore from Velero backups is typically 30+ minutes for clusters of moderate size; warm replicas reduce this to minutes (HPA scales to handle traffic).

---

### CTL.EKS.EBS.ORPHAN.001

**EKS Has Detached EBS Volumes From Terminated Worker Nodes**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: CM-2, CM-8; soc2: CC8.1;

EKS account has EBS volumes tagged `kubernetes.io/cluster/<name>` in `available` state (not attached to any instance) where the volume's origin instance has been terminated. The volume represents former workload state from a now-deleted node. CSI-managed volumes typically clean up on node termination; manually-created or migration-era volumes often don't. Cost accumulates per unattached volume.

**Remediation:** Snapshot the volumes (preserves data if needed), then delete via aws ec2 delete-volume. Audit via:
  aws ec2 describe-volumes
    --filters Name=status,Values=available
              Name=tag-key,Values=kubernetes.io/cluster
Set up a recurring CloudWatch Events / Lambda to alert on / auto-delete EKS-tagged orphan volumes after a documented retention period.

---

### CTL.EKS.ECR.PULL.PUBLIC.GALLERY.001

**EKS Workload Pulls From AWS ECR Public Gallery Without Mirror**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SR-3; iso_27001_2022: A.5.16, A.8.30; nist_800_53_r5: CM-2, SR-3; soc2: CC6.1, CC8.1;

EKS workload pulls an image from public.ecr.aws (AWS ECR Public Gallery) directly rather than mirroring through the org's private ECR. ECR Public is operated by AWS but anyone can publish to it under their own namespace; pulls are subject to rate limits, the same supply-chain risks as any public registry, and the org has no scan-on-push visibility into images they didn't build. Mirror through private ECR for security and rate-limit predictability.

**Remediation:** Mirror the image into the org's private ECR via skopeo / crane. Configure ECR scan-on-push on the private mirror. Update workload manifests to reference the private ECR copy. For images updated frequently upstream, automate the mirror via a Lambda triggered by CodePipeline / scheduled rebuild.

---

### CTL.EKS.ECR.REPLICATION.GAP.001

**EKS Cluster Pulls Images Without ECR Replication To DR Region**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9, CM-2; iso_27001_2022: A.5.30, A.8.13; nist_800_53_r5: CP-9, CM-2; soc2: A1.2, CC8.1;

EKS cluster — primary or DR — pulls images from ECR repositories that aren't replicated to the cluster's region. Primary-region clusters work fine; DR clusters in different regions can't pull the same images during failover because ECR replication wasn't configured. Pods restored to DR fail ImagePullBackOff. The DR plan looked complete on paper; failover reveals the cross-region image gap.

**Remediation:** Configure ECR cross-region replication (Replication Configuration) from the primary region to all DR regions. Verify replication via aws ecr describe-replication-configuration. For workloads with private mirror of upstream images (see EKS-7), the mirror process must push to all regions. Test by pulling on the DR cluster.

---

### CTL.EKS.ECR.SCAN.EXPORT.001

**EKS ECR Scan Findings Not Exported To Security Hub**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: RA-5, SI-4; iso_27001_2022: A.5.16, A.8.8, A.8.16; nist_800_53_r5: RA-5, SI-4; soc2: CC7.2, CC8.1;

EKS cluster's ECR repositories scan-on-push (covered by CTL.ECR.SCAN.001) but the scan findings aren't exported to AWS Security Hub or another central vulnerability dashboard. Findings stay siloed in the ECR console; ops teams running their dashboards against Security Hub don't see container CVEs alongside other findings. Coverage looks complete per-service but is fragmented for operators.

**Remediation:** Enable Security Hub in the region. Enable the Inspector integration with Security Hub (Inspector is the native AWS service that scans ECR images and forwards findings). Verify findings appear:
  aws securityhub get-findings --filters
    ProductName=Inspector
Create a Security Hub insight on Severity=CRITICAL+HIGH for routing to the on-call queue.

---

### CTL.EKS.ENDPOINT.PRIVATE.001

**EKS Clusters Must Enable Private Endpoint Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; owasp_subtractive: S03; soc2: CC6.6; subtractive_tier: deletion;

EKS clusters must enable private endpoint access so kubectl and API traffic can use a VPC-resolved private endpoint. Without private access, all control plane traffic traverses the public internet, expanding the attack surface and adding an internet dependency for cluster management.

**Remediation:** Enable private endpoint access via aws eks update-cluster-config --name <cluster> --resources-vpc-config endpointPrivateAccess=true.

---

### CTL.EKS.FARGATE.DAEMONSET.001

**EKS DaemonSet Selector Overlaps With Fargate Profile Selector**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: CM-2, SI-4; soc2: CC7.2, A1.1;

EKS cluster has a DaemonSet whose pod selector matches a namespace covered by a Fargate profile. Fargate doesn't support DaemonSets — pods scheduled to Fargate are one-per-task, not one-per-node. The DaemonSet's pods selected for Fargate-covered namespaces never schedule; the DaemonSet remains "0 of N nodes" and the workload the DaemonSet was meant to run (log forwarding, monitoring agents, security daemons) silently doesn't run for Fargate-targeted pods.

**Remediation:** Fargate workloads need their per-pod equivalent of the DaemonSet via sidecars (logging via Fluent Bit sidecar, monitoring via per-pod agent) rather than a DaemonSet. Add the namespace where the DaemonSet needs to schedule to the Fargate profile selector's exclusion list (or move the DaemonSet's targeted workloads off Fargate). Audit the cluster: DaemonSets + Fargate profiles together require explicit per-pod instrumentation for the workloads the DaemonSet would have served.

---

### CTL.EKS.FARGATE.PROFILE.OVERPRIV.001

**EKS Fargate Profile Pod Execution Role Is Overprivileged**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EKS Fargate profile's pod execution role has IAM permissions beyond the documented Fargate runtime requirements. The pod execution role is what AWS uses to provision the Fargate task — pull container images from ECR, write logs to CloudWatch, and bootstrap pod networking. AWS publishes `AmazonEKSFargatePodExecutionRolePolicy` with the precise permission set; broader roles grant pods (or whoever assumes the role) more than they need.

**Remediation:** Replace the role's policies with AmazonEKSFargatePodExecutionRolePolicy (the AWS-managed minimal policy). For pods needing additional AWS permissions, grant them via IRSA on the workload's ServiceAccount — not via the pod execution role, which is shared across every pod the profile selects.

---

### CTL.EKS.FARGATE.SELECTOR.WIDE.001

**EKS Fargate Profile Selector Matches All Pods Or Default Namespace**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: CM-2, AC-3; soc2: CC8.1, A1.1;

EKS Fargate profile selector matches `*` namespace, the `default` namespace, or has empty label selectors that match every pod. Every workload that drops into the matched scope gets scheduled on Fargate — including workloads the operator didn't intend to run there. Common surprise: a cluster with a "catch-all" Fargate profile silently runs DaemonSets, system pods, and short-lived Jobs on Fargate at a per-pod cost premium.

**Remediation:** Tighten the selector to the specific namespace + label combination Fargate is intended for. Avoid matching the `default` namespace (workloads frequently land there accidentally) or empty label selectors. For a cluster that's mostly EC2-backed with a Fargate exception, scope the profile to a dedicated namespace + a deliberate label (e.g., `compute=fargate`).

---

### CTL.EKS.GUARDDUTY.EKS.PROTECTION.001

**EKS Cluster Has GuardDuty EKS Protection Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4, AU-6; iso_27001_2022: A.5.24, A.8.16; nist_800_53_r5: SI-4, IR-4, AU-6; pci_dss_v4.0: 10.2, 11.5; soc2: CC7.2, CC7.3;

EKS cluster's region has GuardDuty EKS Protection not enabled. EKS Protection consumes the cluster's control-plane audit logs and applies AWS-managed threat detection signatures: privilege escalation via ServiceAccount tokens, anonymous access, excessive Secret reads, suspicious cluster API calls. Without it, threat detection on the control-plane layer relies on whatever custom detections the team has built — typically less comprehensive than AWS's signature catalog.

**Remediation:** Enable GuardDuty in the region; enable EKS Protection (audit log monitoring) under GuardDuty's Kubernetes protection settings:
  aws guardduty update-detector
    --detector-id <id>
    --features Name=EKS_AUDIT_LOGS,Status=ENABLED
Verify findings flow to Security Hub for central operations dashboard.

---

### CTL.EKS.GUARDDUTY.RUNTIME.001

**EKS Cluster Has GuardDuty Runtime Monitoring Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.24, A.8.16; nist_800_53_r5: SI-4, IR-4; pci_dss_v4.0: 11.5; soc2: CC7.2, CC7.3;

EKS cluster has GuardDuty Runtime Monitoring not enabled. Runtime Monitoring deploys an agent DaemonSet (managed-by-AWS) that observes per-pod system calls, file access, and process execution to detect runtime threats — crypto miners, reverse shells, container escapes, privilege escalation. Without it, runtime threat detection depends on whatever the team deployed (Falco, Sysdig) — typically not installed by default. The control-plane layer alone (covered by GuardDuty EKS Protection) doesn't see runtime activity.

**Remediation:** Enable Runtime Monitoring in GuardDuty for the region. Configure automated agent management:
  aws guardduty update-detector
    --detector-id <id>
    --features
    'Name=RUNTIME_MONITORING,Status=ENABLED,
    AdditionalConfiguration=[{Name=EKS_ADDON_MANAGEMENT,
    Status=ENABLED}]'
The aws-guardduty-agent EKS add-on deploys automatically to the cluster. Findings flow to Security Hub.

---

### CTL.EKS.HELM.RELEASE.FAILED.001

**EKS Helm Release Stuck In Failed State Over 7 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC8.1, CC7.4;

EKS cluster has at least one Helm release in `failed` / `pending-install` / `pending-upgrade` state for more than 7 days. The release's last operation didn't complete; the cluster's resources are in whatever partial state the failed operation left them. Operators commonly let failed releases sit because the deploy succeeded the second time on a different release name; the original failed release accumulates as inventory clutter and blocks future releases with the same name.

**Remediation:** Decide whether to retry or remove. Retry:
  helm rollback <release> 0 (or upgrade with
  --reset-values to a known-good chart version).
Remove: helm uninstall <release> deletes the release record + cluster resources. Audit cluster Helm state regularly:
  helm list -A --pending --failed

---

### CTL.EKS.HPA.GHOST.TARGET.001

**EKS HorizontalPodAutoscaler Targets Deleted Workload**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC8.1, A1.1;

HorizontalPodAutoscaler's `scaleTargetRef` points to a Deployment / StatefulSet / ReplicaSet that no longer exists. The HPA continues to evaluate metrics but its scaling decisions have nothing to apply to. Console shows the HPA configured; CloudWatch / Prometheus shows the HPA reporting "unable to fetch pod metrics" or unable to resolve the target. Auto-scaling for the workload that used to own the target is silently inactive.

**Remediation:** Delete the orphan HPA via kubectl delete hpa <name> -n <namespace>, OR repoint the scaleTargetRef to a live workload if the target was renamed. Audit cluster HPAs for orphan targets via kubectl get hpa -A and verify every scaleTargetRef resolves.

---

### CTL.EKS.IMAGE.BASE.STALE.001

**EKS Workload Image Was Built More Than 180 Days Ago**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-2, RA-5; iso_27001_2022: A.5.16, A.8.8; nist_800_53_r5: SI-2, RA-5; pci_dss_v4.0: 6.3, 11.2; soc2: CC8.1, CC7.2;

EKS workload's image has a build timestamp older than 180 days. Container base images (ubuntu, alpine, node, python) accumulate CVEs over time as vulnerabilities are disclosed in their package contents. An image built 6+ months ago carries every CVE disclosed since the build; even with no changes to application code, the security posture degrades silently. The remediation is rebuild-and- redeploy, not just patching.

**Remediation:** Rebuild the workload's image on a current base image and redeploy. For low-change services that don't have a regular rebuild cadence, automate via CI: trigger a base-image-refresh build weekly / monthly that rebuilds on the latest tag of the upstream base. Pair with ECR scan-on-push to identify regressions in the rebuild output.

---

### CTL.EKS.IMAGE.CVE.BLOCK.001

**EKS Cluster Admission Does Not Block Images With HIGH Or CRITICAL CVEs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: RA-5, SI-2; iso_27001_2022: A.5.16, A.8.8; nist_800_53_r5: RA-5, SI-2; pci_dss_v4.0: 11.2; soc2: CC8.1, CC7.2;

EKS cluster has no admission policy that rejects pods whose container images carry HIGH or CRITICAL CVEs per the latest scan results. ECR scan-on-push identifies vulnerabilities; admission control should consume those scan results to gate pod creation. Without enforcement at the admission layer, scan reports are advisory — vulnerable images continue running, the scan dashboard accumulates findings, no one acts.

**Remediation:** Install an admission controller that consults ECR / Inspector / Trivy scan results. Common patterns: Kyverno + ECR scan API (validate against scan findings before admit), Trivy operator with ValidatingAdmissionPolicy, or AWS-native via Inspector + EKS audit. Configure the policy to block CRITICAL severities outright; warn or block HIGH; allow MEDIUM / LOW with annotation documenting acceptance.

---

### CTL.EKS.IMAGE.LATEST.TAG.001

**EKS Production Workload Uses :latest Image Tag**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC8.1, CC7.4;

EKS production workload's image reference uses the `:latest` tag (or no tag, which defaults to :latest). The :latest tag is mutable — the image bytes change when a new image is pushed under the same tag. Deploys lose reproducibility (rolling back via spec revision doesn't roll back the image bytes), pod scheduling onto a new node may pull a different image than the existing pods on the cluster, and release auditing can't tie a running container to a specific image build.

**Remediation:** Replace :latest with a specific version tag (semver, Git SHA, or build ID). For maximum reproducibility, pin by SHA256 digest:
  image: 111122223333.dkr.ecr.us-east-1.amazonaws.com/
         orders@sha256:abc123...
Tags are convenient pointers; digests are cryptographic identifiers. Production should pin by digest where possible.

---

### CTL.EKS.IMAGE.NODIGEST.001

**EKS Production Workload Image Pinned By Tag Without Digest**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.30; nist_800_53_r5: CM-2, SR-3; soc2: CC8.1, CC7.4;

EKS production workload's image reference uses a semver / build-ID tag without an accompanying SHA256 digest. While tags are typically immutable in well-governed registries, ECR's imageTagMutability=MUTABLE setting allows tag reassignment, and supply-chain attacks (including registry compromise) can swap image bytes under an unchanged tag. Pinning by `image@sha256:digest` guarantees the running image matches what was scanned and approved.

**Remediation:** Update workload manifests to reference image by `image:tag@sha256:digest`. The tag stays for operator readability; the digest is cryptographic proof. CI / Helm chart values should record both. Verify ECR repo's imageTagMutability=IMMUTABLE for defense in depth.

---

### CTL.EKS.IMAGE.NOSIGNATURE.001

**EKS Cluster Has No Image Signature Verification In Admission**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SR-3; iso_27001_2022: A.5.16, A.8.30; nist_800_53_r5: CM-2, SR-3, SR-4; pci_dss_v4.0: 6.3; soc2: CC6.1, CC8.1;

EKS cluster has no admission controller (Kyverno verify-images, Connaisseur, OPA Gatekeeper with Cosign) that verifies container image signatures before pod creation. Workloads run any image the cluster's pull credentials can access regardless of provenance. Sigstore / Notation / AWS Signer are all viable options; one must be configured and enforced for the cluster's image-trust posture to mean anything.

**Remediation:** Install Kyverno (or equivalent) and apply a verifyImages policy:
  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata: { name: verify-image-signatures }
  spec:
    validationFailureAction: Enforce
    rules:
      - name: verify-signed
        match: { any: [{ resources: { kinds: [Pod] } }] }
        verifyImages:
          - imageReferences: ["111122223333.dkr.ecr.*"]
            attestors: [...] # public key or Cosign keyless
Sign images during CI build with cosign sign or AWS Signer; the policy rejects unsigned pods.

---

### CTL.EKS.IMAGE.PUBLIC.REGISTRY.001

**EKS Workload Pulls Image From Non-Allowlisted Public Registry**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SI-3; iso_27001_2022: A.5.16, A.8.30; nist_800_53_r5: CM-2, SI-3, SR-3; pci_dss_v4.0: 6.3; soc2: CC6.1, CC8.1;

EKS workload's container image is pulled from a public registry not on the org's allowlist (Docker Hub, Quay, GHCR, gcr.io public projects). Public registries can serve tampered images on arbitrary tags; without admission control restricting pulls to allowlisted registries (typically the org's private ECR), workloads are vulnerable to supply-chain attacks including dependency confusion, typosquatting, and upstream account compromise.

**Remediation:** Mirror upstream public images into the org's private ECR via tools like skopeo / crane, scan on push, and update workload manifests to pull from the private ECR copy. Add an admission policy (Kyverno, OPA Gatekeeper, EKS Pod Identity Agent) that rejects workloads pulling from non-allowlisted registries.

---

### CTL.EKS.IMAGE.PULLPOLICY.NEVER.001

**EKS Pod Has imagePullPolicy=Never**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2; soc2: CC8.1, CC7.4;

EKS Pod has `imagePullPolicy: Never` set on at least one container. The kubelet only uses the cached image on the node; if the image isn't present, the pod fails to start. Common cause: dev / debug configuration left in production manifests; the intent is "use the local image I built", but the effect in production is "use whatever's been cached here, possibly stale, possibly never updated."

**Remediation:** Change to imagePullPolicy: IfNotPresent (default when image references a specific tag) or Always (default for :latest tag). For local dev environments where Never is appropriate (kind / minikube with locally-built images), keep Never but ensure these manifests don't get applied to production clusters.

---

### CTL.EKS.IMAGE.PULLSECRET.SHARED.001

**EKS imagePullSecret Shared Across Multiple Namespaces**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, IA-5; iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: AC-3, IA-5; pci_dss_v4.0: 8.3; soc2: CC6.1, CC6.3;

EKS cluster has the same imagePullSecret (registry credential, typically of type `kubernetes.io/dockerconfigjson`) replicated across multiple namespaces. Compromise of any pod in any of those namespaces yields the registry credential — which then permits pulling any image the credential is authorized to read, including private images belonging to other tenants. The blast radius of a pull-credential leak scales linearly with the number of namespaces it's replicated to.

**Remediation:** Per-namespace pull secrets scoped to that namespace's image needs. For private ECR specifically, prefer IRSA-based pull (configure the workload's ServiceAccount with IRSA + an IAM role granting ecr:GetAuthorizationToken + repo-scoped pull) instead of long-lived dockerconfigjson Secrets entirely. ECR now supports IAM-side authentication directly, making Secret-based credentials a legacy pattern.

---

### CTL.EKS.INGRESS.GHOST.CERT.001

**EKS Ingress References Deleted ACM Certificate**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SC-13; iso_27001_2022: A.5.16, A.8.24, A.8.32; nist_800_53_r5: CM-2, CM-3, SC-13; soc2: CC6.1, CC6.7, CC8.1;

EKS Ingress (typically ALB Ingress Controller) has the `alb.ingress.kubernetes.io/certificate-arn` annotation pointing at an ACM certificate that no longer exists. When the ALB Ingress Controller reconciles, the ALB can't bind the certificate; HTTPS listener fails to provision or breaks on next reconcile cycle. Console shows the Ingress configured; clients see TLS handshake failures.

**Remediation:** Update the Ingress annotation to a live ACM certificate ARN (kubectl edit ingress <name>), or recreate the deleted certificate at the original ARN if it was intentional and the original is still needed. Pair with cert expiry monitoring so future ACM deletions / expiry surfaces immediately.

---

### CTL.EKS.IRSA.AUDIENCE.MISSING.001

**EKS IRSA Role Trust Policy Has No Audience Condition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, IA-5; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, IA-5; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

IRSA role's trust policy doesn't include the `aud` (audience) condition checking for `sts.amazonaws.com`. Without the audience check, tokens minted by the cluster's OIDC provider for non-AWS-STS audiences (other AWS services, third-party audiences) can also be used to assume the role. AWS documentation explicitly requires the `aud` check; omitting it widens the role's assumable scope beyond what the cluster operator likely intended.

**Remediation:** Add `<oidc-issuer>:aud` = `sts.amazonaws.com` to the trust policy's StringEquals condition. The full per-workload pattern is:
  "Condition": {
    "StringEquals": {
      "<oidc-issuer>:sub": "system:serviceaccount:<ns>:<sa>",
      "<oidc-issuer>:aud": "sts.amazonaws.com"
    }
  }

---

### CTL.EKS.IRSA.CROSSACCOUNT.001

**EKS IRSA Trust Policy Permits Cross-Account Assumption Without OrgID**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, IA-5; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-4, IA-5; owasp_subtractive: S05; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3, CC6.6; subtractive_tier: deletion;

EKS IRSA role's trust policy permits assumption from an OIDC issuer in a different AWS account (cross-account IRSA) without an `aws:PrincipalOrgID` condition. Cross-account IRSA is occasionally legitimate (shared services account pattern), but unrestricted cross-account trust means any compromised cluster's OIDC tokens can assume the role across the organization boundary.

**Remediation:** Add aws:PrincipalOrgID condition to the trust policy. For legitimate cross-account IRSA (shared services pattern), restrict to the specific source-account ID and source-cluster OIDC issuer rather than allowing any cluster's OIDC.

---

### CTL.EKS.IRSA.ENFORCE.001

**EKS Clusters Must Have OIDC Provider for IRSA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** aws_security_hub: EKS.9; mitre_attack: TA0006; nist_800_53_r5: AC-6;

Without IRSA (IAM Roles for Service Accounts), pods needing AWS API access must use the node's EC2 instance profile — granting all pods on the node the same IAM permissions. A compromised pod can use the node's credentials to access any AWS service the node role permits. IRSA binds IAM roles to Kubernetes service accounts via OIDC federation. Each pod gets only the permissions its service account requires. IRSA requires the EKS OIDC provider to be configured. This control verifies the OIDC provider exists.

**Remediation:** Associate an OIDC provider: eksctl utils associate-iam-oidc-provider --cluster <cluster> --approve. Then create service account-specific IAM roles.

---

### CTL.EKS.IRSA.OIDC.GHOST.001

**EKS IRSA Role Trust Policy References Non-Existent OIDC Provider**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: CM-2, IA-5; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, IA-5; soc2: CC6.1, CC8.1, CC7.4;

IRSA role's trust policy references a federated OIDC provider URL that doesn't match any IAM identity provider in the account, OR the URL has a typo / extra slash / wrong region / missing thumbprint. The role can never be assumed — every AssumeRoleWithWebIdentity call fails. Workloads depending on the role report "couldn't get caller identity" and operators trace the configuration twice before noticing the URL mismatch. Same ghost-reference pattern as other EB / SQS ghost-target controls but at the federation layer.

**Remediation:** Verify the OIDC provider exists: aws iam list-open-id-connect-providers. Confirm the URL in the trust policy matches exactly — including the region, the cluster ID segment, and no trailing slash. If the cluster OIDC provider was deleted, recreate via eksctl utils associate-iam-oidc-provider --cluster <name>. Update the trust policy with the new ARN if it changed.

---

### CTL.EKS.IRSA.SUB.UNSCOPED.001

**EKS IRSA Role Trust Policy Has No sub Filter**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6, IA-5; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

IRSA (IAM Roles for Service Accounts) role's trust policy authorizes the cluster's OIDC provider but doesn't scope the trust to a specific Kubernetes ServiceAccount via the `sub` condition. Without `sub`, ANY ServiceAccount in the cluster with a properly-formatted token can assume the role. The intent of IRSA — bind specific IAM permissions to specific workloads — is defeated. The role becomes effectively a cluster-wide role available to every pod that knows the role ARN.

**Remediation:** Add a `sub` condition to the trust policy:
  "Condition": {
    "StringEquals": {
      "<oidc-issuer>:sub": "system:serviceaccount:<namespace>:<sa-name>",
      "<oidc-issuer>:aud": "sts.amazonaws.com"
    }
  }
Pin to the exact namespace + SA name. For roles serving multiple workloads, list each `sub` explicitly via StringEquals on an array.

---

### CTL.EKS.LOGGING.001

**EKS Control Plane Logging Must Be Enabled for All Log Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_eks: 2.1; fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-2;

EKS clusters must have all five control plane log types enabled (api, audit, authenticator, controllerManager, scheduler). Without full logging, an attacker who compromises the cluster can escalate privileges and exfiltrate data without any audit trail.

**Remediation:** Enable all five control plane log types via AWS CLI: aws eks update-cluster-config --name <cluster> --logging '{"clusterLogging":[{"types":["api","audit","authenticator", "controllerManager","scheduler"],"enabled":true}]}'

---

### CTL.EKS.NETPOL.EGRESS.OPEN.001

**EKS NetworkPolicy Allows Egress To 0.0.0.0/0**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-4, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-4, SC-7; pci_dss_v4.0: 1.2, 1.3; soc2: CC6.1, CC6.6;

EKS NetworkPolicy has an egress rule with `ipBlock.cidr: 0.0.0.0/0` — pods covered by the rule can connect to any destination. The intent is usually "I need to call any external API"; the effect defeats default-deny-egress isolation. Should be replaced with an egress allowlist matching the actual external endpoints the workload calls (specific CIDRs or DNS-name-resolved IPs).

**Remediation:** Replace 0.0.0.0/0 with specific egress destinations: AWS API ranges (or VPC endpoints + the endpoint's private IP range), partner API CIDRs, internal cluster services. For workloads needing broad outbound, use a DNS firewall + egress-via-NAT-with-logging pattern rather than NetworkPolicy 0.0.0.0/0.

---

### CTL.EKS.NETPOL.ENFORCE.001

**EKS Clusters Must Have Network Policy Enforcement Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** mitre_attack: TA0008; nist_800_53_r5: AC-4;

Without network policy enforcement, all pods in an EKS cluster can communicate freely regardless of namespace or label. A compromised pod can reach any other pod, service, or node in the cluster on any port. NetworkPolicy objects exist but have no effect unless a network policy controller enforces them. The VPC CNI network policy controller (enableNetworkPolicy) enforces Kubernetes NetworkPolicy objects using eBPF rules.

**Remediation:** Enable network policy enforcement via VPC CNI: aws eks update-addon --cluster-name <cluster> --addon-name vpc-cni --configuration-values '{"enableNetworkPolicy": "true"}'. Then apply default-deny NetworkPolicy in each namespace.

---

### CTL.EKS.NETPOL.GHOST.PEER.001

**EKS NetworkPolicy Peer Selectors Match No Live Pods**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, CM-2; iso_27001_2022: A.5.16, A.8.16, A.8.32; nist_800_53_r5: AC-3, CM-2, CM-3; soc2: CC6.1, CC8.1, CC7.4;

NetworkPolicy's ingress / egress peer selectors (`podSelector` + `namespaceSelector`) match zero live pods. The policy persists with allow / deny rules pointing at nothing. Same ghost pattern as RBAC bindings to deleted subjects but on the network-policy surface. The danger is label re-use: if a namespace or pod is later created with matching labels, it silently inherits the policy's connectivity (which may be broader or narrower than the new workload needs).

**Remediation:** Either delete the orphan policy (kubectl delete networkpolicy <name>) if the workload it protected is decommissioned, or update the selectors to match the current workload labels if the labels have shifted. Audit cluster network policies via `kubectl get netpol -A` + a label-match dry run.

---

### CTL.EKS.NETPOL.INGRESS.OPEN.001

**EKS NetworkPolicy Allows Ingress From 0.0.0.0/0**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 1.3; soc2: CC6.1, CC6.6;

EKS NetworkPolicy has an ingress rule with `ipBlock.cidr: 0.0.0.0/0` — effectively no source restriction. Common intent: "I want this to be reachable from anywhere"; common effect: defeats the namespace's default-deny baseline. If the rule applies to all pods in the namespace (podSelector: {}), the namespace is functionally ingress-open even with default-deny present.

**Remediation:** Replace 0.0.0.0/0 with the specific source CIDR or podSelector that should be permitted. For workloads that legitimately need to be reachable from external networks, place them behind an Ingress controller / ALB rather than allowing 0.0.0.0/0 directly to pods.

---

### CTL.EKS.NETPOL.INGRESSONLY.001

**EKS Namespace Configures Ingress Policies But No Egress Policies**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-4, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-4, SC-7; soc2: CC6.1, CC6.6;

EKS namespace has at least one ingress NetworkPolicy but no egress NetworkPolicies — one-way isolation. Operators often configure ingress-side NetworkPolicies first (visible failure mode: "X can't talk to me"), then never return to add egress (silent failure mode: "I can talk to anywhere"). The result is half-applied isolation: the cluster appears to have NetworkPolicy discipline because ingress rules exist, but pods retain unbounded egress.

**Remediation:** Add a default-deny-egress NetworkPolicy plus explicit egress allow rules matching the workload's intended outbound connections (internal services by namespace + pod selector, external APIs by CIDR via egress-allow rules with cidr blocks).

---

### CTL.EKS.NETPOL.NODEFAULTDENY.EGRESS.001

**EKS Namespace Has No Default-Deny Egress NetworkPolicy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-4, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-4, SC-7; pci_dss_v4.0: 1.2, 1.3; soc2: CC6.1, CC6.6, CC6.7;

EKS namespace has no NetworkPolicy that selects all pods with empty egress rules — the default-deny-egress baseline. Without it, pods can initiate connections to any destination including external internet, the IMDS endpoint (169.254.169.254), and all internal cluster services. Default-deny egress is the namespace-level exfiltration floor; without it, a pod compromise yields full outbound network access.

**Remediation:** Apply a default-deny baseline:
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: default-deny-egress
    namespace: <ns>
  spec:
    podSelector: {}
    policyTypes: [Egress]
Then explicitly allow only the egress destinations the workload requires (internal cluster services, AWS endpoints via VPC endpoints, specific external APIs). Block IMDS access by including its IP range in deny rules.

---

### CTL.EKS.NETPOL.NODEFAULTDENY.INGRESS.001

**EKS Namespace Has No Default-Deny Ingress NetworkPolicy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 1.3; soc2: CC6.1, CC6.6, CC6.7;

EKS namespace has no NetworkPolicy that selects all pods (`podSelector: {}`) with empty ingress rules — the default-deny-ingress baseline. Without it, pods in the namespace accept ingress from any pod in any namespace by default. NetworkPolicies are additive — explicit allow rules layered on top of a missing default-deny don't actually narrow connectivity, they just add to the permissive default. Default-deny ingress is the namespace-level isolation floor.

**Remediation:** Apply a default-deny baseline:
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: default-deny-ingress
    namespace: <ns>
  spec:
    podSelector: {}
    policyTypes: [Ingress]
Then layer explicit allow policies for the connections the workload actually needs. Default-deny + explicit allow is the documented Kubernetes pattern for namespace-level network isolation.

---

### CTL.EKS.NETPOL.NSSELECTOR.WIDE.001

**EKS NetworkPolicy Uses Empty namespaceSelector Permitting All Namespaces**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-4, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-4, SC-7; soc2: CC6.1, CC6.6;

EKS NetworkPolicy has an ingress / egress rule with `namespaceSelector: {}` — every namespace in the cluster matches. Combined with podSelector, the pods covered by the rule are reachable from / can reach pods in every namespace. Multi-tenant isolation between namespaces collapses for the workloads this rule covers.

**Remediation:** Replace `namespaceSelector: {}` with a selector matching the specific namespaces that should be permitted. Use namespace labels (`team=orders`, `tier=backend`) plus pod labels to scope the rule narrowly. AWS-recommended pattern: every NetworkPolicy peer should select on at least namespace + pod labels, never on empty selectors.

---

### CTL.EKS.NODEGROUP.AMI.001

**EKS Node Groups Must Use Current AMIs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2;

EKS managed node groups must use current Amazon Machine Images. AWS publishes updated EKS-optimized AMIs that include kernel patches, container runtime updates, and kubelet security fixes. Node groups running outdated AMIs are missing security patches for the underlying operating system and Kubernetes node components. Unlike the EKS control plane which AWS manages, node group AMIs must be updated by the operator. Outdated node AMIs create a persistent attack surface at the node level — container escapes, kernel exploits, and privilege escalation vulnerabilities in the kubelet or containerd remain exploitable until the AMI is updated. The gap between the current AMI and the running AMI directly correlates with the number of unpatched CVEs on every node in the group.

**Remediation:** Update the node group to use the latest EKS-optimized AMI. For managed node groups, trigger an AMI update through the EKS console or AWS CLI using update-nodegroup-version. Use the rolling update strategy to replace nodes without downtime. Verify pod disruption budgets are configured to protect workload availability during the node rotation.

---

### CTL.EKS.NODEGROUP.BOOTSTRAP.UNPINNED.001

**EKS Self-Managed Node Bootstrap Script Not Pinned To AMI Checksum**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC8.1;

EKS self-managed node group's launch template runs a bootstrap script that fetches and runs unpinned content (curl from a non-version-pinned URL, eksctl bootstrap with `--latest`, ad-hoc Helm install) without pinning to a specific AMI version or content hash. On node recreation (scaling, replacement, AZ rebalance), the script may pull a different version than the original cluster nodes ran — silent kernel parameter drift, kubelet config drift, or CNI version drift between otherwise-identical-looking nodes.

**Remediation:** Pin the bootstrap content: bake a custom AMI with the desired bootstrap state pre-applied (rather than running a fetch-and-execute on first boot), or download bootstrap artifacts from a versioned S3 bucket with object-version checksums and verify before execution. EKS-optimized AMIs are preferred for managed node groups precisely because they're versioned + AWS- maintained.

---

### CTL.EKS.NODEGROUP.DISK.ENCRYPT.001

**EKS Node Group Has Unencrypted EBS Root Volumes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

EKS managed node group launches instances with unencrypted EBS root volumes. Container filesystems, kubelet data, and pod ephemeral storage sit on unencrypted disk. The launch template for the node group does not specify EBS encryption. Unlike EKS secrets encryption (control plane etcd), this is data-at-rest encryption for the node's local storage — container images, emptyDir volumes, kubelet state, and anything written to the node's filesystem by pods. Existing node groups cannot be modified — remediation requires creating a new node group with encryption and migrating workloads.

**Remediation:** Configure the node group's launch template with an encrypted EBS volume. Specify a KMS key for customer-managed encryption. Existing node groups require replacement — create a new node group with encryption enabled, cordon and drain the old nodes, then delete the unencrypted node group. Verify pod disruption budgets protect workload availability during the migration.

---

### CTL.EKS.NODEGROUP.IMDS.DISABLED.001

**EKS Node Group Has IMDS Endpoint Disabled While Workloads Need It**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, SI-4; soc2: CC8.1, CC7.4;

EKS worker node group's launch template has `MetadataOptions.HttpEndpoint: disabled` while at least one workload on the node group depends on IMDS for AWS API authentication (no IRSA, no Pod Identity). Workloads silently fail to authenticate to AWS APIs. Operators investigating "AWS calls hanging / timing out" trace from the workload through to MetadataOptions. Distinct from the IMDSV2 / hop-limit controls — those catch over-permissive IMDS; this catches IMDS being disabled when it shouldn't be.

**Remediation:** Either enable IMDS (HttpEndpoint: enabled, with HttpTokens: required + HttpPutResponseHopLimit: 1 for secure config) and rely on the node role for those workloads, OR migrate the workloads to IRSA / Pod Identity for per-pod IAM (preferred). Disabling IMDS cluster-wide is a valid posture only when every workload uses IRSA / Pod Identity exclusively and the cluster operations don't depend on instance metadata.

---

### CTL.EKS.NODEGROUP.IMDS.HOPLIMIT.001

**EKS Node Group IMDS Hop Limit Permits Pod-Side Reach**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, IA-2; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, IA-2, SC-7; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EKS node group's launch template has `MetadataOptions.HttpPutResponseHopLimit` greater than 1. The hop limit is the IP TTL on IMDS responses; a value of 1 means responses can only reach processes on the host itself, not containers (containers add a hop). With HopLimit > 1, container processes — including pods — can directly read IMDS and obtain the node's IAM credentials. Combined with IMDSv2 required (still reachable from containers if hop limit allows), this is the documented EKS hardening required to keep IMDS access node-only.

**Remediation:** Update the launch template's MetadataOptions to `HttpPutResponseHopLimit: 1`. Roll the node group to apply. After rollout, verify pods can no longer reach 169.254.169.254 by exec-ing into a test pod and curl-ing the metadata service — should time out.

---

### CTL.EKS.NODEGROUP.IMDSV2.001

**EKS Node Group Permits IMDSv1 Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, IA-2; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, IA-2, SC-7; owasp_subtractive: S01; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3; subtractive_tier: deletion;

EKS managed node group's launch template has `MetadataOptions.HttpTokens: optional` — IMDSv1 (the legacy unauthenticated metadata service) is permitted in addition to IMDSv2. IMDSv1 is reachable via simple HTTP GET to 169.254.169.254 with no token; SSRF / proxy / XSPA exploits in pod workloads commonly target it to exfiltrate the node's IAM instance profile credentials. IMDSv2 (HttpTokens: required) requires a session token obtained via PUT first, which most SSRF surfaces can't produce.

**Remediation:** Update the launch template's MetadataOptions to require IMDSv2:
  MetadataOptions:
    HttpTokens: required
    HttpPutResponseHopLimit: 1
    HttpEndpoint: enabled
Roll the node group to apply (replace nodes). Verify every node group in the cluster — IMDSv2 must be cluster-wide; one node group permitting v1 is enough for an SSRF-targeted pod.

---

### CTL.EKS.NODEGROUP.PROFILE.SHARED.001

**EKS Node Groups Share One Instance Profile Across Tenants**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

Multiple EKS node groups across the cluster — typically serving different tenants, environments, or workload classes — share the same IAM instance profile. Every pod scheduled on any of these node groups inherits the same node-role credentials via IMDS (subject to IMDS hardening). Cross-tenant isolation at the IAM layer is defeated; one tenant's pod compromise yields the same credentials another tenant's pod has access to.

**Remediation:** Create per-tenant / per-class instance profiles with least-privilege IAM policies scoped to that tenant's AWS resource needs. Update each node group's launch template to use its dedicated instance profile. Combined with IMDSv2 + hop limit 1, this enforces per-node-group IAM isolation.

---

### CTL.EKS.NODEGROUP.ROLE.OVERBROAD.001

**EKS Node Group IAM Role Exceeds Kubelet-Minimum Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EKS managed node group's IAM role has permissions beyond kubelet-minimum. The kubelet-minimum set is: eks:DescribeCluster, ECR pull (ecr:GetAuthorizationToken, ecr:BatchGetImage, ecr:GetDownloadUrlForLayer), CloudWatch Logs push (logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, logs:DescribeLogStreams), EC2 describe (ec2:DescribeInstances, ec2:DescribeRegions), and VPC CNI (ec2:CreateNetworkInterface, ec2:AttachNetworkInterface, ec2:DeleteNetworkInterface, ec2:DescribeNetworkInterfaces). Any action outside this set — s3:*, iam:PassRole, sts:AssumeRole on broad targets, secretsmanager:* — means every pod that inherits the node profile (via missing IRSA or Pod Identity) gains excess permissions. The companion control CTL.EKS.POD.NODE.PROFILE.INHERIT.001 detects pods using the node profile; this control flags that the profile itself is over-permissioned.

**Remediation:** Scope the node group IAM role to kubelet-minimum permissions only: eks:DescribeCluster, ECR pull, CloudWatch Logs push, EC2 describe, and VPC CNI network-interface operations. Move all workload-specific AWS permissions to IRSA or Pod Identity bindings on specific service accounts. After migration, remove excess policies from the node role and verify pods still function with their dedicated IRSA roles.

---

### CTL.EKS.NODEGROUP.SELFMANAGED.NOTREADY.001

**EKS Self-Managed Node Joined But Never Reached Ready**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: CM-2, CM-8, SI-4; soc2: CC8.1, A1.1;

EKS self-managed node has joined the cluster (kubelet registered with the API server) but has been in `NotReady` state for more than 30 minutes. Common causes: CNI plugin failed to install, kubelet bootstrap script error, IAM trust mismatch, network connectivity to the cluster API endpoint blocked. The node consumes IAM trust, CloudWatch metrics, and node-license cost without serving any pods. Workloads requesting matching node selectors stall in Pending.

**Remediation:** Check kubelet logs (`journalctl -u kubelet`) for the bootstrap failure. Common causes: CNI plugin incompatibility (re-run aws-node DaemonSet), IAM trust policy doesn't include "Principal": { "Service": "ec2.amazonaws.com" }, network path to the cluster API endpoint blocked by SG / NACL. If the node is genuinely not recoverable, terminate it and remove from the cluster (kubectl delete node <name>).

---

### CTL.EKS.NODEGROUP.SG.001

**EKS Node Groups Must Not Use the Cluster Default Security Group**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** mitre_attack: TA0008; nist_800_53_r5: SC-7;

EKS clusters create a default cluster security group that allows all traffic between nodes and the control plane. Node groups without dedicated security groups rely on this permissive default — all nodes can communicate with all other nodes on all ports. Dedicated node group security groups with minimal required rules reduce the blast radius of a compromised node.

**Remediation:** Create a dedicated security group for each node group with only required rules: port 10250 (kubelet) from control plane SG, port 443 to control plane SG, and application-specific ports. Assign via launch template.

---

### CTL.EKS.NODEGROUP.SSH.OPEN.001

**EKS Worker Node Security Group Permits SSH Inbound**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, AC-17, SC-7; pci_dss_v4.0: 1.2, 2.2; soc2: CC6.1, CC6.6;

EKS worker node group's security group permits inbound TCP/22 (SSH) from any source — including 0.0.0.0/0 or broad CIDRs. EKS-managed Kubernetes doesn't require SSH access to workers; the recommended pattern is SSM Session Manager (no inbound port required, fully audited). SSH on worker nodes is an unnecessary attack surface that bypasses Kubernetes RBAC and audit logging.

**Remediation:** Remove the SSH inbound rule from the worker SG. For operational access, deploy SSM Agent on the AMI (the EKS-optimized AMI includes it) and use Session Manager:
  aws ssm start-session --target <instance-id>
Session Manager doesn't require open inbound ports, integrates with IAM for authorization, and logs every session to CloudWatch Logs for audit.

---

### CTL.EKS.NODEGROUP.SSM.MISSING.001

**EKS Node Group Lacks SSM Session Manager Configuration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AU-12; iso_27001_2022: A.5.15, A.8.15; nist_800_53_r5: AC-3, AU-12, IA-2; soc2: CC6.1, CC7.2;

EKS worker node group's instance profile doesn't include the AmazonSSMManagedInstanceCore policy (or an equivalent scoping policy granting Session Manager APIs). Without it, SSM Session Manager isn't usable for the workers, which often leads operators to fall back to SSH — see CTL.EKS.NODEGROUP.SSH.OPEN. Session Manager provides the audited, IAM-controlled, no-open-port path for operational shell access; missing it pushes the cluster toward the SSH alternative.

**Remediation:** Attach AmazonSSMManagedInstanceCore (or a tighter custom policy) to the node group's instance profile. Verify the SSM Agent is running on the AMI (EKS- optimized AMIs include it; custom AMIs may not). Configure CloudWatch logging for Session Manager sessions for audit.

---

### CTL.EKS.NS.DORMANT.001

**EKS Namespace Has No Workloads And No Recent API Activity**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-8; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-8; soc2: CC8.1;

EKS namespace has zero Deployments / StatefulSets / DaemonSets / Jobs / Pods AND no kubectl API activity in the last 90 days. The namespace is operationally dead — typically left over from a decommissioned service, a pre-production migration that completed, or a refactor that moved workloads elsewhere without removing the empty namespace. Long-dormant namespaces accumulate stale RBAC, NetworkPolicies, ResourceQuotas, and Secrets that complicate audits without providing operational value.

**Remediation:** Delete the namespace via kubectl delete ns <name>. If the namespace must be retained for a documented reason (capacity reservation, naming reservation), tag it with Lifecycle=Reserved + DocumentedReason=<reason>. Audit cluster namespace inventory periodically via kubectl get ns plus the `kubernetes.io/cluster-event-history` audit log.

---

### CTL.EKS.NS.MULTITENANT.001

**EKS Namespace Houses Workloads From Multiple Tenants**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-4; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-4; soc2: CC6.1, CC6.6;

EKS namespace contains workloads tagged for multiple tenants / teams (per the cluster's `tenant`/`team`/`owner` label convention). Multiple tenants in a single namespace means RBAC granted to one tenant's principals applies to the other's resources, NetworkPolicies designed for one tenant's threat model apply to the other's pods, and cost- attribution by namespace can't separate the bills. Each tenant should have its own namespace.

**Remediation:** Move each tenant's workloads to a dedicated namespace. Migration: (1) create per-tenant namespaces; (2) recreate each tenant's workloads in their namespace via Helm / GitOps; (3) replicate ConfigMaps / Secrets needed; (4) update Service references; (5) delete the old shared namespace.

---

### CTL.EKS.NS.NOCLASSIFICATION.TAG.001

**EKS Namespace Has No Data Classification Label**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CA-7, CM-8; iso_27001_2022: A.5.9, A.5.12; nist_800_53_r5: CA-7, CM-8; soc2: CC6.1, CC6.5;

EKS namespace has no `data-classification` label (or equivalent per-org convention: `Confidentiality`, `Sensitivity`, `Compliance`). Without classification, automated compliance reports can't determine whether the namespace carries PII / PHI / PCI-scope data, whether encryption / retention controls apply, or whether cross-namespace traffic respects compliance boundaries. Required for compliance frameworks scoped at the workload-tier (HIPAA, PCI-DSS, GDPR).

**Remediation:** Apply org-standard classification labels:
  kubectl label ns <name>
    data-classification=internal
    compliance=hipaa
    owner=team-name
Standardize the label vocabulary across the cluster (Public / Internal / Confidential / Restricted is one common scheme). Compliance reports can then scope by label:
  kubectl get ns -l data-classification=restricted

---

### CTL.EKS.NS.NOCOSTALLOC.TAG.001

**EKS Namespace Has No Cost-Allocation Label**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9, A.5.30; nist_800_53_r5: CM-8, PM-3; soc2: CC8.1;

EKS namespace has no cost-allocation label (`cost-center`, `team`, or `owner` per org convention). Cluster-level cost (compute, storage, network) reaches AWS billing as one undivided bucket; without per-namespace cost-allocation labels, attribution to specific teams / applications / cost centers requires manual review. Multi-tenant clusters lose chargeback capability; cost optimization decisions are made without per-team visibility.

**Remediation:** Apply org-standard labels:
  kubectl label ns <name>
    cost-center=engineering-billing
    team=billing
    owner=billing-leads@example.com
Consider AWS Cost Allocation Tags (activate via Billing Console) so per-namespace costs roll up to AWS Cost Explorer. EKS-specific tools like Kubecost / CloudWatch Container Insights consume namespace labels directly for chargeback reports.

---

### CTL.EKS.NS.NOLIMITRANGE.001

**EKS Namespace Has No LimitRange**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.6; nist_800_53_r5: SC-5, SC-6; soc2: CC8.1, A1.1;

EKS namespace has no LimitRange object. Without a LimitRange, individual pods can be created with no resource requests / limits, OR with arbitrarily high values. Per-pod resource consumption is bounded only by what fits on the node — one greedy pod can consume the entire node. Combined with no ResourceQuota, the namespace has no resource discipline at any granularity.

**Remediation:** Apply a LimitRange to enforce default + max per-pod / per-container resource bounds:
  apiVersion: v1
  kind: LimitRange
  metadata: { name: <ns>-limits, namespace: <ns> }
  spec:
    limits:
      - type: Container
        default:        { cpu: 500m, memory: 512Mi }
        defaultRequest: { cpu: 100m, memory: 128Mi }
        max:            { cpu: 2,    memory: 4Gi }
        min:            { cpu: 50m,  memory: 64Mi }
Tune to the workload's expected per-pod range.

---

### CTL.EKS.NS.NORESOURCEQUOTA.001

**EKS Namespace Has No ResourceQuota**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.6; nist_800_53_r5: SC-5, SC-6; soc2: CC8.1, A1.1;

EKS namespace has no ResourceQuota object. Without a quota, workloads in the namespace can consume unbounded cluster resources — CPU, memory, persistent volumes, pods, services. One namespace's runaway workload can starve the entire cluster of capacity. Multi-tenant clusters require ResourceQuotas to enforce per-tenant resource ceilings.

**Remediation:** Apply a ResourceQuota matching the namespace's intended resource budget:
  apiVersion: v1
  kind: ResourceQuota
  metadata:
    name: <ns>-quota
    namespace: <ns>
  spec:
    hard:
      requests.cpu: "20"
      requests.memory: 40Gi
      limits.cpu: "40"
      limits.memory: 80Gi
      pods: "100"
Tune the values to the workload's expected steady-state plus headroom.

---

### CTL.EKS.NS.PRIORITYCLASS.SYSTEM.001

**EKS Pod Uses System PriorityClass To Bypass Tenant Isolation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, SC-5; iso_27001_2022: A.5.15, A.8.6; nist_800_53_r5: AC-3, SC-5; soc2: CC6.1, CC6.6, CC8.1;

EKS Pod in a tenant namespace uses `priorityClassName: system-cluster-critical` or `system-node-critical` — the highest-priority classes reserved for cluster-system pods. The scheduler grants these pods preferential placement and preempts lower- priority pods to fit them. Tenant workloads using system priority classes bypass per-namespace ResourceQuotas (priority classes scoped via ResourceQuota may not catch this) and can starve other tenants by triggering preemption.

**Remediation:** Remove the `priorityClassName` from tenant pods or change it to a tenant-appropriate class. Use the cluster's RBAC + ResourceQuota with `scopes: [PriorityClass]` to restrict which priority classes a namespace can request. System priority classes should be limited to `kube-system` and equivalent infrastructure namespaces.

---

### CTL.EKS.OIDC.SHARED.001

**EKS Multiple Clusters Share The Same OIDC Issuer URL**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6, IA-5; soc2: CC6.1, CC6.3;

EKS multiple clusters in the account share the same OIDC issuer URL — typically a copy-paste error during cluster bootstrap, or intentional reuse that wasn't reviewed. EKS clusters get unique OIDC issuer URLs by design. Two clusters with the same URL means an IRSA role trusting that URL can be assumed by ServiceAccounts on EITHER cluster — a workload on cluster A's compromised pod can mint tokens that assume the role intended for cluster B. Per-cluster IAM scope intent collapses across clusters.

**Remediation:** Verify each cluster's OIDC issuer URL is unique:
  aws eks describe-cluster --name <c>
    --query 'cluster.identity.oidc.issuer'
If two clusters share an URL, this is a configuration error — recreate the affected cluster (the OIDC URL is set at cluster creation and can't be changed). Re-deploy IRSA roles afterward with the new OIDC URLs.

---

### CTL.EKS.POD.GHOST.CONFIGMAP.001

**EKS Pod References Deleted ConfigMap In env Or volumes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC8.1, CC7.4;

Pod / Deployment / StatefulSet manifest references a ConfigMap (in `envFrom`, `valueFrom.configMapKeyRef`, or `volumes.configMap.name`) that no longer exists in the namespace. New pod creation fails; existing pods continue with cached values. Same ghost-reference pattern as the Secret variant; ConfigMaps are typically more frequently edited than Secrets, so ghost references here accumulate faster but the failure mode is identical.

**Remediation:** Recreate the ConfigMap at the original name (kubectl create configmap), or update the pod spec to reference a live ConfigMap (kubectl edit deploy <name>). Audit via `kubectl get pods -A -o yaml | grep configMapRef`.

---

### CTL.EKS.POD.GHOST.SECRET.001

**EKS Pod References Deleted Secret In env Or volumes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC6.1, CC8.1, CC7.4;

Pod / Deployment / StatefulSet manifest references a Kubernetes Secret (in `envFrom`, `valueFrom.secretKeyRef`, or `volumes.secret.secretName`) that no longer exists in the namespace. New pod creation fails with `CreatePodError: secret X not found`; existing pods continue running with cached values. Same name-reuse risk as the other ghost controls — if the Secret is recreated, the pod silently picks up whatever values the new Secret carries.

**Remediation:** Recreate the Secret at the original name (kubectl create secret), or update the pod spec to reference a live Secret (kubectl edit deploy <name>). Audit pods for ghost Secret refs via `kubectl get pods -A -o yaml | grep secretRef` plus a kubectl get secret -A walk.

---

### CTL.EKS.POD.HOSTACCESS.001

**EKS Pod Uses hostNetwork hostPID Or hostIPC**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, AC-6, SC-7; pci_dss_v4.0: 1.4; soc2: CC6.1, CC6.6;

EKS workload Pod has `hostNetwork: true`, `hostPID: true`, or `hostIPC: true`. Each shares a host namespace with the pod and breaks the pod's isolation. hostNetwork lets the pod observe and bind to host network interfaces (including internal cluster traffic and IMDS); hostPID lets the pod see and signal all host processes; hostIPC lets the pod share IPC with host processes. Each is a documented privilege escalation path. Should be limited to infrastructure DaemonSets.

**Remediation:** Remove `hostNetwork`, `hostPID`, `hostIPC` from the pod spec. For network-level needs, use a Service / ClusterIP. For monitoring host processes, use a per-pod metrics collector that exports via the cluster network rather than reading from the host PID namespace. For infrastructure DaemonSets that legitimately need these (kube-proxy, CNI), document the exception and confirm the namespace's PSA level permits it.

---

### CTL.EKS.POD.HOSTPATH.001

**EKS Pod Mounts Sensitive Host Path**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, AC-6, SC-7; pci_dss_v4.0: 1.4, 2.2; soc2: CC6.1, CC6.6;

EKS Pod mounts a hostPath volume that targets a sensitive host filesystem location: `/`, `/etc`, `/var`, `/var/run/docker.sock`, `/proc`, `/sys`, or `/var/lib/kubelet`. Each gives the container the ability to read or modify host-level state — `/etc` exposes host configuration including SSH keys; the docker / containerd socket lets the container start sibling containers with arbitrary privilege; `/proc` exposes every host process's memory / fd table; `/var/lib/kubelet` carries ServiceAccount tokens for every pod on the node.

**Remediation:** Remove the hostPath mount. Use ConfigMaps / Secrets / PersistentVolumes for application state. For monitoring or troubleshooting workloads that need host filesystem visibility, deploy them in dedicated namespaces with explicit security context exceptions and operator review.

---

### CTL.EKS.POD.NODE.PROFILE.INHERIT.001

**EKS Pod Calls AWS APIs Through Node Instance Profile Without IRSA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6, IA-2; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EKS Pod calls AWS APIs (detected via observed AWS SDK usage, IRSA-aware base images, or AWS-related env vars) but the pod's ServiceAccount has no IRSA annotation and no Pod Identity association. The pod inherits the node's EC2 instance profile credentials via IMDS — every workload on every node sharing that node group gets the same IAM permissions. The IRSA / Pod Identity mechanism — bind IAM permissions to specific workloads, not to nodes — is defeated. Compromise of any pod yields whatever the node role permits.

**Remediation:** Create an IRSA role scoped to the workload's specific AWS API needs (least privilege). Annotate the pod's ServiceAccount with the role ARN. Confirm the role's trust policy carries both `sub` (specific serviceaccount) and `aud`=`sts.amazonaws.com` conditions (see CTL.EKS.IRSA.SUB.UNSCOPED and CTL.EKS.IRSA.AUDIENCE.MISSING). Block IMDSv2 access from pods at the node level (`HttpPutResponseHopLimit: 1`) so pods can't fall back to the node profile.

---

### CTL.EKS.POD.PRIVESCALATION.001

**EKS Pod Allows Privilege Escalation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 2.2; soc2: CC6.1, CC6.6;

EKS Pod's container has `securityContext.allowPrivilegeEscalation: true` (or unset, which defaults to true in some Kubernetes versions). With this set, a process inside the container can call setuid binaries to gain capabilities the original process didn't have. Combined with any setuid binary on the image (sudo, su, mount, ping with capabilities) the container's capability ceiling becomes the union of capabilities of every setuid binary it contains.

**Remediation:** Set `securityContext.allowPrivilegeEscalation: false` on every container. As a defense-in-depth measure also drop all Linux capabilities (`securityContext.capabilities.drop: ["ALL"]`) and add only the specific capabilities the workload needs.

---

### CTL.EKS.POD.PRIVILEGED.001

**EKS Pod Or Container Runs With privileged=true**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2, A.8.16; nist_800_53_r5: AC-3, AC-6, SI-3; pci_dss_v4.0: 1.4, 2.2; soc2: CC6.1, CC6.6;

EKS workload Pod / Deployment / DaemonSet has at least one container with `securityContext.privileged: true`. A privileged container has effectively root access on the host node — full Linux capabilities, no AppArmor / SELinux enforcement, host devices accessible. Pod compromise yields node compromise. Privileged containers should be limited to specific infrastructure DaemonSets (CNI plugins, storage drivers) and absolutely never application workloads.

**Remediation:** Remove `privileged: true` from the container's securityContext. If the container truly needs elevated capabilities, request only the specific Linux capabilities it needs via `securityContext.capabilities.add`. For DaemonSets that legitimately require privileged (CNI, storage drivers, monitoring with eBPF), document the exception in the workload manifest comments and confirm the namespace's PSA level allows it (typically a dedicated `kube-system`-style namespace, not the application namespace).

---

### CTL.EKS.POD.RUNASROOT.001

**EKS Pod Runs As Root User**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 2.2; soc2: CC6.1, CC6.6;

EKS Pod's container runs as root — either explicitly via `securityContext.runAsUser: 0` / `runAsNonRoot: false`, or implicitly because the container image's USER directive is unset / 0 and the pod doesn't override. Root inside the container has all Linux capabilities by default; combined with kernel vulnerabilities, hostPath mounts, or privileged mode, root accelerates every privilege escalation path.

**Remediation:** Set `securityContext.runAsNonRoot: true` and `securityContext.runAsUser: <non-zero-uid>` on the pod spec. Build images with a USER directive set to a non-zero UID. For images that legitimately need root capabilities, request only the specific capabilities via `securityContext.capabilities.add` and run as a non-zero UID with those capabilities granted explicitly.

---

### CTL.EKS.POD.SATOKEN.AUTOMOUNT.001

**EKS Pod Auto-Mounts ServiceAccount Token Without Needing API Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EKS Pod has `automountServiceAccountToken: true` (or unset, defaulting true) but doesn't actually need to call the Kubernetes API. Every such pod has a token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token — reachable by any process in the container. If the pod is compromised, the attacker harvests the token and uses it against the K8s API with whatever permissions the ServiceAccount has been granted. For pods that don't need K8s API access (which is most workloads — they call AWS APIs, internal services, or external APIs), the token is unnecessary attack surface.

**Remediation:** Set `automountServiceAccountToken: false` on the pod spec. For pods that DO call the K8s API, also enable BoundServiceAccountTokenVolume (default in K8s ≥ 1.21) and review the ServiceAccount's RBAC scope. Workloads using IRSA / Pod Identity for AWS API access do not need a Kubernetes API token by default.

---

### CTL.EKS.PODIDENTITY.DEFAULTNS.001

**EKS Pod Identity Association In default Namespace**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-4; soc2: CC6.1, CC6.6;

EKS Pod Identity association binds an IAM role to a ServiceAccount in the `default` namespace. The default namespace has no RBAC isolation from cluster-default identity scope; in shared / multi-tenant clusters every team has at least read access to the default namespace by convention. A Pod Identity binding there grants the IAM role to whichever pod ends up using that ServiceAccount — which in shared clusters can be many unrelated workloads. Pod Identity associations should always be in application-specific namespaces.

**Remediation:** Move the workload to an application-specific namespace with proper RBAC isolation. Recreate the Pod Identity association pointing at the new namespace + SA. Delete the default-namespace association. As a forward-looking governance move, consider an admission policy that blocks new workloads in default.

---

### CTL.EKS.PODIDENTITY.GHOST.SA.001

**EKS Pod Identity Association References Deleted ServiceAccount**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, CM-2; iso_27001_2022: A.5.15, A.5.16, A.8.32; nist_800_53_r5: AC-3, CM-2, CM-3; soc2: CC6.1, CC8.1, CC7.4;

EKS Pod Identity association binds an IAM role to a specific Kubernetes ServiceAccount. When the ServiceAccount is deleted but the Pod Identity association persists, the association is a ghost grant. If the ServiceAccount is later recreated with the same name in the same namespace — by Helm chart redeploy, manifest reapply, or namespace recreation — the new SA inherits the original Pod Identity binding. Same ghost-reference pattern as IRSA OIDC ghosts but on the newer Pod Identity surface.

**Remediation:** Delete the orphan association via aws eks delete-pod-identity-association. Audit cluster Pod Identity associations against current ServiceAccounts (kubectl get sa -A) — every association's serviceAccount + namespace pair should resolve to a live SA.

---

### CTL.EKS.PROXY.BYPASS.001

**EKS Cluster Must Configure Proxy When VPC Uses Proxy-Mode Firewall**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

EKS pods do not have HTTP_PROXY/HTTPS_PROXY configured — when the VPC uses Network Firewall in proxy mode, pod egress traffic bypasses the firewall. For EKS, proxy configuration should be enforced via admission controller, init container, or node-level environment variable injection — not per-pod configuration which is error-prone and impossible to audit at scale.

**Remediation:** Configure proxy environment variables at the node level or use a mutating admission webhook to inject HTTP_PROXY and HTTPS_PROXY into all pod specs automatically.

---

### CTL.EKS.PSA.AUDITONLY.001

**EKS Namespace Has PSA In Audit-Only Mode On Production Workload**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, SI-3; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, CM-2, SI-3; soc2: CC6.1, CC8.1;

EKS production namespace has PSA configured with audit / warn but no enforce — non-compliant pods generate audit events but are still admitted. PSA's audit and warn modes exist for measuring compliance during migration; running them indefinitely on production without enforce means insecure pods continue to land while auditors see "PSA is configured" reports.

**Remediation:** Promote audit / warn to enforce after a measurement period (typically 2-4 weeks of audit events review). Set:
  pod-security.kubernetes.io/enforce=restricted
leaving audit / warn at the same level for cross-check. If the namespace has legitimate violations at the chosen level, exempt them via per-pod annotations rather than weakening the namespace-wide enforce.

---

### CTL.EKS.PSA.MISSING.001

**EKS Namespace Has No Pod Security Admission Enforcement Label**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, SI-3; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, CM-2, SI-3; pci_dss_v4.0: 1.4, 2.2; soc2: CC6.1, CC6.6;

EKS namespace has no `pod-security.kubernetes.io/enforce` label. Without an enforce label, every pod admitted to the namespace can run with any security profile — `privileged: true`, host network, host path mounts, root user — without admission rejecting it. PSA replaced PodSecurityPolicy in K8s 1.25; clusters that skipped the PSA migration have no namespace-level pod-security floor.

**Remediation:** Apply a PSA enforce label appropriate to the workload profile. For production application namespaces:
  kubectl label ns <namespace> \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted
For workloads needing elevated privileges, use `baseline` rather than `privileged` and document the reason in the namespace's annotations.

---

### CTL.EKS.PSA.PRIVILEGED.PROD.001

**EKS Production Namespace Has PSA enforce=privileged**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, SI-3; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, CM-2, SI-3; pci_dss_v4.0: 1.4, 2.2; soc2: CC6.1, CC6.6;

EKS namespace tagged as production carries the PSA label `pod-security.kubernetes.io/enforce: privileged` — the weakest profile, equivalent to no enforcement. The label exists, satisfies "every namespace has a PSA label" audits, but admits any pod regardless of security context. Common cause: namespace inherited the label during PSA migration with intent to tighten later, never tightened.

**Remediation:** Tighten the enforce level. Most application namespaces should be `restricted` (denies privileged, host*, root). Workloads that legitimately need host access — typically DaemonSets like CNI plugins, monitoring agents — should live in dedicated namespaces with `baseline` (denies privileged but allows hostNetwork) rather than the application namespace.

---

### CTL.EKS.PUBLIC.ENDPOINT.001

**EKS Public API Endpoint Must Restrict Access with CIDR Allowlists**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_eks: 2.2; fedramp_moderate: SC-7; nist_800_53_r5: AC-17;

EKS clusters with public API endpoints must restrict access to specific CIDR ranges. An unrestricted public endpoint (0.0.0.0/0) allows any internet IP to reach the API server, enabling credential-based attacks from anywhere.

**Remediation:** Option 1 (preferred): Disable public endpoint entirely. Option 2: Restrict to specific CIDRs (corporate NAT, VPN, CI/CD). aws eks update-cluster-config --name <cluster> --resources-vpc-config endpointPublicAccess=true, publicAccessCidrs="10.0.0.0/8,203.0.113.0/24"

---

### CTL.EKS.PV.RELEASED.STALE.001

**EKS PersistentVolume In Released State Over 30 Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: CM-2, CM-8; soc2: CC8.1;

EKS PersistentVolume in `Released` phase — its bound PVC was deleted but the PV itself remains with the data intact (default reclaim policy is `Retain` for manually-provisioned PVs, `Delete` for dynamically-provisioned). PVs in Released state are operationally orphan: not bound to any PVC, not consumable by new PVCs without manual edit, but still consuming the underlying EBS / EFS storage cost. After 30+ days of Released, the data is either decommissioned (and the PV should be deleted) or someone forgot about it.

**Remediation:** Decide: delete the PV (kubectl delete pv) — its underlying storage is also released — OR re-bind by creating a matching PVC with the same name. For PVs that contain data still needed, snapshot the underlying EBS / EFS first, then attach to a new PVC in the workload's current namespace.

---

### CTL.EKS.PVC.GHOST.STORAGECLASS.001

**EKS PersistentVolumeClaim References Deleted StorageClass**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.13, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC8.1, A1.1, CC7.4;

PersistentVolumeClaim's `storageClassName` references a StorageClass that no longer exists. New PVCs / pods needing storage from this PVC stall in `Pending` — dynamic provisioning can't proceed because the StorageClass is missing. Existing PVs continue serving bound PVCs, masking the failure until pod recycling triggers a new bind.

**Remediation:** Recreate the StorageClass at the original name (often `gp2` / `gp3` with cluster-default annotation), or update the PVC's storageClassName to a live class. Audit cluster PVCs via kubectl get pvc -A and verify every storageClassName resolves to a live StorageClass.

---

### CTL.EKS.RAM.EXTERNAL.001

**EKS Cluster Shared Via RAM With External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

EKS cluster (or cluster-related shared resources — shared subnets, transit gateway attachments) is shared via AWS Resource Access Manager (RAM) with accounts outside the AWS Organization, without an `aws:PrincipalOrgID` condition restricting access. External accounts get cluster-adjacent permissions that are difficult to audit at the EKS layer because the trust is established at the RAM layer.

**Remediation:** Restrict RAM share to accounts within the org by adding `aws:PrincipalOrgID` condition. For legitimately external collaborators, use a dedicated cluster (per-tenant clusters) rather than RAM-share. Audit current RAM shares:
  aws ram get-resource-share-associations
    --association-type RESOURCE
and remove any non-org principals.

---

### CTL.EKS.RBAC.AUDIT.001

**EKS Cluster Must Not Grant cluster-admin to Service Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.1.1; nist_800_53_r5: AC-6;

EKS clusters must not bind the cluster-admin ClusterRole to service accounts. The cluster-admin role grants unrestricted access to every resource in every namespace. When a service account holds this binding, any pod running under that service account inherits full cluster control. An attacker who compromises a single workload can escalate to cluster-admin privileges by reading the mounted service account token. Legitimate automation rarely needs cluster-wide admin access — most controllers operate within a bounded set of API groups. A cluster-admin binding to a service account turns a container escape into a full cluster compromise with no additional exploit required.

**Remediation:** Remove the cluster-admin binding from the service account. Create a scoped ClusterRole or Role with only the API groups and verbs the workload actually needs. Bind that scoped role to the service account instead. Audit all ClusterRoleBindings with kubectl get clusterrolebindings -o json and filter for subjects of kind ServiceAccount bound to cluster-admin.

---

### CTL.EKS.RBAC.GHOST.ROLEREF.001

**EKS RoleBinding Or ClusterRoleBinding References Deleted Role**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, CM-2; iso_27001_2022: A.5.15, A.5.16, A.8.32; nist_800_53_r5: AC-3, CM-2, CM-3; soc2: CC6.1, CC8.1, CC7.4;

RoleBinding or ClusterRoleBinding's `roleRef` points at a Role / ClusterRole that no longer exists. The binding is inert — kubectl auth checks against it return "no" because the role can't resolve. But the binding persists in cluster state. If the role is later recreated under the same name with broader scope than the original, the binding's subjects silently inherit the new permissions.

**Remediation:** Delete the orphan binding via kubectl delete rolebinding / clusterrolebinding <name>. If the role name will be reused, audit who the binding granted to BEFORE deletion to confirm the intended grants.

---

### CTL.EKS.RBAC.GHOST.SUBJECT.001

**EKS RoleBinding Or ClusterRoleBinding References Deleted Subject**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, CM-2; iso_27001_2022: A.5.15, A.5.16, A.8.32; nist_800_53_r5: AC-3, CM-2, CM-3; soc2: CC6.1, CC8.1, CC7.4;

RoleBinding or ClusterRoleBinding has a subject — ServiceAccount, User, or Group — that no longer exists. The binding persists with permissions still attached. The same name-reuse problem as aws-auth ghost roles: if a ServiceAccount is recreated with the same name + namespace (Helm reapply, namespace recreation), it inherits the ghost binding's permissions automatically.

**Remediation:** Delete the binding (kubectl delete rolebinding / clusterrolebinding <name>) OR remove the orphan subject from the subjects list. Audit cluster bindings via `kubectl get clusterrolebinding,rolebinding -A -o yaml` and verify every subject resolves: ServiceAccounts via kubectl get sa, Users / Groups via the cluster's auth provider.

---

### CTL.EKS.SECRETS.ENCRYPT.001

**EKS Kubernetes Secrets Must Be Encrypted with KMS CMK**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_eks: 2.3; fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28;

EKS clusters must encrypt Kubernetes secrets at rest using a customer-managed KMS key. Without envelope encryption, anyone with access to the etcd backup or underlying EBS volume can read all cluster secrets (API tokens, database passwords, TLS certificates) in plaintext.

**Remediation:** Enable secrets encryption: aws eks associate-encryption-config --cluster-name <cluster> --encryption-config '[{"resources":["secrets"],"provider": {"keyArn":"arn:aws:kms:<region>:<account>:key/<key-id>"}}]'

---

### CTL.EKS.SECRETS.ENCRYPT.CMK.001

**EKS Secrets Envelope Encryption Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

EKS clusters with secrets encryption enabled must use a customer-managed KMS key for the envelope encryption provider, not the AWS-managed default. The AWS-managed key provides no key-policy control, no custom rotation schedule, and no ability to revoke access to Kubernetes secrets during an incident. EKS secrets store credentials, tokens, and TLS certificates; the KMS key wraps the data-encryption key that protects them in etcd.

**Remediation:** Create a customer-managed KMS key with a key policy scoped to the EKS service principal. Update the cluster encryption config with aws eks associate-encryption-config --cluster-name <name> --encryption-config '[{"provider":{"keyArn":"<cmk-arn>"}, "resources":["secrets"]}]'.

---

### CTL.EKS.SECRETS.ROTATION.001

**KMS Key for EKS Secrets Encryption Must Have Rotation Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** mitre_attack: TA0006; nist_800_53_r5: SC-12; owasp_nhi: NHI7;

EKS envelope encryption uses a KMS CMK to encrypt the data encryption key protecting Kubernetes secrets. A compromised KMS key grants permanent access to all secrets encrypted with it — without rotation, a leaked or compromised key remains valid indefinitely. Annual KMS key rotation limits the window of exposure. Each rotation generates a new key version — previous versions remain available for decryption but new encryptions use the current version.

**Remediation:** Enable automatic rotation on the KMS key: aws kms enable-key-rotation --key-id <key-id>

---

### CTL.EKS.SERVICE.GHOST.SG.001

**EKS LoadBalancer Service Annotation References Deleted Security Group**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, AC-3; iso_27001_2022: A.5.15, A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, AC-3; soc2: CC6.1, CC8.1, CC7.4;

EKS Service of type `LoadBalancer` has the `service.beta.kubernetes.io/aws-load-balancer-security-groups` (or NLB equivalent) annotation pointing at one or more security group IDs that no longer exist. The AWS-load-balancer-controller's reconcile cycle attempts to attach the SGs to the ELB; AWS rejects the call with InvalidSecurityGroup. The Service can't reach Ready; existing traffic routing through a previously-provisioned ELB continues but reconfiguration / ELB recreation fails.

**Remediation:** Update the Service's `service.beta.kubernetes.io/aws-load-balancer-security-groups` annotation to a live SG ID (kubectl edit svc <name>), or recreate the SG at the original ID if reproducible. Pair with VPC SG ghost detection (CTL.VPC.SG.GHOST.001) to catch the SG-deletion event earlier.

---

### CTL.EKS.SERVICE.LB.NOENDPOINTS.001

**EKS LoadBalancer Service Has Zero Endpoints**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: CM-2, CM-8; soc2: CC8.1, A1.1;

EKS Service of type `LoadBalancer` has zero endpoints (no Ready pods match the Service's selector). The ELB / ALB exists in AWS, billed hourly, with no traffic targets. Common causes: workload renamed / labels changed but Service selector wasn't updated, workload deleted but Service wasn't, or all matching pods evicted / CrashLooping. The Service still resolves DNS; clients connect; ELB returns 503s.

**Remediation:** Diagnose root cause: Service selector vs pod labels mismatch (kubectl get pods -l <selector>); workloads CrashLooping (kubectl get pods); workloads scaled to zero. Either fix the underlying workload, update the Service selector, or delete the Service if the workload is decommissioned (also tear down the ELB AWS cost).

---

### CTL.EKS.STORAGECLASS.GHOST.KMS.001

**EKS StorageClass References Deleted KMS Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SC-12; iso_27001_2022: A.5.16, A.8.24, A.8.32; nist_800_53_r5: CM-2, CM-3, SC-12; soc2: CC6.1, CC8.1, CC7.4;

StorageClass parameters reference a KMS key (kmsKeyId for EBS CSI; encryption KeyId for FSx) that has been deleted. Existing volumes encrypted with the key continue to be decryptable so long as the key exists in PendingDeletion / Disabled state, but new volume provisioning fails. Combined with the key actually being deleted past the recovery window, existing volumes also become unrecoverable. The same control fires whether the key is pending deletion (catch up via KMS-1 cross-cut) or fully gone — it's the EKS-side check that the StorageClass references a key the cluster can still use.

**Remediation:** Cancel the key deletion if it's within the recovery window (aws kms cancel-key-deletion); update the StorageClass parameters to a live KMS key ARN; re-encrypt affected volumes by snapshot-and-restore onto the new key. Pair with a CloudWatch alarm on KMS DisableKey / ScheduleKeyDeletion / DeleteAlias for keys referenced by StorageClasses.

---

### CTL.EKS.STORAGECLASS.GP2DEFAULT.001

**EKS Cluster Default StorageClass Is gp2**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16; nist_800_53_r5: CM-2; soc2: CC8.1, A1.1;

EKS cluster has gp2 marked as the default StorageClass (`storageclass.kubernetes.io/is-default-class: "true"`). gp2 is the legacy AWS EBS general-purpose volume type — superseded by gp3, which AWS prices lower, performs better at small sizes, and supports independent IOPS / throughput tuning. New clusters should default to gp3; existing clusters should migrate.

**Remediation:** Create a gp3 StorageClass with the default annotation, then remove the default annotation from gp2. Existing PVs bound to gp2 continue to function; new PVCs without an explicit storageClassName get gp3. Migrate existing volumes by snapshot + restore onto a new gp3 PV at the application's next maintenance window.

---

### CTL.EKS.STORAGECLASS.NOTENCRYPTED.001

**EKS StorageClass Provisions Unencrypted Volumes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12, SC-28; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1, CC6.7;

EKS StorageClass parameters don't include `encrypted: "true"` (for EBS CSI) or equivalent encryption flag. PVCs using the StorageClass dynamically provision EBS volumes without encryption at rest. Workload data on these volumes is unprotected; AWS account-level default encryption may catch it (if enabled), but StorageClass-level explicit encryption is the documented EKS pattern.

**Remediation:** Update StorageClass parameters to include encrypted: "true" plus optional kmsKeyId for CMK encryption:
  apiVersion: storage.k8s.io/v1
  kind: StorageClass
  metadata: { name: gp3-encrypted }
  provisioner: ebs.csi.aws.com
  parameters:
    type: gp3
    encrypted: "true"
    kmsKeyId: "arn:aws:kms:us-east-1:111122223333:key/abc"
For new clusters, also enable EBS account-level default encryption as defense in depth.

---

### CTL.EKS.STORAGECLASS.NOWAITFORCONSUMER.001

**EKS StorageClass volumeBindingMode Is Immediate Not WaitForFirstConsumer**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.13; nist_800_53_r5: CM-2; soc2: CC8.1, A1.1;

EKS StorageClass has `volumeBindingMode: Immediate` (or unset, defaulting Immediate). With Immediate binding, dynamic PV provisioning happens at PVC creation time — the PV is created in whatever AZ the provisioner picks, before the consuming pod is scheduled. The pod is then constrained to the AZ where its PV lives. WaitForFirstConsumer delays provisioning until the pod is scheduled, letting the scheduler pick the optimal AZ.

**Remediation:** Update the StorageClass to use volumeBindingMode: WaitForFirstConsumer:
  apiVersion: storage.k8s.io/v1
  kind: StorageClass
  metadata: { name: gp3 }
  provisioner: ebs.csi.aws.com
  volumeBindingMode: WaitForFirstConsumer
Existing PVs are unaffected; new PVCs get the new binding behavior. WaitForFirstConsumer is the Kubernetes-recommended default for cloud-provider storage that's AZ-bound.

---

### CTL.EKS.VELERO.RESTORE.SCOPE.001

**EKS Velero Backup Restorable Across Cluster Boundaries Without Scope Check**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, CP-9; iso_27001_2022: A.5.15, A.8.13; nist_800_53_r5: AC-3, AC-4, CP-9; soc2: CC6.1, CC6.6, A1.2;

EKS Velero backups are stored in an S3 bucket that multiple clusters can read from / restore from without per-cluster scope validation. A backup taken from one cluster — including its Secrets, ConfigMaps, RBAC, and resource definitions — can be restored to a different cluster without guardrails. Cross-cluster restore is occasionally intentional (DR pattern); unrestricted access is a tenant-data-leakage surface.

**Remediation:** Per-cluster S3 bucket prefixes with bucket policies restricting reads to that cluster's IAM role. Or per-cluster KMS keys for backup encryption — a different cluster can list the backups but can't decrypt without the source cluster's KMS access. Document the DR plan that distinguishes intentional cross-cluster restore (DR) from accidental cross-cluster overwrite.

---

### CTL.EKS.VERSION.001

**EKS Clusters Must Not Run Deprecated Kubernetes Versions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-6; hipaa: 164.312(a)(2)(i); nist_800_53_r5: CM-6; pci_dss_v4.0: 2.2.1; soc2: CC7.1;

EKS clusters must not run Kubernetes versions that have reached end-of-support. AWS publishes a Kubernetes version support lifecycle for EKS — each minor version is supported for approximately 14 months after release. After end-of-support, the cluster no longer receives security patches for the Kubernetes control plane or EKS-managed components. Kubernetes has a high rate of critical CVEs affecting the API server, kubelet, and container runtime. An EKS cluster on a deprecated version is running an unpatched control plane against which known exploits exist. EKS version upgrades require a defined upgrade path and may involve breaking API changes, causing clusters to accumulate version debt due to upgrade friction rather than deliberate choice. For organizations that have invested in Kubernetes network policies, RBAC, and secrets encryption, running a deprecated control plane version undermines every other security control in the cluster.

**Remediation:** Upgrade the EKS cluster to a supported Kubernetes version. Review the AWS EKS Kubernetes version support lifecycle for the current end-of-support dates. Follow the EKS upgrade guide — upgrade one minor version at a time. Test workloads against the new version in a staging cluster before upgrading production. Check for deprecated API usage with kubectl deprecations or the Kubernetes API deprecation guide for your target version.

---

### CTL.EKS.VPC.CNI.CUSTOMNETWORKING.001

**EKS VPC CNI Custom Networking Enabled But Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SC-7; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: CM-2, AC-4, SC-7; soc2: CC6.1, CC8.1;

EKS VPC CNI add-on has AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG=true (custom networking enabled) but no ENIConfig CRDs are created in the cluster. Pods get IPs from the default subnet ranges instead of the custom per-AZ subnets the operator intended to provision. Multi-tenant clusters depending on custom networking for IP isolation lose the isolation; pods land in the wrong subnets.

**Remediation:** Create ENIConfig CRDs per AZ, each pointing at the custom subnet for that AZ:
  apiVersion: crd.k8s.amazonaws.com/v1alpha1
  kind: ENIConfig
  metadata: { name: us-east-1a }
  spec:
    securityGroups: [sg-...]
    subnet: subnet-...
Then label each node with its AZ's ENIConfig via the VPC CNI's ENI_CONFIG_LABEL_DEF environment variable. Verify pod IPs land in the custom subnets via `kubectl get pods -A -o wide`.

---

### CTL.EKS.VPC.CNI.NETPOL.TTL.001

**EKS VPC CNI NetworkPolicy Must Have Completed Pod Firewall Cleanup**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: TA0008; nist_800_53_r5: AC-4;

EKS clusters with VPC CNI NetworkPolicy enforcement must have completed pod firewall rule cleanup configured. VPC CNI creates per-IP firewall rules on nodes. Pod completion does not trigger rule removal — only pod deletion does. Without TTL controller or explicit flush, completed pod IPs are recycled with stale rules.

**Remediation:** Option 1: Enable the TTLAfterFinished feature gate at cluster level. Option 2: Set ttlSecondsAfterFinished on all Job specs. Option 3: Update VPC CNI to a version with pod completion handling. Verify VPC CNI version:
  kubectl describe daemonset aws-node -n kube-system | grep Image

---

### CTL.EKS.WORKLOAD.GHOST.IMAGE.001

**EKS Workload References Image From Deleted ECR Repository**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SI-4; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-4; soc2: CC6.1, CC8.1, CC7.4;

EKS workload (Deployment / StatefulSet / DaemonSet / Job / Pod) specifies a container image whose ECR repository has been deleted. Pod scheduling proceeds; the kubelet attempts ImagePullBackOff and never recovers. New pods can't start — scaling, rolling updates, and node replacements all silently break. Existing pods continue running on cached layers but become unrunable when their nodes recycle.

**Remediation:** Either recreate the ECR repo + republish the expected image, or update the workload spec to point at a live repository (kubectl set image deploy/<name> container=<new-image>). For the long term: add an ECR repository policy that prevents accidental deletion plus a CloudWatch alarm on DeleteRepository events.

---


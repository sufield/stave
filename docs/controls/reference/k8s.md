# Control Reference — K8S

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.K8S.APISERVER.ADM.CTRL.001

**API Server Must Enable AlwaysPullImages Admission Controller**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.11;

The API server must enable the AlwaysPullImages admission controller. This ensures every new pod always pulls the image, preventing nodes from using cached images that may have been tampered with.

**Remediation:** Add AlwaysPullImages to --enable-admission-plugins on the API server.

---

### CTL.K8S.APISERVER.ADM.CTRL.002

**API Server Must Enable Pod Security Admission**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.12;

The API server must enable PodSecurity or SecurityContextDeny admission controller to enforce pod security standards.

**Remediation:** Add PodSecurity to --enable-admission-plugins on the API server.

---

### CTL.K8S.APISERVER.ADM.CTRL.003

**API Server Must Enable ServiceAccount Admission Controller**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.13;

The API server must enable the ServiceAccount admission controller to automate service account management for pods.

**Remediation:** Add ServiceAccount to --enable-admission-plugins on the API server.

---

### CTL.K8S.APISERVER.ADM.CTRL.004

**API Server Must Enable NodeRestriction Admission Controller**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.16;

The API server must enable the NodeRestriction admission controller to limit what a kubelet can modify, preventing compromised nodes from escalating privileges.

**Remediation:** Add NodeRestriction to --enable-admission-plugins on the API server.

---

### CTL.K8S.APISERVER.ANON.001

**API Server Anonymous Authentication Must Be Disabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.1;

The Kubernetes API server must not allow anonymous authentication. Anonymous auth permits unauthenticated requests to the API, enabling reconnaissance and potential cluster compromise.

**Remediation:** Set --anonymous-auth=false on the API server. For managed clusters, verify the provider disables anonymous auth by default.

---

### CTL.K8S.APISERVER.AUDIT.001

**API Server Audit Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.22;

The Kubernetes API server must have audit logging enabled. Without audit logs, security-relevant API calls are not recorded.

**Remediation:** Configure --audit-policy-file and --audit-log-path on the API server.

---

### CTL.K8S.APISERVER.AUDIT.MAXAGE.001

**API Server Audit Log Retention Must Be At Least 30 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.23;

Audit log retention must be at least 30 days to support incident investigation and compliance evidence requirements.

**Remediation:** Set --audit-log-maxage=30 or higher on the API server.

---

### CTL.K8S.APISERVER.AUDIT.MAXBACKUP.001

**API Server Audit Log Max Backup Must Be At Least 10**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.24;

The API server must retain at least 10 old audit log files before rotation deletes them. Insufficient backup retention limits the availability of historical audit data for incident investigation.

**Remediation:** Set --audit-log-maxbackup=10 or higher on the API server.

---

### CTL.K8S.APISERVER.AUDIT.MAXSIZE.001

**API Server Audit Log Max Size Must Be At Least 100 MB**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.25;

Each audit log file must be allowed to grow to at least 100 MB before rotation. Smaller limits cause frequent rotation that may result in loss of audit records during high-activity periods.

**Remediation:** Set --audit-log-maxsize=100 or higher on the API server.

---

### CTL.K8S.APISERVER.AUTHZ.001

**API Server Must Use RBAC Authorization**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.7;

The API server authorization mode must include RBAC and must not include AlwaysAllow. RBAC enforces fine-grained access control; AlwaysAllow permits any authenticated user to perform any action.

**Remediation:** Set --authorization-mode=RBAC,Node on the API server. Remove AlwaysAllow from the mode list.

---

### CTL.K8S.APISERVER.CLIENT.CA.001

**API Server Client CA Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.29;

The API server must be configured with a client certificate authority file to verify client certificates for mutual TLS authentication.

**Remediation:** Set --client-ca-file on the API server pointing to the cluster CA.

---

### CTL.K8S.APISERVER.ENCRYPT.PROV.001

**API Server Encryption Provider Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.30;

The API server must have an encryption provider configuration set via --encryption-provider-config. Without this, Kubernetes secrets are stored unencrypted in etcd, exposing sensitive data to anyone with etcd access.

**Remediation:** Set --encryption-provider-config on the API server pointing to an EncryptionConfiguration resource that uses aescbc, secretbox, or a KMS provider.

---

### CTL.K8S.APISERVER.ETCD.CERT.001

**API Server Must Use TLS for etcd Communication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.32;

The API server must present a client certificate when connecting to etcd. Without mutual TLS, API server to etcd traffic is unauthenticated and unencrypted.

**Remediation:** Set --etcd-certfile and --etcd-keyfile on the API server.

---

### CTL.K8S.APISERVER.INSECURE.PORT.001

**API Server Insecure Port Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.19;

The API server insecure port must be set to 0 (disabled). The insecure port serves requests without authentication or authorization, allowing unrestricted access to the Kubernetes API.

**Remediation:** Set --insecure-port=0 on the API server. This flag is deprecated in recent Kubernetes versions and will be removed.

---

### CTL.K8S.APISERVER.KUBELET.CERT.001

**API Server Kubelet Certificate Authority Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.5;

The API server must have --kubelet-certificate-authority configured to verify kubelet serving certificates. Without this, the API server cannot authenticate kubelet endpoints, enabling man-in-the-middle attacks on API-server-to-kubelet communication.

**Remediation:** Set --kubelet-certificate-authority on the API server pointing to the CA bundle used to sign kubelet serving certificates.

---

### CTL.K8S.APISERVER.PROFILING.001

**API Server Profiling Must Be Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.18;

The API server profiling endpoint must be disabled. Profiling exposes system and program details useful for attackers to identify vulnerabilities and plan exploitation.

**Remediation:** Set --profiling=false on the API server.

---

### CTL.K8S.APISERVER.SA.KEY.001

**API Server Service Account Key File Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.28;

The API server must be configured with --service-account-key-file to verify service account tokens with a dedicated key pair.

**Remediation:** Set --service-account-key-file on the API server.

---

### CTL.K8S.APISERVER.TLS.CERT.001

**API Server TLS Certificate Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.26;

The API server must be configured with a TLS serving certificate. Without TLS, API traffic is transmitted in cleartext.

**Remediation:** Set --tls-cert-file and --tls-private-key-file on the API server.

---

### CTL.K8S.APISERVER.TOKEN.AUTH.001

**API Server Static Token Authentication Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.2;

The API server must not use static token authentication via --token-auth-file. Static tokens do not expire, cannot be revoked without restarting the API server, and are stored in cleartext.

**Remediation:** Remove --token-auth-file from the API server configuration. Use OIDC, service account tokens, or certificate-based authentication.

---

### CTL.K8S.AUDIT.001

**Kubernetes Audit Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 3.2.1; hipaa: 164.312(b); soc2: CC7.1;

The Kubernetes API server must have audit logging enabled. Without audit logs, API calls (including unauthorized access attempts) are not recorded for forensic analysis.

**Remediation:** Configure the API server with --audit-policy-file and --audit-log-path. For managed clusters (EKS, GKE), enable control plane logging via the cloud provider console.

---

### CTL.K8S.AUTH.ACCESSKEYMAP.001

**K8s Clusters Must Not Map Identity via AccessKeyID**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_k8s_v1.8.0: 3.1.1; nist_800_53_r5: IA-2; soc2: CC6.1;

Kubernetes clusters using AWS IAM Authenticator must not use {{AccessKeyID}} in identity mapping templates. The AccessKeyID is extracted from client-supplied presigned URL query parameters, not from the STS response, making it vulnerable to parameter injection via case-variant duplication.

**Remediation:** Replace {{AccessKeyID}} with {{SessionName}} or use ARN-based mapping (userARN matching) without template substitution. ARN and SessionName come from the STS GetCallerIdentity response and cannot be manipulated by the client.

---

### CTL.K8S.CM.BIND.ADDR.001

**Controller Manager Must Bind to Loopback Address**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.7;

The controller manager must bind to a loopback address (127.0.0.1 or ::1). Binding to 0.0.0.0 or a routable address exposes the controller manager's unsecured HTTP endpoints to the network.

**Remediation:** Set --bind-address=127.0.0.1 on the controller manager.

---

### CTL.K8S.CM.GC.001

**Controller Manager Terminated Pod GC Threshold Must Be Set**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.1;

The controller manager must have a positive terminated pod garbage collection threshold to prevent resource exhaustion from accumulated terminated pods.

**Remediation:** Set --terminated-pod-gc-threshold to a positive value (e.g. 12500).

---

### CTL.K8S.CM.PROFILING.001

**Controller Manager Profiling Must Be Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.2;

The controller manager profiling endpoint must be disabled. Profiling exposes system and program details useful for attackers to identify vulnerabilities and plan privilege escalation.

**Remediation:** Set --profiling=false on the controller manager.

---

### CTL.K8S.CM.ROOT.CA.001

**Controller Manager Root CA File Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.5;

The controller manager must have --root-ca-file configured. This CA bundle is injected into each service account token secret, allowing pods to verify the API server's TLS certificate and preventing man-in-the-middle attacks.

**Remediation:** Set --root-ca-file on the controller manager pointing to the cluster CA bundle.

---

### CTL.K8S.CM.ROTATE.CERTS.001

**Controller Manager Must Enable RotateKubeletServerCertificate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.6;

The controller manager must enable the RotateKubeletServerCertificate feature gate. This allows the kubelet to request and rotate its serving certificate automatically, preventing certificate expiry and ensuring continued TLS for kubelet endpoints.

**Remediation:** Set --feature-gates=RotateKubeletServerCertificate=true on the controller manager.

---

### CTL.K8S.CM.SA.CREDS.001

**Controller Manager Must Use Individual Service Account Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.3;

The controller manager must use individual service account credentials for each controller. Without this, all controllers share the controller manager's credentials, violating least privilege.

**Remediation:** Set --use-service-account-credentials=true on the controller manager.

---

### CTL.K8S.CM.SA.KEY.001

**Controller Manager Service Account Private Key Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.4;

The controller manager must have a service account private key file configured for signing service account tokens.

**Remediation:** Set --service-account-private-key-file on the controller manager.

---

### CTL.K8S.ETCD.AUTO.TLS.001

**etcd Auto-TLS Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.3;

etcd auto-TLS generates self-signed certificates without CA validation, providing encryption without authentication. An attacker can MITM the connection with their own self-signed cert.

**Remediation:** Set --auto-tls=false and configure proper CA-signed certificates.

---

### CTL.K8S.ETCD.CERT.001

**etcd Must Use TLS Certificates**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.1;

etcd must be configured with TLS certificate and key files. Without TLS, all cluster state (including Secrets) is transmitted in cleartext.

**Remediation:** Set --cert-file and --key-file on the etcd server.

---

### CTL.K8S.ETCD.CLIENT.AUTH.001

**etcd Client Certificate Authentication Must Be Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.2;

etcd must require client certificate authentication. Without it, any client with network access to etcd can read and write all cluster state.

**Remediation:** Set --client-cert-auth=true on the etcd server.

---

### CTL.K8S.ETCD.PEER.AUTO.TLS.001

**etcd Peer Auto-TLS Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.6;

etcd peer auto-TLS uses self-signed certificates for cluster member communication without CA validation. A rogue etcd member can join the cluster and exfiltrate all data.

**Remediation:** Set --peer-auto-tls=false and configure --peer-cert-file, --peer-key-file, and --peer-trusted-ca-file.

---

### CTL.K8S.ETCD.PEER.CERT.001

**etcd Peer Certificate File Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.4;

etcd must be configured with a peer certificate file for mutual TLS between etcd cluster members. Without peer TLS, inter-node etcd communication is unencrypted and unauthenticated, allowing cluster state interception or injection.

**Remediation:** Set --peer-cert-file on the etcd server pointing to a valid TLS certificate for peer communication.

---

### CTL.K8S.ETCD.PEER.KEY.001

**etcd Peer Key File Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.5;

etcd must be configured with a peer key file for mutual TLS between etcd cluster members. Without the private key, peer TLS cannot be established and inter-node communication is insecure.

**Remediation:** Set --peer-key-file on the etcd server pointing to the private key corresponding to the peer certificate.

---

### CTL.K8S.EXEC.RESTRICT.001

**kubectl exec Must Be Restricted via RBAC to Authorized Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_k8s_v1.9: 5.1.3; mitre_attack: T1609; nist_800_53_r5: AC-3;

kubectl exec (pods/exec) allows executing commands in running pods. Granting this to service accounts or broad principals enables arbitrary code execution in any pod the principal can target. An attacker who compromises a principal with pods/exec access can run commands in privileged pods, access secrets mounted in other pods, and pivot to the host if any pod runs with elevated privileges.

**Remediation:** Audit all ClusterRoles and Roles granting pods/exec. Restrict pods/exec to named developer roles with namespace scope, not cluster-wide roles. Remove pods/exec from service account bindings.

---

### CTL.K8S.IMDS.BLOCK.001

**Cluster Must Have NetworkPolicy Blocking Pod Egress to IMDS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: TA0006; nist_800_53_r5: AC-4; owasp_subtractive: S01; subtractive_tier: deletion;

Kubernetes clusters must have a NetworkPolicy blocking pod egress to the cloud instance metadata service at 169.254.169.254. A pod with hostNetwork=true and CAP_NET_RAW can intercept IMDS traffic and inject crafted responses containing attacker-controlled SSH keys, gaining root access to the node. A NetworkPolicy blocking 169.254.169.254/32 egress prevents this escalation even when pod security controls fail.

**Remediation:** Apply a NetworkPolicy in every namespace blocking egress to 169.254.169.254/32. For AWS, also enforce IMDSv2 with hop limit 1 on all node groups.

---

### CTL.K8S.INCOMPLETE.001

**Complete Data Required for Kubernetes Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Kubernetes cluster safety cannot be assessed when audit logging status is missing from the snapshot. The extractor must populate audit.audit_logging_enabled.

**Remediation:** Re-run the extractor with Kubernetes API access to describe cluster configuration, RBAC, network policies, and secrets.

---

### CTL.K8S.JOB.TTL.001

**Jobs in NetworkPolicy Namespaces Must Configure ttlSecondsAfterFinished**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: TA0008; nist_800_53_r5: AC-4;

Kubernetes Jobs in namespaces with active NetworkPolicy must set ttlSecondsAfterFinished to limit completed pod residency. The VPC CNI controller does not flush NetworkPolicy firewall rules when a pod reaches Completed state. Without TTL, completed pod IPs are recycled with stale firewall rules attached, silently granting new pods the original pod's network access.

**Remediation:** Add ttlSecondsAfterFinished (60-300 seconds) to all Job specs in namespaces with NetworkPolicy. For cluster-wide enforcement, use a policy engine (OPA/Kyverno) to require this field.

---

### CTL.K8S.KUBELET.ANON.001

**Kubelet Anonymous Authentication Must Be Disabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.1;

The kubelet must not allow anonymous authentication. Anonymous auth permits unauthenticated requests to the kubelet API, enabling pod listing, log access, and command execution on the node.

**Remediation:** Set authentication.anonymous.enabled=false in the kubelet config or pass --anonymous-auth=false.

---

### CTL.K8S.KUBELET.AUTHZ.001

**Kubelet Must Not Use AlwaysAllow Authorization**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.2;

The kubelet authorization mode must not be set to AlwaysAllow. AlwaysAllow permits any authenticated request without RBAC checks.

**Remediation:** Set authorization.mode=Webhook in the kubelet config or pass --authorization-mode=Webhook.

---

### CTL.K8S.KUBELET.CLIENT.CA.001

**Kubelet Client CA Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.3;

The kubelet must be configured with a client CA file to verify client certificates for x509 authentication.

**Remediation:** Set authentication.x509.clientCAFile in the kubelet config.

---

### CTL.K8S.KUBELET.EVENTRECORD.001

**Kubelet Event Record QPS Must Be Greater Than Zero**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.9;

The kubelet event record QPS must be greater than zero. Setting this to zero disables event creation, hiding node-level events from the API server and preventing detection of security-relevant activities.

**Remediation:** Set eventRecordQPS to a value greater than 0 (default is 5) in the kubelet config.

---

### CTL.K8S.KUBELET.HOSTNAME.001

**Kubelet Hostname Override Should Not Be Set**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.8;

The kubelet should not have --hostname-override set. Overriding the hostname can interfere with TLS certificate validation and node identity verification, as certificates are typically issued for the actual hostname.

**Remediation:** Remove --hostname-override from the kubelet configuration. If hostname override is required for cloud provider integration, ensure certificates match the overridden name.

---

### CTL.K8S.KUBELET.KERNEL.001

**Kubelet Must Protect Kernel Defaults**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.6;

The kubelet must set protectKernelDefaults to true. This prevents pods from modifying kernel parameters that could weaken node security or enable privilege escalation.

**Remediation:** Set protectKernelDefaults=true in the kubelet config.

---

### CTL.K8S.KUBELET.READONLY.001

**Kubelet Read-Only Port Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.4;

The kubelet read-only port (default 10255) must be disabled by setting it to 0. The read-only port exposes node and pod metrics without authentication.

**Remediation:** Set readOnlyPort=0 in the kubelet config or pass --read-only-port=0.

---

### CTL.K8S.KUBELET.ROTATE.001

**Kubelet Certificate Rotation Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.11;

The kubelet must have certificate rotation enabled to automatically renew its client and serving certificates before expiry.

**Remediation:** Set rotateCertificates=true in the kubelet config.

---

### CTL.K8S.KUBELET.ROTATE.SERVER.001

**Kubelet Server Certificate Rotation Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.12;

The kubelet must have server certificate rotation enabled via serverTLSBootstrap or the RotateKubeletServerCertificate feature gate. Without rotation, kubelet serving certificates may expire, breaking TLS for kubelet endpoints.

**Remediation:** Set serverTLSBootstrap=true or featureGates.RotateKubeletServerCertificate=true in the kubelet config.

---

### CTL.K8S.KUBELET.STREAMING.001

**Kubelet Streaming Connection Idle Timeout Must Not Be Zero**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.5;

The kubelet streaming connection idle timeout must be greater than zero. A zero timeout disables connection cleanup, allowing idle streaming connections (exec, attach, port-forward) to persist indefinitely, consuming resources and increasing attack surface.

**Remediation:** Set streamingConnectionIdleTimeout to a non-zero duration (e.g., 4h0m0s) in the kubelet config.

---

### CTL.K8S.KUBELET.TLS.001

**Kubelet TLS Certificate Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.10;

The kubelet must be configured with a TLS serving certificate. Without TLS, kubelet API traffic is transmitted in cleartext.

**Remediation:** Set tlsCertFile and tlsPrivateKeyFile in the kubelet config.

---

### CTL.K8S.NETPOL.001

**Namespaces Must Have Network Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.3.2; hipaa: 164.312(e)(1);

Kubernetes namespaces containing workloads must have at least one NetworkPolicy defined. Without network policies, all pod-to-pod traffic is allowed by default, enabling lateral movement.

**Remediation:** Create a default-deny NetworkPolicy for the namespace, then add explicit allow rules for required traffic flows.

---

### CTL.K8S.NETPOL.DENY.001

**Namespaces Must Have Default-Deny Network Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.3.2;

Namespaces with network policies must include a default-deny ingress policy. Without default-deny, network policies only add allow rules on top of the implicit allow-all default.

**Remediation:** Add a default-deny ingress NetworkPolicy that selects all pods and has no ingress rules.

---

### CTL.K8S.NETPOL.EGRESS.001

**Cluster Must Have Egress Network Policies**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.3.2;

The cluster must have egress network policies defined. Without egress policies, compromised pods can freely communicate with external command-and-control servers, exfiltrate data, or attack other services outside the cluster.

**Remediation:** Create egress NetworkPolicies to restrict outbound traffic from pods to only approved destinations and ports.

---

### CTL.K8S.POD.CAPABILITIES.001

**Containers Must Drop NET_RAW Capability**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.2.7;

Containers must drop the NET_RAW capability. NET_RAW allows crafting raw network packets, enabling ARP spoofing, DNS poisoning, and other network-level attacks from within the container.

**Remediation:** Add NET_RAW to securityContext.capabilities.drop in the container spec. Prefer dropping ALL capabilities and adding back only those required.

---

### CTL.K8S.POD.HOSTIPC.001

**Pods Must Not Share the Host IPC Namespace**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_kubernetes: 5.2.3; nist_800_53_r5: SC-7;

Pods must not enable hostIPC which shares the host's IPC namespace. Shared IPC allows containers to access shared memory segments of other processes on the host, enabling cross-process data access and manipulation.

**Remediation:** Set hostIPC to false in the pod spec.

---

### CTL.K8S.POD.HOSTNET.001

**Pods Must Not Share the Host Network Namespace**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.2.4;

Pods must not share the host network namespace. Sharing the host network gives containers access to all network interfaces and listening services on the node, bypassing network policies and enabling network-level attacks.

**Remediation:** Set hostNetwork=false in the pod spec. Use Kubernetes Services and NetworkPolicies to control network access instead.

---

### CTL.K8S.POD.HOSTPID.001

**Pods Must Not Share the Host PID Namespace**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.2.2;

Pods must not share the host PID namespace. Sharing the host PID namespace allows containers to see and signal all processes on the host, enabling process inspection, injection, and denial of service.

**Remediation:** Set hostPID=false in the pod spec. Remove hostPID sharing unless there is a documented operational requirement.

---

### CTL.K8S.POD.HOSTPORT.001

**Containers Must Not Use Host Ports**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_kubernetes: 5.2.6; nist_800_53_r5: SC-7;

Containers must not declare hostPort, which binds directly to the node's network stack. HostPort bypasses Kubernetes service abstractions and network policies, exposing the container's port on the node's IP address.

**Remediation:** Remove hostPort from container spec. Use Kubernetes Services for port exposure.

---

### CTL.K8S.POD.PRIVILEGED.001

**Containers Must Not Run in Privileged Mode**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.2.1;

Pods must not run privileged containers. Privileged containers have full access to the host's devices, kernel capabilities, and namespaces, effectively granting root-level access to the node.

**Remediation:** Set securityContext.privileged=false on all containers. Use specific capabilities instead of privileged mode.

---

### CTL.K8S.POD.RUNASROOT.001

**Containers Must Not Run as Root**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.2.6;

Containers must not run as the root user. Running as root inside a container increases the impact of container breakout vulnerabilities and grants unnecessary privileges for filesystem and process operations.

**Remediation:** Set securityContext.runAsNonRoot=true and specify a non-root runAsUser in the pod or container security context.

---

### CTL.K8S.POD.SECCOMP.001

**Pods Must Use RuntimeDefault or Localhost Seccomp Profile**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_kubernetes: 5.7.2; nist_800_53_r5: SC-7;

Pods must have a seccomp profile set to RuntimeDefault or Localhost at the pod or container level. Without a seccomp profile, containers run with the full set of available syscalls, increasing the kernel attack surface for container escape.

**Remediation:** Set securityContext.seccompProfile.type to RuntimeDefault.

---

### CTL.K8S.RBAC.DEFAULT.SA.001

**Default Service Account Automount Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.1.5;

The default service account in each namespace must have automountServiceAccountToken set to false. The default service account is shared by all pods that do not specify one, and its token grants unnecessary API access to workloads.

**Remediation:** Set automountServiceAccountToken=false on the default ServiceAccount in each namespace.

---

### CTL.K8S.RBAC.SA.TOKEN.001

**Service Account Token Automount Must Be Opt-In Only**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.1.6;

Service account tokens must not be automatically mounted into pods unless explicitly required. Automatic token mounting provides every pod with API credentials, increasing the blast radius of container compromise.

**Remediation:** Set automountServiceAccountToken=false on ServiceAccounts and only enable it on pods that require API access.

---

### CTL.K8S.RBAC.SERVICEACCOUNT.001

**Default Service Account Must Not Have Active Tokens**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.1.5;

The default service account in each namespace should not have auto-mounted tokens. Pods using the default service account inherit permissions that may allow unintended API access.

**Remediation:** Set automountServiceAccountToken to false on the default service account in every namespace. Create dedicated service accounts with minimal permissions for workloads that need API access.

---

### CTL.K8S.RBAC.WEBHOOK.001

**RBAC Must Restrict Admission Webhook Configuration Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_kubernetes: 5.1.4; nist_800_53_r5: AC-6(5);

Roles and ClusterRoles must not grant create, update, or delete on mutatingwebhookconfigurations or validatingwebhookconfigurations. Admission webhooks intercept every API request — an attacker with webhook configuration access can inject a mutating webhook that modifies all pod specs, secrets, or deployments passing through the API server.

**Remediation:** Restrict webhook configuration write access to cluster administrators only.

---

### CTL.K8S.RBAC.WILDCARD.001

**ClusterRoles Must Not Use Wildcard Resources or Verbs**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.1.3;

Kubernetes ClusterRoles must not grant wildcard (*) access to resources or verbs. Wildcard grants provide cluster-wide permissions that bypass the principle of least privilege.

**Remediation:** Replace wildcard entries with explicit resource names and verbs. Use Roles (namespace-scoped) instead of ClusterRoles where possible.

---

### CTL.K8S.SCHEDULER.PROFILING.001

**Scheduler Profiling Must Be Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.4.1;

The scheduler profiling endpoint must be disabled. Profiling exposes system and program details useful for attackers to identify vulnerabilities and plan privilege escalation.

**Remediation:** Set --profiling=false on the scheduler.

---

### CTL.K8S.SECRETS.ENCRYPT.001

**Kubernetes Secrets Must Be Encrypted at Rest in etcd**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 1.2.29; hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

Kubernetes Secrets stored in etcd must be encrypted at rest. By default, Secrets are stored as base64-encoded plaintext in etcd, readable by anyone with etcd access or etcd backup access.

**Remediation:** Configure the API server with --encryption-provider-config pointing to an EncryptionConfiguration that uses aescbc, aesgcm, or kms provider. For EKS, enable envelope encryption with a KMS key.

---

### CTL.K8S.SECRETS.PLAINTEXT.001

**Pods Must Not Mount Secrets as Environment Variables**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.4.1;

Secrets should be mounted as files, not environment variables. Environment variables are visible in process listings, crash dumps, and container inspection output, increasing the risk of credential exposure.

**Remediation:** Mount Secrets as volumes instead of environment variables. Use projected volumes with restrictive file permissions (0400).

---


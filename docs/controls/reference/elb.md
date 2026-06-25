# Control Reference — ELB

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ELB.ACCESSLOG.PERMISSION.001

**ELB Cannot Write to Access Log S3 Bucket**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1; fedramp_moderate: AU-2; iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-2, AU-9, AC-3; pci_dss_v4.0: 10.1, 10.5; soc2: CC7.1, CC7.2;

ELB access logging is enabled and the S3 bucket exists, but the bucket policy doesn't grant the region's ELB log-delivery service account s3:PutObject. Logs are silently dropped — same effect as a deleted bucket, but caused by missing permissions rather than missing infrastructure. A common failure mode when buckets are created without the ELB grant or the grant is later removed by policy edits.

**Remediation:** Update the bucket policy to grant s3:PutObject to the regional ELB log-delivery service account (e.g., 127311923021 for us-east-1 — the IDs are region-specific and listed in the AWS docs). Test by triggering ELB traffic and verifying a new log file appears under AWSLogs/<account>/elasticloadbalancing/<region>/ within five minutes.

---

### CTL.ELB.ALARM.5XX.001

**No CloudWatch Alarm for ELB 5xx Errors**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 2.5; fedramp_moderate: SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: SI-4, IR-4, IR-5; pci_dss_v4.0: 10.6, 12.10; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch alarm monitors HTTPCode_ELB_5XX_Count (ALB) or HTTPCode_ELB_5XX (CLB). 5xx errors come from the load balancer itself — not the backend application — and indicate perimeter failures: 503 (no healthy targets), 502 (target closed connection), or 500 (internal LB error). Without an alarm, users experience errors while operations team has no signal. Skipped for NLB which doesn't generate HTTP error codes.

**Remediation:** Create a CloudWatch alarm on AWS/ApplicationELB HTTPCode_ELB_5XX_Count (or AWS/ELB HTTPCode_ELB_5XX for CLB) dimensioned by the load balancer name. Threshold > 0 over a 1-minute period; route to on-call. Pair with a target-side HTTPCode_Target_5XX_Count alarm so the team can distinguish ELB-side failures (no healthy targets) from application-side failures (target returned 5xx).

---

### CTL.ELB.ALARM.REJECTEDCONNECTION.001

**No CloudWatch Alarm for Rejected Connections**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: SI-4, SI-10; pci_dss_v4.0: 10.6; soc2: CC7.2, A1.2;

No CloudWatch alarm monitors RejectedConnectionCount. Rejected connections mean the load balancer can't accept new connections — capacity exhausted. Causes include traffic spike beyond ALB scaling, DDoS activity exhausting connection limits, or underprovisioned ALB. Without an alarm, connection refusals accumulate while users get connect-refused errors.

**Remediation:** Create a CloudWatch alarm on RejectedConnectionCount with threshold > 0 over a 1-minute period. Route to on-call. A non-zero rejected count means the ALB is at capacity — investigate scaling, DDoS, or upstream traffic pattern changes.

---

### CTL.ELB.ALARM.RESPONSETIME.001

**No CloudWatch Alarm for Target Response Time**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.6; soc2: CC7.2;

No CloudWatch alarm monitors TargetResponseTime (ALB). Rising response time indicates backend overload, downstream-dependency latency, or application bugs (memory leaks, thread exhaustion). Latency spikes degrade user experience without necessarily generating errors — without an alarm, the team learns about slowness from user reports rather than monitoring.

**Remediation:** Create a CloudWatch anomaly-detection alarm on AWS/ApplicationELB TargetResponseTime dimensioned by the load balancer or target group. Anomaly detection adapts to baseline latency so static thresholds aren't required (a 100ms baseline API and a 5s baseline report endpoint shouldn't share a single static threshold). Route to the application on-call team.

---

### CTL.ELB.ALARM.TLSERROR.001

**No CloudWatch Alarm for TLS Negotiation Errors**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16, A.8.24; nist_800_53_r5: SI-4, SC-12; pci_dss_v4.0: 10.6, 4.1; soc2: CC7.2;

No CloudWatch alarm monitors ClientTLSNegotiationErrorCount. TLS errors mean clients can't establish HTTPS connections — the TLS handshake fails before any HTTP request reaches the load balancer. Common causes: certificate expired, TLS policy too strict for the client's supported versions, certificate mismatch (SNI doesn't cover the requested host), missing intermediate CA. Without an alarm, TLS errors accumulate while clients silently fail to connect.

**Remediation:** Create a CloudWatch alarm on ClientTLSNegotiationErrorCount dimensioned by the load balancer. Threshold tuned to a small baseline (e.g., > 5 errors per 5 minutes — there's always some noise from outdated bots and probing clients). Pair with CTL.ELB.CERT.RENEWAL.FAILING.001 so cert expiration is caught earlier than its TLS-error consequence.

---

### CTL.ELB.ALARM.UNHEALTHYHOST.001

**No CloudWatch Alarm for Unhealthy Host Count**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 2.5; fedramp_moderate: SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: SI-4, IR-4; pci_dss_v4.0: 10.6; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch alarm monitors UnHealthyHostCount. Rising unhealthy host count is the leading indicator of backend degradation — it precedes the zero-healthy state caught by CTL.ELB.TARGET.NOHEALTHY.001. Early detection (alarm at threshold 1) flags the first unhealthy target; by the time TARGET.NOHEALTHY fires, every target is unhealthy and the service is down.

**Remediation:** Create a CloudWatch alarm on UnHealthyHostCount per target group with threshold >= 1 over a 5-minute period. Route to on-call. Pair with HealthyHostCount alarm at threshold 0 so total-failure (NOHEALTHY) is caught even if UnHealthyHostCount stays at 0 (e.g., all targets deregistered).

---

### CTL.ELB.ALB.DESYNC.MODE.001

**ALB Desync Mitigation Mode Set to Monitor**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.4; fedramp_moderate: SC-7, SI-10; iso_27001_2022: A.8.16, A.8.26; nist_800_53_r5: SC-7, SI-3, SI-10; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.7, CC7.2;

ALB desync mitigation mode is set to "monitor" rather than "defensive" or "strictest". Monitor mode lets ambiguous HTTP requests through unchanged — only logging — instead of normalizing or rejecting them. Request-smuggling payloads that exploit Content-Length / Transfer-Encoding ambiguity reach the backend.

**Remediation:** Set the ALB attribute routing.http.desync_mitigation_mode to "defensive" (the default for new ALBs) or "strictest" for hardened workloads: aws elbv2 modify-load-balancer- attributes --attributes Key=routing.http.desync_mitigation_mode,Value=defensive. Defensive normalizes ambiguous requests; strictest rejects them outright. Monitor mode is appropriate only as a temporary rollout step when validating that a defensive switch won't break legitimate clients.

---

### CTL.ELB.ALB.DROP.INVALID.HEADERS.001

**ALB Forwards Invalid HTTP Header Fields to Backend**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7, SI-10; iso_27001_2022: A.8.16, A.8.26; nist_800_53_r5: SC-7, SI-10; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.7;

ALB attribute drop_invalid_header_fields is disabled. Headers that don't conform to RFC 7230 (control characters, invalid whitespace, malformed names) are forwarded to the backend instead of being stripped. Header-injection and parser-disagreement attacks reach the application layer.

**Remediation:** Enable the ALB attribute routing.http.drop_invalid_header_fields.enabled: aws elbv2 modify-load-balancer-attributes --attributes Key=routing.http.drop_invalid_header_fields.enabled,Value=true. The ALB will then strip headers that don't conform to RFC 7230 before forwarding to the backend. Some legacy clients send technically-invalid headers; validate against expected traffic before flipping in production.

---

### CTL.ELB.ALB.IDLE.TIMEOUT.LONG.001

**ALB Idle Timeout Exceeds Reasonable Ceiling**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.6, A.8.16; nist_800_53_r5: SC-5, SC-7; pci_dss_v4.0: 6.4.2; soc2: CC6.6, A1.1, A1.2;

ALB idle_timeout is configured for more than 300 seconds. Long-held idle connections amplify the impact of slowloris-style resource exhaustion — each open connection consumes an ALB connection slot and (if forwarded) a backend connection slot until the timeout fires.

**Remediation:** Lower the ALB attribute idle_timeout.timeout_seconds to 60-300 seconds depending on application profile: aws elbv2 modify-load-balancer- attributes --attributes Key=idle_timeout.timeout_seconds,Value=60. The default is 60 seconds. Workloads that need long-held connections (server-sent events, long-poll APIs) should explicitly justify the longer timeout in code review and pair it with WAF rate limiting and connection quotas.

---

### CTL.ELB.ALB.MTLS.SG.001

**mTLS-Protected ALB Has No Network Restriction on Its Security Group**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7, AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

An ALB with mutual-TLS enabled still allows public inbound on its security group (0.0.0.0/0 or ::/0). mTLS authenticates clients by certificate, but defense-in-depth wants a network restriction too: without it, every host on the internet can open a TLS handshake, reach the cert-verification path, and probe for handshake/parsing flaws or exhaust connection capacity. Restrict the SG to the expected client CIDRs in addition to mTLS.
The SG check resolves nested security-group references, so an ALB whose SG references another SG that allows 0.0.0.0/0 is caught (the FN trap).
Inspired by Doyensec CloudsecTidbits No. 5 — Navigating Lax Load Balancers. Validated against doyensec/ELBaph.

**Remediation:** Restrict the ALB security group inbound to the expected client CIDR ranges in addition to mTLS. Resolve and tighten any referenced security groups that themselves allow 0.0.0.0/0.

---

### CTL.ELB.ALB.STICKY.COOKIE.INSECURE.001

**ALB Application-Controlled Sticky Cookie Missing Secure Flag**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8, SC-23; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: SC-8, SC-23, AC-12; pci_dss_v4.0: 4.2, 8.3; soc2: CC6.1, CC6.7;

Target group is configured with application-controlled sticky session cookies, but the upstream application's cookie response doesn't set the Secure flag. The cookie is transmitted over plain HTTP whenever a user inadvertently lands on the http:// scheme, exposing the session affinity identifier to any party on the path.

**Remediation:** Update the application emitting the sticky cookie to set Secure (and HttpOnly + SameSite as appropriate). Set-Cookie: AWSALBAPP-X=...; Path=/; Secure; HttpOnly; SameSite=Strict. For load-balancer-controlled stickiness (the default cookie name AWSALB), AWS sets Secure automatically when the listener is HTTPS — this control flags the application-managed variant where the operator owns the Set-Cookie header.

---

### CTL.ELB.ALB.XFF.PRESERVE.001

**Internet-Facing ALB Preserves Client-Controlled X-Forwarded-For**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

An internet-facing ALB sets routing.http.xff_header_processing.mode to "preserve", so the client's X-Forwarded-For header is passed through unchanged. If any downstream service trusts XFF for access control, rate limiting, geo decisions, or audit logging, a client can spoof its source IP by setting the header. "append" (ALB adds the real client IP) or "remove" closes this.
The ALB is treated as internet-facing not only when its scheme is internet-facing, but also when it is internal yet sits behind an internet-facing NLB (NLB->ALB passthrough) — the collector resolves that and sets internet_facing, so the FN trap is caught.
Inspired by Doyensec CloudsecTidbits No. 5 — Navigating Lax Load Balancers. Validated against doyensec/ELBaph.

**Remediation:** Set routing.http.xff_header_processing.mode to "append" (the ALB appends the true client IP) or "remove". Never "preserve" on an internet-facing ALB.

---

### CTL.ELB.AUTH.COGNITO.GHOST.001

**ALB Authentication References Deleted Cognito User Pool**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, CM-2, CM-3; pci_dss_v4.0: 8.1, 8.2; soc2: CC6.1, CC6.3, CC8.1;

ALB listener rule has an authenticate-cognito action referencing a Cognito user pool that has been deleted. The auth action attempts to redirect unauthenticated users to the Cognito hosted login; the user pool doesn't exist; the redirect fails. Depending on OnUnauthenticatedRequest: users see an error page (auth broken) or — if set to "allow" — reach the backend without auth (compound failure with CTL.ELB.AUTH.UNAUTHENTICATED.ALLOW.001).

**Remediation:** Either recreate the Cognito user pool with the same configuration (clients, identity providers, callback URLs) and update the rule's UserPoolArn / UserPoolClientId / UserPoolDomain, or repoint the rule at an existing user pool, or remove the authenticate-cognito action if authentication is no longer required. Audit any rules where OnUnauthenticatedRequest = allow — those are silently bypassing auth right now.

---

### CTL.ELB.AUTH.OIDC.SECRET.PLAINTEXT.001

**ELB OIDC Auth Action Stores Client Secret in Plaintext**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: IA-5, SC-13; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.5.17, A.8.24; nist_800_53_r5: IA-5, SC-13; pci_dss_v4.0: 3.5, 8.6; soc2: CC6.1, CC6.7;

ALB authenticate-oidc action's ClientSecret is a literal string rather than a reference to AWS Secrets Manager. The OIDC client secret sits in the listener rule configuration in plaintext, visible to anyone with elbv2:DescribeRules.

**Remediation:** Migrate the client secret to AWS Secrets Manager and reference it from the listener rule: store the secret with aws secretsmanager create-secret, then update the rule's authenticate-oidc action to reference the secret ARN. Anyone with elbv2:DescribeRules then sees the ARN rather than the literal secret. Rotate the secret afterwards since the previous plaintext value may be in CloudTrail history.

---

### CTL.ELB.AUTH.SESSION.TIMEOUT.001

**ELB Authentication Session Timeout Exceeds Threshold**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-12, IA-2; hipaa: 164.312(a)(2)(iii); iso_27001_2022: A.5.17, A.8.5; nist_800_53_r5: AC-12, IA-2; pci_dss_v4.0: 8.6; soc2: CC6.1;

ALB authenticate-cognito or authenticate-oidc action has SessionTimeout greater than 12 hours. The authentication session persists past the working day; a stolen session cookie remains usable for an extended window.

**Remediation:** Set SessionTimeout to 43200 seconds (12 hours) or less in the listener rule's authenticate-cognito or authenticate-oidc action: aws elbv2 modify-rule with Authenticate*Config.SessionTimeout=43200 (or shorter for sensitive workloads — HIPAA-aligned applications often pick 3600 seconds / 1 hour).

---

### CTL.ELB.AUTH.UNAUTHENTICATED.ALLOW.001

**ALB Authentication Action Allows Unauthenticated Requests**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, IA-2, IA-8; pci_dss_v4.0: 8.1, 8.2; soc2: CC6.1, CC6.3, CC6.6;

ALB listener rule has an authenticate-oidc or authenticate-cognito action with OnUnauthenticatedRequest set to "allow." Unauthenticated requests pass through the authentication action without being challenged. An auditor sees "authentication configured" — the rule has an authenticate-* action. Unauthenticated requests reach the backend anyway. False protection archetype at the auth layer: same class as DMARC p=none, WAF COUNT-only, and rotation-Lambda-deleted.

**Remediation:** Update the listener rule's authentication action to set OnUnauthenticatedRequest to either "authenticate" (redirect to login — standard) or "deny" (return 401 — strictest). Reserve "allow" for paths that intentionally serve mixed authenticated/unauthenticated content. Verify by sending a request without a valid session token — the response should be a redirect or 401, not the backend's response.

---

### CTL.ELB.AZ.SAME.001

**ELB Subnets Resolve to the Same Availability Zone**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.5.30, A.8.14; nist_800_53_r5: CP-7, SC-5; pci_dss_v4.0: 12.10; soc2: CC7.1, A1.1;

ALB or NLB has multiple subnets configured but they all map to the same AZ. The configuration looks redundant but isn't — loss of that single AZ takes the load balancer offline despite the multi-subnet appearance.

**Remediation:** Replace one or more subnets with subnets from a different AZ: aws elbv2 set-subnets with a list spanning at least two AZs. Verify by checking each subnet's AvailabilityZone field — they must differ. The minimum production posture for HA is two AZs; three is common in regions with three AZs available.

---

### CTL.ELB.BACKEND.DIRECT.ACCESS.001

**ELB Backend Reachable Bypassing the Load Balancer**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.2; fedramp_moderate: AC-3, SC-7; hipaa: 164.312(c)(1); iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, SC-7; pci_dss_v4.0: 1.2, 1.3, 6.4.2; soc2: CC6.1, CC6.6;

Target group's backend security groups allow inbound traffic on the application port from sources other than the ALB's security group. Direct internet or cross-VPC access reaches the backend without traversing the ALB — the WAF, TLS termination, and access logging at the ALB are all bypassed.

**Remediation:** Tighten backend security groups to allow inbound on the application port from only the ALB's security group: aws ec2 authorize-security-group-ingress with SourceSecurityGroupId pointing at the ALB's SG. Remove broader rules (0.0.0.0/0, broad CIDRs, other SGs that don't serve as ALBs).

---

### CTL.ELB.CERT.CHAIN.INCOMPLETE.001

**ELB Listener Certificate Chain Missing Intermediate CA**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12, SC-23; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

ELB listener certificate is configured without the intermediate CA in its chain. Browsers that don't have the intermediate cached fail to verify the certificate; some clients (curl, mobile platforms) reject the connection outright.

**Remediation:** Re-import the certificate with the full intermediate chain via aws acm import-certificate with the --certificate-chain flag pointing at the PEM-bundled intermediate CAs. ACM-issued certificates auto-include the chain; manually imported certs require the operator to bundle intermediates explicitly.

---

### CTL.ELB.CERT.EXPIRY.WARN.001

**ELB Listener Certificate Expiring Within 30 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12; owasp_nhi: NHI7; pci_dss_v4.0: 4.2; soc2: CC6.1, CC8.1;

ELB listener certificate has 30 or fewer days until expiry. ACM-issued certificates auto-renew if DNS validation is in place, but imported certificates and ACM certs with broken validation paths require manual rotation. A certificate expiring inside 30 days needs immediate operator attention.

**Remediation:** For ACM certificates: confirm DNS validation records are in place so the cert can auto-renew (the existing CTL.ELB.CERT.RENEWAL.FAILING control catches the case where renewal is actively failing). For imported certificates: request a new cert, import it via aws acm import-certificate, and swap it onto the listener via aws elbv2 modify-listener-certificates before the current one expires.

---

### CTL.ELB.CERT.GHOST.001

**Load Balancer References Deleted or Expired SSL Certificate**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-17; hipaa: 164.312(e)(1); nist_800_53_r5: SC-17; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

Load balancer HTTPS listener references an ACM certificate that has been deleted, has expired, or failed renewal. The load balancer continues to serve the missing or expired certificate — browsers display certificate warnings, API clients reject the TLS handshake, and automated integrations (webhooks, partner APIs, service meshes) fail at connection time. The listener configuration appears intact; the failure is external and immediate.

**Remediation:** Replace the certificate on the listener. If the original ACM certificate was deleted, request a new one with the same subject alternative names and associate it. If renewal failed, investigate the ACM renewal path (DNS validation records, IAM permissions for renewal). Enable automated ACM renewal where possible and add a 30-day-before-expiry alarm so the finding does not recur.

---

### CTL.ELB.CERT.MISMATCH.001

**ELB Listener Certificate Does Not Match Listener Domain**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-12, SC-23; hipaa: 164.312(e)(1); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

ELB listener serves a certificate whose CN/SAN does not include the domain users reach the listener on. Browsers reject the connection with a hostname-mismatch error.

**Remediation:** Either request a new certificate covering all domains routed to the listener (including SANs for each subdomain) and swap it in via aws elbv2 modify-listener-certificates, or remove the mismatched DNS records pointing at the listener. ACM supports up to 10 SAN entries per certificate; for more, use a wildcard or split across multiple certificates with SNI.

---

### CTL.ELB.CERT.NOTACM.001

**Load Balancer Certificate Not Managed by ACM**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.6; fedramp_moderate: SC-17; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: SC-12, SC-17; pci_dss_v4.0: 4.1, 4.2.1; soc2: CC6.1, CC6.7;

Load balancer listener uses an SSL/TLS certificate that is not managed by AWS Certificate Manager (ACM). The certificate was uploaded to IAM (legacy) or is self-signed. Non-ACM certificates don't auto-renew (manual renewal — risk of expiration), require manual rotation (download new cert, upload, update listener), and may not be validated by a trusted CA (self-signed certificates trigger browser warnings).

**Remediation:** Issue a replacement certificate via ACM (aws acm request-certificate or import-certificate), validate via DNS, then update the listener to reference the new ACM certificate: aws elbv2 modify-listener --listener-arn <arn> --certificates CertificateArn=<acm-arn>. Test the new certificate before deleting the old IAM certificate so a rollback path remains. ACM's DNS-validated certificates auto-renew — once migrated, the manual renewal risk disappears.

---

### CTL.ELB.CERT.RENEWAL.FAILING.001

**ACM Certificate Auto-Renewal Is Failing**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-17; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: SC-12, SC-17; pci_dss_v4.0: 4.1, 4.2.1; soc2: CC6.7, A1.1;

ACM certificate used by the load balancer has auto-renewal failing. ACM attempted to renew the certificate but the DNS validation record is missing or the email validation wasn't completed. The certificate will expire on its expiration date if not resolved. Precursor to expiration — fires while there's still time to fix the validation record before the certificate stops working.

**Remediation:** Inspect the certificate's renewal status via aws acm describe-certificate. For DNS-validated certificates, recreate the missing CNAME validation record in the domain's DNS zone. For email-validated certificates, request a new validation email and have a domain admin click the validation link. After fixing, ACM retries renewal automatically; status moves to SUCCESS within a day or two. Track certificate_expiry_days — if it drops below 14 the risk of expiration becomes immediate.

---

### CTL.ELB.CERT.SAN.COVERAGE.001

**ELB Listener Certificate Doesn't Cover All Routed Domains**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12, SC-23; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7, CC8.1;

Route 53 alias records point at the ELB from multiple domains, but the listener certificate's SAN list doesn't include every domain. Some routed domains produce hostname-mismatch TLS errors — partial outage that only some users experience.

**Remediation:** Either add the missing domains to the certificate's SAN list (request a new cert, ACM allows up to 10 SANs and a wildcard counts as one SAN per subdomain level), or remove the Route 53 records for domains the cert doesn't cover. Detection cross-references Route 53 alias targets pointing at the ELB DNS name with the certificate's SAN list.

---

### CTL.ELB.CERT.SELFSIGNED.001

**ELB Listener Uses Self-Signed Certificate**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-12, SC-23; hipaa: 164.312(e)(1); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

ELB listener serves a certificate that is self-signed (issuer equals subject) rather than issued by a publicly trusted CA. Browsers reject the connection with a certificate error; users either bypass the warning (training them to ignore TLS errors) or fail to connect.

**Remediation:** Replace the self-signed certificate with one from ACM (free, auto-renewing) or another publicly trusted CA. Use aws elbv2 modify-listener with the new certificate ARN. If self-signed is intentional (lab testing only), document the deviation; production listeners should never serve self-signed certs to end users.

---

### CTL.ELB.CERT.STALE.001

**ELB Listener Has Old Certificate Still Attached After Replacement**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-8, SA-22; soc2: CC8.1;

ELB listener has multiple certificates attached including one that's been superseded but not removed. The stale certificate is no longer the default but remains active for SNI matches against its SAN list — a forgotten cert may still be serving traffic.

**Remediation:** Identify the active certificate (the one used by current production traffic) and remove the others: aws elbv2 remove-listener-certificates with --certificates CertificateArn=<old>. Each ALB listener can attach multiple certificates (for SNI), so 'multiple' isn't itself a defect — but certificates that no SAN-bearing domain currently routes to the LB are stale.

---

### CTL.ELB.CERT.WEAKKEY.001

**ELB Listener Certificate Uses Weak RSA-1024 Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-12, SC-13; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-13; pci_dss_v4.0: 3.5; soc2: CC6.1, CC6.7;

ELB listener certificate uses RSA-1024 (or weaker) key. RSA-1024 has been considered insufficient for TLS use since 2014 — major CAs stopped issuing 1024-bit certificates long ago. A certificate using 1024-bit keys typically indicates a long-lived manual import that wasn't refreshed.

**Remediation:** Replace the certificate with one using RSA-2048 (minimum) or ECDSA-P-256. Request via ACM (which only issues modern key sizes) or, if importing, generate a new key with openssl genrsa 2048 (or openssl ecparam genkey -name prime256v1). Update the listener via aws elbv2 modify-listener-certificates.

---

### CTL.ELB.CLB.BACKEND.PLAINTEXT.001

**Classic Load Balancer Backend Listener Uses HTTP**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-8, SC-23; hipaa: 164.312(e)(1); iso_27001_2022: A.8.20, A.8.24; nist_800_53_r5: SC-8, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

Classic Load Balancer's backend instance protocol is HTTP rather than HTTPS. The CLB-to-backend hop transits unencrypted over the VPC network, even when client- to-CLB is HTTPS. End-to-end encryption isn't preserved.

**Remediation:** Either migrate the CLB to ALB or NLB (recommended — CLB is legacy; the existing CTL.ELB.LIFECYCLE.CLB.MIGRATION control flags this), or update the CLB backend to HTTPS: aws elb create-load-balancer-listeners with InstanceProtocol=HTTPS and the appropriate backend cert. Migration to ALB or NLB unlocks every modern feature the CLB lacks.

---

### CTL.ELB.CLB.DRAINING.001

**Classic Load Balancer Connection Draining Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-10; iso_27001_2022: A.5.30, A.8.32; nist_800_53_r5: CP-10, SI-2; pci_dss_v4.0: 11.5.1; soc2: A1.1, A1.2;

Classic Load Balancer does not have connection draining enabled. When an instance is deregistered (during deployment or scaling), in-flight requests on that instance are immediately dropped — the connection closes mid-request. Clients receive connection-reset or timeout errors during routine deployments. Connection draining gives in-flight requests a graceful completion window before the instance is removed from rotation.

**Remediation:** Enable connection draining on the CLB: aws elb modify-load-balancer-attributes --load-balancer-name <name> --load-balancer-attributes "ConnectionDraining={Enabled=true,Timeout=300}". A 300-second drain window gives long-running requests time to complete; tune lower for short-request workloads. Better long-term move: migrate to ALB (CTL.ELB.LIFECYCLE.CLB.MIGRATION.001) — ALB handles graceful deregistration without a distinct draining flag.

---

### CTL.ELB.CLB.HEALTHCHECK.MISSING.001

**Classic Load Balancer Has No Health Check Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.5; fedramp_moderate: CP-10; iso_27001_2022: A.5.30, A.8.32; nist_800_53_r5: CP-10, SI-4; pci_dss_v4.0: 11.5.1; soc2: CC7.1, A1.1, A1.2;

Classic Load Balancer has no health check configured (or has health checks disabled). The CLB cannot detect unhealthy instances — every registered instance receives traffic regardless of health. An instance with a crashed application, hung process, or network failure still gets 1/N of the traffic; every request to that instance fails for the client.

**Remediation:** Configure a health check on the CLB: aws elb configure-health-check --load-balancer-name <name> --health-check Target=HTTP:80/health,Interval=30, Timeout=5,UnhealthyThreshold=2,HealthyThreshold=2. Pick a target endpoint that exercises the application's basic functionality (database reachability, dependency check) rather than a static OK page. Better long-term: migrate to ALB (CTL.ELB.LIFECYCLE.CLB.MIGRATION.001) — ALB target-group health checks are richer (matcher codes, multiple paths, advanced options).

---

### CTL.ELB.CONNLOG.GHOST.BUCKET.001

**NLB Connection Log References Deleted S3 Bucket**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-2, AU-9, CM-3; iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-2, AU-9, CM-2, CM-3; pci_dss_v4.0: 10.5; soc2: CC7.1, CC7.2, CC8.1;

Network Load Balancer connection logging is configured with an S3 bucket name that doesn't exist. NLB writes silently fail; TLS handshake forensics are lost despite the configuration showing logging enabled.

**Remediation:** Either recreate the bucket with the same name and the appropriate Config- delivery / ELB-write bucket policy, or repoint the NLB connection log destination at an existing bucket: aws elbv2 modify-load-balancer-attributes with connection_logs.s3.bucket=<new>. Pair with the existing CTL.ELB.GHOST.ACCESSLOG.001 control that catches the same shape on access logs.

---

### CTL.ELB.CROSSACCOUNT.PRIVATELINK.OPEN.001

**NLB PrivateLink Service Allows Connections from Any Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

NLB is configured as a VPC endpoint service (PrivateLink) but the endpoint service permissions allow connections from any AWS account — no account restriction, no PrincipalOrgID condition. Any account can create a VPC endpoint targeting this NLB and route traffic to its backend services via PrivateLink. Open permissions defeat the purpose of PrivateLink (private connectivity with controlled access).

**Remediation:** Restrict allowed principals: aws ec2 modify-vpc-endpoint-service-permissions --service-id <id> --add-allowed-principals "arn:aws:iam::<consumer-account>:root" — and remove the wildcard. For organization-internal endpoint services, attach an SCP with aws:PrincipalOrgID so only org accounts can connect. Verify by attempting a connection from an out-of-org account — it must fail with a permission error before reaching the NLB.

---

### CTL.ELB.CROSSACCOUNT.SHARED.BLASTRADIUS.001

**Multiple Unrelated Services Share the Same ALB**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, SC-7; pci_dss_v4.0: 11.5.1; soc2: CC6.1, CC8.1;

Multiple services from different teams or applications share the same ALB via listener rules. A single ALB-level change — TLS policy downgrade, WAF removal, security-group modification — affects every service behind it. The blast radius spans multiple service owners. Shared ALBs are sometimes intentional (cost optimization) but the increased blast radius warrants explicit acknowledgement. Heuristic threshold: more than 5 distinct services on one ALB.

**Remediation:** Either split the ALB along service / team boundaries (one ALB per major service) or document the shared-ALB choice with the affected teams and add change-control gating on any ALB-level modification (TLS policy, WAF, security group). Pair with CTL.ELB.WAF.NORULES.001 and CTL.ELB.WAF.COUNTONLY.001 — a misconfigured WAF on a shared ALB blast-radiuses across every tenant.

---

### CTL.ELB.CROSSZONE.001

**Load Balancer Must Have Cross-Zone Load Balancing Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** ffiec: BCP; hipaa: 164.308(a)(7); soc2: A1.1;

Load balancers must distribute traffic across all registered targets in all enabled Availability Zones. Without cross-zone balancing, uneven distribution can cause availability issues during AZ failures.

**Remediation:** Enable cross-zone load balancing. Run: aws elbv2 modify-load-balancer-attributes --load-balancer-arn xxx --attributes Key=load_balancing.cross_zone.enabled,Value=true

---

### CTL.ELB.DELETION.PROTECT.001

**Load Balancer Must Have Deletion Protection Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-10; soc2: CC6.1;

Production load balancers must have deletion protection enabled.

**Remediation:** Enable deletion protection.

---

### CTL.ELB.GHOST.ACCESSLOG.001

**ELB Access Log S3 Bucket Does Not Exist**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1; fedramp_moderate: AU-2; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-2, AU-9, CM-2, CM-3; pci_dss_v4.0: 10.1, 10.5; soc2: CC7.1, CC7.2;

ELB access logging is enabled but the S3 destination bucket has been deleted. The configuration shows "access logging: enabled" with the bucket name. An auditor sees access logging configured. Every log write fails silently. Same invisible-harmful pattern as CTL.CLOUDTRAIL.GHOST.S3BUCKET.001 — the logging appears configured, the destination is gone, the logs are silently lost.

**Remediation:** Either (a) recreate the bucket with the same name and restore the bucket policy granting the regional ELB log-delivery service account s3:PutObject, or (b) repoint the ELB at an existing audit bucket via aws elbv2 modify-load-balancer-attributes — Key access_logs.s3.bucket. Verify by triggering traffic and confirming a new log file appears in the bucket within five minutes. Audit the gap window: every request handled while the bucket was missing has no access-log record.

---

### CTL.ELB.GHOST.TARGET.LAMBDA.001

**Target Group References Deleted Lambda Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SC-7; pci_dss_v4.0: 11.5.1; soc2: CC6.1, CC8.1, A1.2;

ELB target group of type Lambda references a Lambda function that has been deleted. Every request forwarded to this target group fails — the ALB attempts to invoke the Lambda, the invocation returns ResourceNotFoundException, and the response is 502 Bad Gateway. Distinct from CTL.ELB.TARGET.GHOST.001 (terminated EC2 instances) — the Lambda case is invisible at the EC2 inventory layer.

**Remediation:** Either redeploy the Lambda function (same name and version) or update the target group to register a different Lambda (aws elbv2 register-targets --target-group-arn <arn> --targets Id=<new-lambda-arn>). Audit the routing rules that forward to this target group — if the deletion was intentional, the rules also need to be repointed or removed.

---

### CTL.ELB.GHOST.WAF.001

**ALB References Deleted WAF Web ACL**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.6; fedramp_moderate: SC-7; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: SC-7, SI-3, SI-4, CM-2; pci_dss_v4.0: 6.4.2, 6.6; soc2: CC6.1, CC6.6, CC7.2;

ALB has a WAF web ACL association but the web ACL has been deleted. The ALB's WebACLArn references a non-existent web ACL. CTL.ELB.WAF.001 sees "WAF associated" and passes. The web ACL doesn't exist — no rules evaluate, no requests are blocked. SQL injection, XSS, bot traffic, known-bad IPs all pass through. This is the false-protection archetype at the perimeter — the most dangerous location for false protection because every external request passes through.

**Remediation:** Either (a) recreate the web ACL with the original rule set and re-associate via aws wafv2 associate-web-acl — WebACLArn — ResourceArn, or (b) detach the dangling association and associate an existing web ACL. Confirm filtering is active by sending a request with a known-malicious payload (e.g., a SQL injection canary string) and verifying it's blocked. Audit the gap window — every request handled while the WAF was a ghost passed through unfiltered.

---

### CTL.ELB.HTTPS.001

**Load Balancer Must Redirect HTTP to HTTPS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

Load balancers serving PHI must redirect all HTTP traffic to HTTPS. Allowing plaintext HTTP exposes data in transit to interception.

**Remediation:** Add a listener rule on port 80 that redirects to HTTPS (443) with status code 301.

---

### CTL.ELB.INCOMPLETE.001

**Complete Data Required for ELB Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Load balancer safety cannot be assessed when TLS configuration is missing from the snapshot. The extractor must populate loadbalancer.encryption.tls_1_2_or_higher.

**Remediation:** Re-run the extractor with ELB permissions: elasticloadbalancing:DescribeLoadBalancers, elasticloadbalancing:DescribeLoadBalancerAttributes, elasticloadbalancing:DescribeListeners.

---

### CTL.ELB.LIFECYCLE.CLB.MIGRATION.001

**Classic Load Balancer Still in Use**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.5; fedramp_moderate: SC-7; iso_27001_2022: A.8.20, A.8.22; nist_800_53_r5: CM-2, SC-7, SI-2; pci_dss_v4.0: 6.6; soc2: CC6.1, CC6.6, A1.2;

Classic Load Balancer is still in active use. CLB is legacy infrastructure: AWS recommends migration to ALB or NLB. CLBs lack WAF integration (no application-layer filtering), modern TLS policies, authentication integration (OIDC/Cognito on ALB), content-based routing, HTTP/2, WebSocket, and Lambda targets. Workloads on CLB miss security and operational features that ALB ships with.

**Remediation:** Migrate to ALB. Provision an ALB in the same VPC and AZs, recreate listeners and target groups, register targets, and switch DNS / Route 53 aliases from the CLB endpoint to the ALB endpoint. Run both in parallel during the cut-over window to validate. After traffic moves, delete the CLB. Migration unlocks WAF integration, modern TLS policies, authentication actions, content-based routing, and the alarm/auth controls in this catalog.

---

### CTL.ELB.LIFECYCLE.DORMANT.001

**Load Balancer Has No Traffic in 90+ Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SA-22; pci_dss_v4.0: 1.2; soc2: CC6.1, CC8.1;

Load balancer has processed no requests (RequestCount for ALB, ActiveFlowCount for NLB) in more than 90 days. The ALB/NLB/CLB exists with listeners, target groups, security groups, WAF association, and TLS configuration but serves no traffic. Latent infrastructure: security groups still allow inbound traffic, the ALB still costs money, and an internet-facing dormant ALB is a forgotten entry point reachable from the internet.

**Remediation:** Audit the LB's CloudTrail history to confirm dormancy. If truly unused, delete the load balancer (aws elbv2 delete-load-balancer --load-balancer-arn <arn>) along with associated target groups and listener rules. If retained for future use, restrict the security group to a minimal source set, document the planned reactivation, and attach a request-count alarm so any traffic surfaces immediately.

---

### CTL.ELB.LIFECYCLE.ORPHAN.TARGETGROUP.001

**Target Group Not Associated with Any Load Balancer**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; pci_dss_v4.0: 1.2; soc2: CC6.1, CC8.1;

ELB target group exists but is not associated with any ALB, NLB, or CLB listener. The target group has registered targets, health-check configuration, and attributes — but no load balancer routes traffic to it. Typically the load balancer was deleted but the target group wasn't, or the target group was created for a service that was never deployed.

**Remediation:** Either reattach the target group to an active load balancer's listener (modify-listener or create-rule with a forward action), or delete it (aws elbv2 delete-target-group --target-group-arn <arn>). Before deletion, audit registered targets — they may still be running production workloads and the orphan target group may be the only documentation that the workload exists.

---

### CTL.ELB.LISTENER.DEFAULTFORWARD.001

**ALB Listener Default Action Forwards Without Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, SC-7; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

ALB listener's default action forwards to a target group without any authentication action AND the listener has at least one rule that DOES carry authentication. The default rule catches every request that doesn't match a specific rule. If specific rules require auth but the default doesn't, any path not covered by a specific rule reaches the backend without authentication. Detects inconsistency, not the absence of auth — listeners with no auth on any rule are out of scope.
The default action is checked at instance level: it also fires when the default forwards (without auth) to a target group whose backend EC2 instances overlap a target group an auth-protected rule forwards to — even when the two target groups have different ARNs (default_forwards_to_auth_target). A naive ARN-only match would miss this.
Inspired by Doyensec CloudsecTidbits No. 5 — Navigating Lax Load Balancers.

**Remediation:** Add an authenticate-oidc or authenticate-cognito action to the listener's default action chain (action types compose; auth then forward). For paths that should be public, define explicit rules with no auth before the default — the rule order matters. Verify with a request to a path that doesn't match any specific rule: the response should be a redirect to login or 401, not the backend's response.

---

### CTL.ELB.LISTENER.GHOST.001

**Load Balancer Listener Rule Forwards to Deleted Target Group**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-8; nist_800_53_r5: CM-8; pci_dss_v4.0: 11.5.1; soc2: CC7.1;

ALB or NLB listener rule has a forward action targeting a target group that has been deleted. The listener rule matches incoming requests — based on path, host, header, or other conditions — and attempts to forward them. The target group no longer exists, so every matched request returns 502/503. The listener rule appears correctly configured in the console; the failure surfaces only when production traffic hits the rule.

**Remediation:** Either delete the listener rule if it is no longer needed, or update its forward action to reference an existing target group (recreating the deleted one if the routing was intentional). Confirm no automation continues to generate these rules against deleted target groups.

---

### CTL.ELB.LOG.001

**Load Balancer Access Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); soc2: CC7.1;

Load balancer access logging must be enabled for audit and forensic analysis. Without access logs, request patterns and potential unauthorized access cannot be investigated after an incident.

**Remediation:** Enable access logging to an S3 bucket. Run: aws elbv2 modify-load-balancer-attributes --load-balancer-arn xxx --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=my-elb-logs

---

### CTL.ELB.LOG.ACCESS.BROAD.001

**ELB Access Log S3 Bucket Accessible to Overly Broad Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AU-9; hipaa: 164.312(b), 164.312(c)(1); iso_27001_2022: A.5.15, A.8.15; nist_800_53_r5: AC-3, AU-9, AU-11; pci_dss_v4.0: 10.5; soc2: CC6.1, CC6.6;

S3 bucket receiving ELB access logs has a bucket policy or ACL granting read access to broad principals (Principal: *, AuthenticatedUsers, or many cross-account principals without OrgID). Anyone with matching credentials reads the access trail.

**Remediation:** Tighten the bucket policy: restrict s3:GetObject to specific accounts or roles with legitimate need (security, compliance, the ELB's logging service principal). Remove Principal: * grants; require aws:PrincipalOrgID for cross- account read. Audit existing principals listed in the policy and cull anyone without ongoing need.

---

### CTL.ELB.LOG.LIFECYCLE.001

**ELB Access Log S3 Bucket Has No Lifecycle Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: AU-11, SI-12; pci_dss_v4.0: 10.5.1, 10.7; soc2: CC7.1, CC8.1;

S3 bucket receiving ELB access logs has no lifecycle policy. Logs accumulate indefinitely; storage cost grows linearly with traffic and retention windows aren't enforced from the storage side.

**Remediation:** Add a lifecycle configuration to the access log bucket with rules matching the workload's compliance retention requirement: aws s3api put-bucket-lifecycle-configuration with rules that transition objects to S3 Glacier after 90 days and expire them after the compliance window (typically 1 year for SOC 2/PCI, 6+ years for HIPAA). Lifecycle ensures costs stay bounded as traffic grows.

---

### CTL.ELB.NETWORK.INTERNAL.PUBLICSUBNET.001

**Internal Load Balancer Is in Public Subnets**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20, A.8.22; nist_800_53_r5: SC-7, AC-3; pci_dss_v4.0: 1.2, 1.3; soc2: CC6.1, CC6.6;

Internal-scheme ALB or NLB is deployed in public subnets (subnets with a route to an internet gateway). Internal load balancers should be in private subnets — they're not intended to receive internet traffic. The internal scheme prevents internet reachability regardless of subnet type, so the control flags a topology misconfiguration rather than an exposure: it indicates confusion about network design and may be a precursor to a future scheme flip that would inadvertently expose the LB.

**Remediation:** Move the load balancer to private subnets: aws elbv2 set-subnets --load-balancer-arn <arn> --subnets <private-subnet-a> <private-subnet-b>. Verify the subnets have no route to an internet gateway. If the LB legitimately needs internet reachability, change the scheme to internet-facing instead of leaving it in mismatched public subnets.

---

### CTL.ELB.NETWORK.INTERNETFACING.PRIVATESUBNET.001

**Internet-Facing Load Balancer Is in Private Subnets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.8.20, A.8.32; nist_800_53_r5: SC-7, CP-7; pci_dss_v4.0: 11.5.1; soc2: CC7.1, A1.1;

Internet-facing ALB or NLB is deployed in private subnets (subnets without a route to an internet gateway). The load balancer can't receive internet traffic — it has no public IP route. The scheme says internet-facing. The network says private. The load balancer is unreachable from the internet despite being configured as internet-facing.

**Remediation:** Move the load balancer to public subnets (subnets with a route to the internet gateway): aws elbv2 set-subnets --load-balancer-arn <arn> --subnets <public-subnet-a> <public-subnet-b>. Verify subnets have an IGW route. If the workload is internal-only, change the scheme to internal instead of fixing the subnet placement.

---

### CTL.ELB.NETWORK.SINGLEAZ.001

**Load Balancer Subnets Are in a Single Availability Zone**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.5; fedramp_moderate: CP-7; iso_27001_2022: A.5.30, A.8.32; nist_800_53_r5: CP-7, CP-10, SC-7; pci_dss_v4.0: 11.5.1; soc2: A1.1, A1.2;

ALB or NLB has subnets configured in only one Availability Zone. The load balancer itself has a single point of AZ failure — if the AZ goes down, the LB has no ENIs in any other AZ and the load balancer becomes unreachable. ALB requires a minimum of two subnets but doesn't require they be in different AZs; two subnets in the same AZ satisfy the API requirement but provide no redundancy. The control checks UNIQUE AZ count, not subnet count.

**Remediation:** Add subnets in additional AZs to the load balancer: aws elbv2 set-subnets --load-balancer-arn <arn> --subnets <subnet-az-a> <subnet-az-b>. Verify the subnets resolve to distinct AvailabilityZone values. Pair with CTL.ELB.TARGET.SINGLEAZ.001 — distributing the load balancer across AZs is necessary but not sufficient; targets must also span AZs.

---

### CTL.ELB.NLB.ACCESSLOG.001

**NLB Access Logging Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AU-2, AU-9, AU-12; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-2, AU-9, AU-12; pci_dss_v4.0: 10.2, 10.5; soc2: CC7.1, CC7.2;

Network Load Balancer has access logging disabled. Connection-level audit data (source IP, port, accepted/rejected, bytes, timestamps) is not written to S3. Investigation of NLB-fronted incidents has no audit trail to query.

**Remediation:** Enable access logging on the NLB and point it at an S3 bucket: aws elbv2 modify-load-balancer-attributes with Attributes including access_logs.s3.enabled=true and access_logs.s3.bucket=<bucket>. Pair with the existing CTL.ELB.ACCESSLOG.PERMISSION control that catches misconfigured bucket policies.

---

### CTL.ELB.NLB.CONNLOG.001

**NLB Connection Logging Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-2, AU-12; iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-2, AU-9, AU-12; pci_dss_v4.0: 10.2; soc2: CC7.1, CC7.2;

Network Load Balancer has connection logging disabled. Per-connection TLS handshake outcomes, cipher negotiations, and SNI values are not logged. TLS troubleshooting and connection-state forensics lose their primary data source.

**Remediation:** Enable connection logging: aws elbv2 modify-load-balancer-attributes with connection_logs.s3.enabled=true and a target bucket. Connection logs are distinct from access logs — they record TLS handshake details (negotiated cipher, client SNI, handshake outcome) that access logs don't capture. Useful for diagnosing client-compatibility issues and TLS-policy-related failures.

---

### CTL.ELB.NLB.TCP80.NOTLS.001

**NLB Has TCP Listener on Port 80 Without Companion TLS Listener**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-8, SC-23; hipaa: 164.312(e)(1); iso_27001_2022: A.8.20, A.8.24; nist_800_53_r5: SC-8, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

Network Load Balancer has a TCP listener on port 80 but no TLS listener on 443. NLBs pass through TCP without termination, so there is no TLS handshake at the LB layer — every byte transits in plaintext from client to backend.

**Remediation:** Either add a TLS listener on the NLB (aws elbv2 create-listener with Protocol=TLS,Port=443 and a configured SSL policy + certificate) and remove the TCP/80 listener, or enable TLS on the backend service and switch the NLB to TLS pass-through. NLBs that genuinely need to handle plaintext TCP (legacy protocols, internal-only) should be documented; production user-facing workloads on TCP/80 are almost always misconfiguration.

---

### CTL.ELB.ORPHAN.NOLISTENER.001

**ELB Has No Listeners Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-8, SA-22; soc2: CC8.1;

ALB or NLB exists with zero listeners. The load balancer can't accept any traffic — it's a configuration shell. Either left over from a half-deleted deployment or a new LB whose setup was abandoned mid-way.

**Remediation:** Either configure listeners (aws elbv2 create-listener) if the LB is intended to be in service, or delete the LB (aws elbv2 delete-load-balancer) if it isn't. ALBs and NLBs cost the hourly rate plus LCU regardless of listener presence — listenerless LBs incur cost for no value.

---

### CTL.ELB.REDIRECT.TARGET.HTTP.001

**ELB Listener Redirects HTTP to Another HTTP Target**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-8, SC-23; hipaa: 164.312(e)(1); iso_27001_2022: A.8.20, A.8.24; nist_800_53_r5: SC-8, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

ALB listener rule redirect action sends HTTP traffic to another HTTP target rather than to HTTPS. The redirect superficially looks correct but doesn't move the user onto TLS — credentials and content stay in plaintext.

**Remediation:** Update the redirect action's Protocol to HTTPS and Port to 443: aws elbv2 modify-rule with Action.RedirectConfig Protocol=HTTPS,Port=443. Verify by requesting http://app.example.com and confirming the response Location header points at https://. Pair with Strict-Transport-Security headers on the HTTPS responses to lock browsers into the secure path.

---

### CTL.ELB.ROUTING.NLBBYPASS.001

**NLB Forwards to the Same Instances as a Gated ALB**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-4, SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

A Network Load Balancer forwards (Layer 4 — no listener rules, auth actions, or path conditions) to one or more EC2 instances that also sit behind an ALB carrying security controls (authentication, source-ip gate, or WAF). Every ALB-layer control is bypassable at the network level by going through the NLB.
Reachability is resolved at the instance level: the collector resolves NLB IP-type targets to instance IDs first, so an NLB that targets the same private IPs by address rather than instance ID is still caught (the FN trap). The derived signal network.elb.nlb_shares_gated_alb_instances is computed by the reasoning spec examples/alb-routing-nlb-bypass/ (Soufflé + Z3, which agree).
Inspired by Doyensec CloudsecTidbits No. 5 — Navigating Lax Load Balancers. Validated against doyensec/ELBaph.

**Remediation:** Apply equivalent network-level restrictions on the NLB path: tighten the target instances' security groups so they only accept traffic from the ALB, not the NLB; or remove the overlapping NLB targets; or front the NLB with the same controls. The instance security group is the enforcement point an NLB cannot bypass.

---

### CTL.ELB.ROUTING.PATHEQUIV.001

**Backend Reachable Via Paths With Inconsistent Security Controls**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

A backend EC2 instance is reachable through more than one ALB/listener/rule path, and those paths do not carry equivalent security controls. One path enforces authentication (authenticate-oidc/cognito), a source-ip gate, or sits behind a WAF; another path reaching the SAME instance does not. The strongest path is irrelevant — an attacker takes the weakest one, bypassing the control.
The master compound for ALB routing: reachability resolves to the instance, not the target-group ARN, so two different target groups that share an EC2 instance are the same backend (instance-level overlap). A listener's default rule is just another path. Subsumes the source-ip-gate-bypass case (ALB-ROUTING-003). The derived signal network.elb.tg_path_controls_inconsistent is computed by the reasoning spec examples/alb-routing-path-equivalence/ (Soufflé + Z3, which agree on the trap-triplet).
Inspired by Doyensec CloudsecTidbits No. 5 — Navigating Lax Load Balancers. Validated against doyensec/ELBaph.

**Remediation:** Make every path to the backend carry equivalent controls, or collapse the paths. Apply the same authentication action, source-ip condition, and WAF association on every ALB/listener/rule that forwards to the shared target groups. If an alternate path is unintended, remove the listener rule or deregister the instance from the alternate target group. Treat the default rule as a path: point it at a fixed 403 response rather than the same backend.

---

### CTL.ELB.ROUTING.RULESHADOW.001

**ALB Listener Rule Shadows an Authentication Action**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

An ALB listener has an authentication rule (authenticate-oidc/cognito) that is unreachable because a higher-precedence rule — one with a lower priority number — matches the same or a broader path without authentication. ALB rules evaluate in ascending priority order, so the broad rule wins and the auth action never fires. A pure ordering bug that silently bypasses authentication.
A rule with no path condition matches everything (equivalent to /*), so a host-only wildcard at a low priority number shadows every auth rule behind it. The derived signal network.elb.auth_rule_shadowed is computed by the reasoning spec examples/alb-routing-rule-shadow/ (Soufflé + Z3, which agree on the trap-triplet, including the no-path-condition case).
Inspired by Doyensec CloudsecTidbits No. 5 — Navigating Lax Load Balancers. Validated against doyensec/ELBaph.

**Remediation:** Reorder the rules so the authentication rule has a lower priority number (higher precedence) than any broader non-auth rule that overlaps its path, or tighten the broad rule's path condition so it no longer subsumes the authenticated path. Give every rule an explicit path condition — a rule with no path condition matches everything.

---

### CTL.ELB.SG.GHOST.001

**Load Balancer References Deleted Security Group**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** fedramp_moderate: CM-8; nist_800_53_r5: CM-8; pci_dss_v4.0: 1.2.1; soc2: CC7.1;

Load balancer is associated with one or more security groups that have been deleted. The SG reference remains on the load balancer but evaluates against a non-existent resource. The effective access-control state is undefined — depending on how AWS resolves the deleted reference, the load balancer may become unreachable or behave as if no rule applies at the SG layer. Either way, the load balancer is in an inconsistent state relative to the firewall policy it was deployed with.

**Remediation:** Replace the deleted SG references with intended live SGs. If the deletion was deliberate, update the load balancer's SG association explicitly rather than leaving the stale reference. Investigate the deletion path that did not update the LB — a proper SG decommissioning runbook should update all dependents before deleting.

---

### CTL.ELB.SG.NONSTANDARD.PORTS.001

**ELB Security Group Allows Inbound on Non-Standard Ports**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.2; fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, SC-7; pci_dss_v4.0: 1.2, 1.3; soc2: CC6.1, CC6.6;

ALB or NLB security group allows inbound traffic on ports other than 80 and 443 (or the configured listener ports). The extra open ports may have been left from early development, debugging tools, or test listeners — they widen the attack surface beyond what the load balancer's listeners require.

**Remediation:** Reconcile the SG inbound rules with the load balancer's listener ports. Remove SG rules for ports that don't correspond to a listener: aws ec2 revoke-security-group-ingress with the extra port. Standard production ALB SGs typically need only 80 and 443 inbound from 0.0.0.0/0 for internet- facing or from internal CIDRs for internal LBs.

---

### CTL.ELB.TARGET.EMPTY.001

**Target Group Associated with Listener Has No Registered Targets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.8.32; nist_800_53_r5: CP-7, CP-10, SI-4; pci_dss_v4.0: 11.5.1; soc2: CC7.1, A1.1, A1.2;

ELB target group is associated with a listener (or listener rule) but has zero registered targets. The target group exists with health-check configuration and attributes but no instances, IPs, or Lambda functions are registered. Every request the load balancer forwards to this group returns 503 immediately. Distinct from orphan target groups (no listener at all — separate lifecycle concern).

**Remediation:** Either register targets via aws elbv2 register-targets — or, if the target group is no longer in use, remove the listener-rule association and delete the group (CTL.ELB.GHOST.* catches lingering orphans). For Auto Scaling Group-backed target groups, attach the ASG and let it register targets automatically.

---

### CTL.ELB.TARGET.GHOST.001

**Target Group References Deregistered or Terminated Instances**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** fedramp_moderate: CM-8; nist_800_53_r5: CM-8; pci_dss_v4.0: 11.5.1; soc2: CC7.1;

ALB or NLB target group contains registered targets that are deregistered or reference terminated EC2 instances. Health checks continue to fire against non-existent targets, wasting health-check capacity and producing persistent unhealthy- target alerts that operators learn to ignore. If every target in the group is a ghost, listener rules that forward to it return 502/503 for every matching request.

**Remediation:** Deregister the ghost targets from the target group. If the target group has only ghost targets, delete the target group (and any listener rules that forward to it) or register fresh targets. Add target-group cleanup to the instance-termination runbook so deregistration happens alongside termination.

---

### CTL.ELB.TARGET.NOHEALTHY.001

**Target Group Has Zero Healthy Targets**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.8.16, A.8.32; nist_800_53_r5: CP-7, CP-10, SI-4; pci_dss_v4.0: 11.5.1; soc2: CC7.1, A1.1, A1.2;

ELB target group has registered targets but zero are passing health checks. Every request the load balancer forwards to this target group fails with 503. The target group exists. Targets are registered. None are healthy. Distinct from CTL.ELB.LISTENER.GHOST.001 (target group deleted) — here the group is intact but the backend is non-functional.

**Remediation:** Investigate the unhealthy targets via aws elbv2 describe-target-health — each unhealthy target carries a Reason code (Target.FailedHealthChecks, Target.NotInService, Target.NotRegistered). Common fixes: restart the application on instances, correct the health check path so the load balancer hits a route that returns 200, or open the security group so health-check traffic from the load balancer can reach the target port.

---

### CTL.ELB.TARGET.SINGLEAZ.001

**Target Group Has All Targets in Single Availability Zone**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.5; fedramp_moderate: CP-7; iso_27001_2022: A.5.30, A.8.32; nist_800_53_r5: CP-7, CP-10; pci_dss_v4.0: 11.5.1; soc2: A1.1, A1.2;

ELB target group has all registered targets in a single Availability Zone. AZ failure (hardware, network, power) takes every target offline simultaneously — the target group has zero healthy targets and every request returns 503. The load balancer itself may span multiple AZs but has nothing to route to once the AZ holding all targets fails.

**Remediation:** Distribute targets across at least two AZs aligned with the load balancer's subnet AZs. For Auto Scaling Group-backed target groups, set the ASG to span multiple AZs and the appropriate HealthCheckGracePeriod. For manually registered targets, deregister and re-register from instances in additional AZs. Verify via aws elbv2 describe-target-health that targets appear in distinct AvailabilityZone values.

---

### CTL.ELB.TG.BACKEND.PLAINTEXT.001

**ELB Target Group Uses HTTP to Backend Despite Backend Supporting HTTPS**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-8, SC-23; hipaa: 164.312(e)(1); iso_27001_2022: A.8.20, A.8.24; nist_800_53_r5: SC-8, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

Target group's Protocol is HTTP even though the backend supports HTTPS (port 443 reachable). The ALB terminates TLS at the listener and re-encodes the request as plaintext over the network to the target. Defense-in-depth requires TLS end-to-end for sensitive workloads.

**Remediation:** Update the target group protocol to HTTPS and the port to the backend's TLS port: aws elbv2 modify-target-group with Protocol=HTTPS,Port=443. Verify backend targets present a valid certificate (or accept self-signed if internal). The ALB will then re-encrypt to the backend rather than send plaintext over the VPC network.

---

### CTL.ELB.TG.HEALTHCHECK.PROTOCOL.001

**ELB Target Group Health Check Uses HTTP When Target Protocol Is HTTPS**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8, SI-4; iso_27001_2022: A.8.20, A.8.24; nist_800_53_r5: SC-8, SI-4; pci_dss_v4.0: 4.2; soc2: CC6.1, CC7.1;

Target group's traffic protocol is HTTPS but the health check protocol is HTTP. Health checks bypass the TLS configuration of the application — a backend whose HTTPS endpoint is broken can still pass health checks if its HTTP endpoint works.

**Remediation:** Update the target group health check protocol to match traffic protocol: aws elbv2 modify-target-group with HealthCheckProtocol=HTTPS. The health check then validates that the backend's TLS endpoint is healthy — broken certificates, expired keys, or TLS misconfigurations cause health failures promptly rather than going undetected.

---

### CTL.ELB.TG.HEALTHCHECK.TIMEOUT.001

**ELB Target Group Health Check Timeout Equals or Exceeds Interval**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.1, A1.1;

Target group health check timeout is greater than or equal to the health check interval. Health checks overlap — a slow check from one cycle may still be running when the next cycle starts. The result is unstable health detection: targets thrash between healthy and unhealthy unpredictably.

**Remediation:** Set HealthCheckTimeoutSeconds < HealthCheckIntervalSeconds. Typical defaults are interval=30s, timeout=5s. Tune both based on the backend's expected response time; timeout should be 25%–50% of the interval so the previous check completes well before the next begins.

---

### CTL.ELB.TLS.001

**Load Balancer Must Use TLS 1.2 or Higher**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

Application and Network Load Balancers must use TLS 1.2 or higher for HTTPS listeners. Older TLS versions have known vulnerabilities.

**Remediation:** Update the HTTPS listener to use an ELBSecurityPolicy that enforces TLS 1.2 minimum (e.g., ELBSecurityPolicy-TLS-1-2-2017-01).

---

### CTL.ELB.TLS.CUSTOM.WEAKCIPHER.001

**ELB Custom SSL Policy Includes Weak Ciphers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-8, SC-13; hipaa: 164.312(e)(1), 164.312(e)(2)(ii); iso_27001_2022: A.8.24; nist_800_53_r5: SC-8, SC-12, SC-13; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

ELB listener uses a custom SSL policy whose cipher list contains weak entries — RC4, DES, 3DES, NULL, EXPORT, or anonymous Diffie-Hellman ciphers. The policy may appear locked-down but accepts cipher suites known-broken at the cryptographic level.

**Remediation:** Switch to one of AWS's predefined modern SSL policies (e.g., ELBSecurityPolicy-TLS13-1-2-2021-06 or ELBSecurityPolicy-FS-1-2-Res-2020-10): aws elbv2 modify-listener with SslPolicy=<modern-policy>. If a custom policy is required, remove RC4, DES, 3DES, NULL, EXPORT, and anonymous DH cipher suites and require modern key exchange (ECDHE).

---

### CTL.ELB.WAF.001

**Application Load Balancer Must Have WAF Web ACL Associated**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Internet-facing ALBs must have an AWS WAF web ACL associated.

**Remediation:** Associate a WAF web ACL with the ALB.

---

### CTL.ELB.WAF.BYPASS.CF.001

**CloudFront-Fronted ALB Reachable Directly (Missing Header Check or Public SG)**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-7, SC-8; iso_27001_2022: A.8.20, A.8.22; nist_800_53_r5: SC-7, SC-8; pci_dss_v4.0: 1.3; soc2: CC6.1, CC6.6;

ALB sits behind a CloudFront distribution but is reachable directly, bypassing CloudFront's WAF, caching, and Shield Advanced. Two bypass vectors fire this control: (1) the ALB does not require a CloudFront-set custom header, so any client that learns the ALB DNS name hits the application directly; or (2) the origin ALB's security group allows a public / over-broad inbound CIDR (0.0.0.0/0, ::/0, or a broad range that includes NAT-egress public IPs) instead of restricting to the com.amazonaws.global.cloudfront.origin-facing managed prefix list — direct access is not even blocked at the network layer.
Inspired by Doyensec CloudsecTidbits No. 5 — Navigating Lax Load Balancers.

**Remediation:** Configure CloudFront to set a custom request header (e.g., X-Origin-Verify with a long random secret stored in Secrets Manager) and add a WAF rule on the ALB requiring that header on every request. Direct ALB requests fail; only requests from the configured CloudFront distribution succeed. Rotate the header value periodically. The pattern is standard CloudFront-to-ALB origin protection.

---

### CTL.ELB.WAF.BYPASS.DIRECT.001

**Backend Targets Are Directly Accessible Bypassing ALB and WAF**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1, 5.2; fedramp_moderate: SC-7; iso_27001_2022: A.8.20, A.8.22; nist_800_53_r5: SC-7, SI-3, AC-3; pci_dss_v4.0: 1.2, 1.3, 6.6; soc2: CC6.1, CC6.6;

Backend targets behind an ALB have security groups that allow inbound traffic from sources OTHER than the ALB's security group. An attacker who can reach the target IP directly bypasses every ALB-layer control: WAF, TLS termination, access logging, authentication, rate limiting. The ALB's security controls apply only to traffic that flows through the ALB. Backend security groups should permit inbound only from the ALB's security group on the application port.

**Remediation:** Tighten the target instances' security group: keep one inbound rule allowing the application port from the ALB's security-group ID, and remove every other inbound rule on that port (especially 0.0.0.0/0, broad CIDRs, or peer security groups that aren't the ALB's). Verify by attempting a direct connection from a test instance — the connection must fail. The ALB's WAF, TLS, auth, and access logging then become the only path to the backend.

---

### CTL.ELB.WAF.CONSISTENCY.001

**WAF Coverage Inconsistent Across Account's ALBs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SC-7; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: CM-2, SC-7, SI-4; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC8.1;

Some ALBs in the account have a WAF web ACL associated and others don't. Mixed WAF posture means an attacker who identifies an unprotected ALB sidesteps the entire perimeter defense — finding the gap is enumeration rather than exploitation work.

**Remediation:** Either attach a web ACL to every ALB or document why specific ALBs are exempt (internal-only, non-production with limited reach, etc.). Use AWS Firewall Manager to enforce uniform WAF association across the organization; Firewall Manager flags non-compliant resources and can auto-remediate.

---

### CTL.ELB.WAF.COUNTONLY.001

**ALB WAF Web ACL Rules Are in COUNT Mode Only**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.6; fedramp_moderate: SC-7; iso_27001_2022: A.8.20, A.8.22; nist_800_53_r5: SC-7, SI-3, SI-4; pci_dss_v4.0: 6.4.2, 6.6; soc2: CC6.1, CC6.6;

ALB WAF web ACL has rules but every rule is in COUNT mode. COUNT mode evaluates requests and records matches but takes no action — the request continues to the backend. SQL injection payloads, known-bad IPs, bot traffic — all matched, all logged, all forwarded. COUNT is intended for testing new rules before enabling BLOCK; production-deployed COUNT-only WAF detects threats without preventing them. Same false- protection class as no-rule WAF — slightly less invisible (logs exist) but no actual blocking.

**Remediation:** Switch rules from COUNT to BLOCK after a brief bake-in window. Use the WAF console (Override statement → none) or aws wafv2 update-web-acl with the rule's Action set to Block instead of Override+Count. Move one rule group at a time, watch the WAF logs for false positives between transitions, and revert if legitimate traffic gets blocked. The common failure: rules deployed in COUNT for testing, testing completed, nobody switched to BLOCK.

---

### CTL.ELB.WAF.MANAGED.001

**ELB WAF Has No AWS Managed Rule Groups**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-7, SI-3; hipaa: 164.312(c)(1); iso_27001_2022: A.8.7, A.8.16; nist_800_53_r5: SC-7, SI-3, SI-4; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

ALB has a WAF web ACL associated but the ACL contains no AWS managed rule groups. The team has assembled the WAF surface themselves without the OWASP-aligned baseline AWS provides for free. Common attacks (SQLi, XSS, command injection, known-bad IPs) may not be covered.

**Remediation:** Add AWS managed rule groups to the web ACL: aws wafv2 update-web-acl with rules including AWSManagedRulesCommonRuleSet (OWASP Top 10), AWSManagedRulesKnownBadInputsRuleSet, AWSManagedRulesAmazonIpReputationList, and protocol-specific groups (LinuxRuleSet, WindowsRuleSet, SQLiRuleSet) where appropriate. Managed rules are free per WCU; the only cost is WCU consumption against the ACL's capacity.

---

### CTL.ELB.WAF.NOLOG.001

**ALB WAF Logging Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 2.6; fedramp_moderate: AU-6; iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-2, AU-6, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

ALB has a WAF web ACL associated and the web ACL exists, but WAF logging is not enabled. Without WAF logs, which requests were blocked is unknown (cannot verify the WAF is filtering), which requests matched rules is unknown (cannot tune rules), which IPs trigger rules is unknown (cannot identify attackers), and false positive analysis is impossible (legitimate requests blocked but nobody knows). WAF rules still block requests in the data plane; logging is the operational-intelligence layer.

**Remediation:** Enable logging on the WAF web ACL pointing at a Kinesis Firehose, CloudWatch Logs group, or S3 bucket: aws wafv2 put-logging-configuration --logging-configuration ResourceArn=<webacl-arn>, LogDestinationConfigs=<destination-arn>. Pair with a CloudWatch alarm on the BlockedRequests metric so spikes in blocking surface immediately.

---

### CTL.ELB.WAF.NORULES.001

**ALB WAF Web ACL Has No Rules**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.6; fedramp_moderate: SC-7; iso_27001_2022: A.8.20, A.8.22; nist_800_53_r5: SC-7, SI-3, SI-4; pci_dss_v4.0: 6.4.2, 6.6; soc2: CC6.1, CC6.6, CC7.1;

ALB has a WAF web ACL associated and the web ACL exists, but the web ACL contains zero rules — no managed rule groups, no custom rules, no rate-based rules. The WAF evaluates nothing. Every request passes through the default action (typically Allow). An auditor checking "is WAF configured?" sees the association and marks it compliant. The WAF provides the appearance of application-layer filtering without any filtering. Same false-protection class as DMARC p=none and rotation-enabled-but-Lambda-deleted.

**Remediation:** Add at minimum the AWS managed core rule set (AWSManagedRulesCommonRuleSet), the SQL injection rule set (AWSManagedRulesSQLiRuleSet), and a rate-based rule for IP-level throttling. Use the AWS WAF console or aws wafv2 update-web-acl. Run rules in COUNT mode initially (CTL.ELB.WAF.COUNTONLY.001 catches leaving them in COUNT) to surface false positives before flipping to BLOCK.

---

### CTL.ELB.WAF.RATELIMIT.001

**ELB WAF Has No Rate-Based Rule**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: SC-5, SI-4; hipaa: 164.312(c)(1); iso_27001_2022: A.8.7, A.8.16; nist_800_53_r5: SC-5, SI-4; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC7.2, A1.1;

ALB has a WAF web ACL associated but the ACL contains no rate-based rule. Application- layer DDoS, credential-stuffing storms, and scraping bots aren't throttled at the WAF — attacks pass through to the application.

**Remediation:** Add a rate-based rule: aws wafv2 update-web-acl with a Rule of type RateBasedStatement. Typical thresholds start at 2000 requests per 5-minute window per source IP for general application traffic; tighter (500–1000) for sign-in endpoints and high-cost API paths. Layer multiple rate-based rules if different paths warrant different thresholds.

---


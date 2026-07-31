# Control Reference — ROUTE53

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ROUTE53.CROSSACCOUNT.PRIVATEASSOC.001

**Private Hosted Zone Associated with VPC in External Account Without Organization Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Route 53 private hosted zone is associated with a VPC in an account outside the organization. Private zone association grants the associated VPC's resources the ability to resolve every record in the zone — internal service names, database endpoints, internal IP addresses, and other infrastructure details. When the associated VPC belongs to an account that is not part of the organization, that external account's resources can resolve the organization's internal DNS. If the external account is later compromised, the attacker discovers the organization's internal infrastructure by querying the private zone's records. Private zone VPC association should be limited to accounts within the organization (verified via aws:PrincipalOrgID or an explicit authorized account list). This is a HIGH-severity finding because the exposure is not a single record — the entire zone's records are accessible from the external VPC.

**Remediation:** Identify the associated VPCs: aws route53 get-hosted-zone --id {zone-id} and inspect the VPCs block for associations whose AWS account is not in the organization's account list. For each external association: confirm with the business whether the cross-account resolution is intended. If the association is intentional and the external account is a trusted partner, document the cross-account dependency and constrain it via a Route 53 resolver rule that limits which records the external VPC can query (rather than full zone resolution). If the association is unintended: disassociate the VPC — aws route53 disassociate-vpc-from-hosted-zone --hosted- zone-id {zone-id} --vpc VPCRegion={region},VPCId={vpc-id}. Audit cross-account VPC associations periodically: a zone-association authorization persists until revoked, so a former partner relationship leaves stale access until the association is actively removed.

---

### CTL.ROUTE53.DANGLING.001

**Route53 A Records Must Not Point to Unassigned IP Addresses**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

Route53 A records using literal IP addresses must point to IP addresses currently assigned to resources in the account. Dangling IPs enable subdomain takeover — an attacker claims the released IP and serves content under the organization's domain.

**Remediation:** Remove the dangling record or reassign the IP.

---

### CTL.ROUTE53.DANGLING.ALIAS.001

**Route 53 Alias Record Points to Deleted AWS Resource — Silent Failure**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; soc2: CC7.1;

Route 53 alias record points to an AWS resource (ALB, CloudFront distribution, S3 bucket, API Gateway, Elastic Beanstalk, or VPC endpoint) that has been deleted. Unlike CNAME records (where deletion of the target causes NXDOMAIN — visible failure), Route 53 alias records that point to deleted resources may return an empty answer with no error code — the query appears to succeed but returns no IP addresses. This is a silent failure: monitoring tools that check for NXDOMAIN miss alias danglings entirely, operators assume the domain is responding, and the silent service failure persists undetected. For reclaimable resources (S3 buckets, CloudFront CNAMEs, Elastic Beanstalk CNAMEs), the silent alias failure masks an active subdomain takeover opportunity.

**Remediation:** Identify what resource the alias pointed to by checking the alias target field. If the resource was deleted intentionally: remove the Route 53 alias record. If the resource must be restored: recreate it and verify the alias record resolves correctly. Enable Route 53 health checks with alias record evaluate-target-health to detect silent resolution failures proactively.

---

### CTL.ROUTE53.DANGLING.AMPLIFY.001

**DNS Record Points to Deleted AWS Amplify App**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 CNAME record points to a deleted AWS Amplify app. Amplify custom domains are associated via CNAME; when the Amplify app is deleted, the custom domain association is removed but the CNAME record may remain. An attacker who creates a new Amplify app and configures the same custom domain can serve content on the organization's subdomain. Amplify apps validate domain ownership via DNS — the existing CNAME record serves as proof of ownership.

**Remediation:** Delete the CNAME record pointing to the decommissioned Amplify app, or re-create the Amplify app and reclaim the custom domain defensively.

---

### CTL.ROUTE53.DANGLING.APIGATEWAY.001

**DNS Record Points to Deleted API Gateway Custom Domain**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC8.1;

Route 53 record points to an API Gateway custom domain (execute-api.region.amazonaws.com or a custom domain name) that has been deleted from API Gateway. The custom domain was removed but the DNS record still points to it. Depending on the API Gateway endpoint type: for Regional APIs, the custom domain name resolves to NXDOMAIN when deleted; for Edge-Optimized APIs fronted by CloudFront, the underlying CloudFront distribution's CNAME may become unclaimed after the API Gateway custom domain is deleted. In the edge-optimized case, an attacker may be able to create a new API Gateway custom domain with the same name and claim the CloudFront CNAME. The organization's DNS record routes API traffic to the attacker's API.

**Remediation:** If the API is no longer needed: remove the Route 53 record. If the API must be restored: re-create the API Gateway custom domain name before the DNS record can route to an attacker's API. For edge-optimized APIs, verify the underlying CloudFront distribution's CNAME is still claimed by your account before creating a new custom domain.

---

### CTL.ROUTE53.DANGLING.APPRUNNER.001

**DNS Record Points to Deleted AWS App Runner Service**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 CNAME record points to a deleted AWS App Runner service. App Runner services accept custom domain configuration via CNAME validation. When the service is deleted, the custom domain binding is removed but the CNAME record in Route 53 may remain. An attacker who creates a new App Runner service and associates the same custom domain can serve content on the organization's subdomain.

**Remediation:** Delete the CNAME record pointing to the decommissioned App Runner service, or create a new App Runner service and reclaim the custom domain defensively.

---

### CTL.ROUTE53.DANGLING.BEANSTALK.001

**DNS Record Points to Terminated Elastic Beanstalk Environment**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 CNAME record points to an Elastic Beanstalk environment CNAME (application.region.elasticbeanstalk.com) for an environment that has been terminated. Elastic Beanstalk environment CNAMEs are reclaimable — after the environment is terminated, the CNAME becomes available for any AWS customer to claim. An attacker creates a new Elastic Beanstalk environment, swaps the CNAME to the target value, and deploys an application. The organization's DNS record routes traffic to the attacker's application. Unlike S3 and CloudFront takeover (where the attacker must specifically discover the target), Elastic Beanstalk CNAMEs are of predictable form and can be scanned systematically. This is the third-most exploited takeover vector after S3 and CloudFront.

**Remediation:** Check whether the Elastic Beanstalk CNAME has already been claimed by another account. If the subdomain is still needed, re-create the Beanstalk environment and claim the CNAME before removing and re-adding the Route 53 record. If the service is permanently decommissioned, remove the Route 53 CNAME record immediately.

---

### CTL.ROUTE53.DANGLING.CLOUDFRONT.001

**DNS Record Points to CloudFront Distribution That Does Not Claim This Domain**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 CNAME record points to a *.cloudfront.net distribution domain where either the distribution has been deleted or the distribution exists but does not have this domain registered as an alternate CNAME. CloudFront allows any distribution to claim any CNAME that is not already claimed by another distribution. If the original distribution is deleted, the CNAME becomes unclaimed — an attacker creates a new distribution, adds the organization's subdomain as an alternate CNAME, and points an origin at attacker-controlled content. The organization's DNS record then routes traffic to the attacker's distribution. This is the second most common subdomain takeover vector after S3, exploited actively in bug bounty programs and in the wild. Complements CTL.CLOUDFRONT.GHOST.ORIGIN.001 (which checks CloudFront → deleted origin) — this checks DNS → CloudFront.

**Remediation:** If the distribution was deleted and the subdomain is still needed: create a new CloudFront distribution, add the subdomain as an alternate CNAME before the DNS record can route traffic to an attacker's distribution. If the distribution exists but doesn't claim the domain: update the distribution to add the subdomain as an alternate CNAME. If the subdomain is no longer needed: remove the Route 53 record immediately.

---

### CTL.ROUTE53.DANGLING.EC2.001

**DNS A Record Points to Terminated EC2 Instance Public IP**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 A record points to the public IP address of an EC2 instance that has been terminated. When an EC2 instance is terminated, its public IP (non-Elastic) is immediately released to the AWS IP pool and can be assigned to any customer's new EC2 instance — including an attacker's. The organization's A record points to whatever instance now holds that IP. Unlike EIPs (which can be explicitly tracked), EC2 public IPs change on every start/stop cycle and are reassigned unpredictably on termination. The attacker's instance receives all traffic directed to the organization's domain name. This is the ephemeral IP version of subdomain takeover — the IP can be reclaimed by any instance in the same region.

**Remediation:** Remove the Route 53 A record. For production services requiring stable IPs, always use Elastic IPs rather than EC2 ephemeral public IPs — Elastic IPs persist until explicitly released and can be precisely tracked. If the service must be restored, launch a new instance, allocate an Elastic IP, associate it, and create a new DNS record pointing to the EIP.

---

### CTL.ROUTE53.DANGLING.EIP.001

**DNS A Record Points to Released Elastic IP Address**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 A record points to an Elastic IP address that has been released. When an Elastic IP is released, it returns to the AWS public IP pool and can be re-allocated by any AWS customer in the same region — including an attacker. The attacker allocates an EC2 instance and associates the reclaimed EIP. The organization's A record now points to the attacker's instance. The attacker can serve any content (phishing, malware, intercepted traffic) on the organization's domain. EIP recycling attacks have been demonstrated by security researchers who successfully reclaimed specific IPs by repeatedly allocating and releasing EIPs in the target region. Complements CTL.ROUTE53.DANGLING.001 (which detects general dangling IPs) by specifically checking whether a Route 53 A record points to a currently-released EIP.

**Remediation:** If the Elastic IP was released intentionally: remove the Route 53 A record immediately. If the IP was accidentally released: check whether it has been re-allocated by another account via AWS IP address tracking. If the IP is still available, allocate a new EIP and update the Route 53 record. If the IP has been claimed by another account, remove the Route 53 record and allocate a new EIP for a new DNS record.

---

### CTL.ROUTE53.DANGLING.ELB.001

**DNS Record Points to Deleted Load Balancer**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3; soc2: CC8.1;

Route 53 alias or CNAME record points to an Application Load Balancer, Network Load Balancer, or Classic Load Balancer that has been deleted. The DNS record resolves to a load balancer DNS name that no longer exists, causing the subdomain to return NXDOMAIN or an empty answer. Unlike S3 and CloudFront (where the resource name is globally reclaimable), ELB DNS names contain account-specific components (randomly generated hex strings and account ID fragments) that make direct takeover harder. However, the dangling record still causes visible service failure on the organization's domain: the subdomain appears broken, returning errors to all visitors. Dangling ELB records indicate incomplete decommissioning — the load balancer was deleted without updating DNS.

**Remediation:** If the load balancer was deleted intentionally and the subdomain is no longer needed: remove the Route 53 record. If the service must be restored: create a new load balancer, update the Route 53 record to point to the new load balancer, and restore the service. For alias records, use Route 53's built-in alias evaluation to detect when the target is deleted.

---

### CTL.ROUTE53.DANGLING.GLOBALACCELERATOR.001

**DNS Record Points to Deleted Global Accelerator**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 CNAME record points to a deleted AWS Global Accelerator. Global Accelerator provides static anycast IP addresses with a DNS name (*.awsglobalaccelerator.com). When the accelerator is deleted, the DNS name and IPs are released. A CNAME pointing to the decommissioned accelerator endpoint can be reclaimed by an attacker who creates a new Global Accelerator and obtains the same or similar endpoint.

**Remediation:** Delete the CNAME record pointing to the decommissioned Global Accelerator, or re-create the accelerator and reclaim the endpoint defensively.

---

### CTL.ROUTE53.DANGLING.LIGHTSAIL.001

**DNS Record Points to Deleted Lightsail Instance**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 CNAME or A record points to a deleted Amazon Lightsail instance. When a Lightsail instance is deleted, its static IP or public DNS name is released. A CNAME pointing to the Lightsail public DNS endpoint or an A record pointing to a released Lightsail static IP can be reclaimed. An attacker who creates a new Lightsail instance at the same endpoint can serve content on the organization's subdomain.

**Remediation:** Delete the DNS record pointing to the decommissioned Lightsail instance, or re-create the instance and reclaim the endpoint defensively.

---

### CTL.ROUTE53.DANGLING.MX.001

**MX Record Points to Decommissioned Mail Server**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 MX record points to a mail server hostname that is no longer serving email for the domain. The mail server was decommissioned, the hosting was cancelled, or the DNS name was changed — but the MX record was not updated. Email delivery fails silently after the SMTP timeout: the sending server tries to connect to the mail server, waits for the timeout (minutes), and then delivers a non-delivery receipt to the sender. If the decommissioned mail server's hostname becomes reclaimable (expired domain, deleted EC2 instance with a reachable hostname, released service endpoint), an attacker who controls the reclaimed resource receives the organization's email — password resets, financial notifications, confidential communications, and multi-factor authentication codes. MX dangling is particularly insidious because email failures are reported to senders, not recipients, so the organization may not know email is being lost or intercepted.

**Remediation:** Verify whether the mail server hostname resolves and accepts SMTP connections on port 25. If the mail server has been decommissioned: update the MX record to point to the new mail infrastructure. If the domain uses a hosted email service (Google Workspace, Microsoft 365, Proton Mail), replace the MX record with the provider's required MX records. Remove any MX records for mail servers that no longer exist.

---

### CTL.ROUTE53.DANGLING.NS.001

**NS Record Delegates to Name Servers That Do Not Serve the Zone**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-20; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 NS record delegates a subdomain to name servers that are not authoritative for that zone — lame delegation. The delegated zone was deleted or the name server configuration was removed, but the parent NS records remain. This is the most powerful form of subdomain takeover: an attacker who controls the delegated name servers (or who registers an expired name server domain) can serve any DNS records for the entire subdomain — A records pointing to attacker servers, MX records intercepting email, TXT records passing domain ownership verification for TLS certificates and service integrations, and CNAME records for unlimited sub-subdomains. NS delegation takeover gives the attacker full DNS control over the subtree, not just a single record. If the name server domain is expired and unregistered, the attacker simply registers it and serves the zone.

**Remediation:** If the subdomain zone is still needed: restore the zone on the delegated name servers before the NS domain can be claimed by an attacker. If the subdomain is no longer needed: remove the NS delegation record from the parent zone. Check whether the name server domain is still registered to a trusted party — if it has expired, register it urgently before attackers claim it.

---

### CTL.ROUTE53.DANGLING.S3.001

**DNS Record Points to Deleted S3 Bucket — Subdomain Takeover**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC7.1;

Route 53 record (CNAME or alias) points to an S3 website hosting endpoint for a bucket that has been deleted. S3 bucket names are globally unique but reclaimable after deletion. An attacker creates a bucket with the same name in their own AWS account, enables static website hosting, and uploads content. The Route 53 record still points to the S3 website hosting endpoint. The endpoint now serves the attacker's content. Visitors to the organization's subdomain see attacker-controlled content — on a domain they trust. The attack requires no special access: the attacker only needs to discover the dangling record (automated tools scan for this pattern), create the bucket, and upload content. This is the most commonly exploited subdomain takeover vector, documented in the OWASP Testing Guide and actively rewarded in bug bounty programs. Complements CTL.S3.DANGLING.ORIGIN.001 (CloudFront distribution → S3) — this control checks Route 53 records → S3 directly.

**Remediation:** Immediately check if the bucket name has been re-registered by another account. If the name is unclaimed, re-create the bucket in your account before an attacker claims it. If the subdomain is no longer needed, remove the Route 53 record. If the service must be restored, re-create the bucket, re-configure website hosting, and restore content before the DNS record points visitors there.

---

### CTL.ROUTE53.DNSSEC.DISABLED.001

**Route 53 Public Hosted Zone Does Not Have DNSSEC Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-20; soc2: CC6.1;

Route 53 public hosted zone does not have DNSSEC signing enabled. Without DNSSEC, DNS responses for this zone are unsigned — a man-in-the-middle or cache poisoning attacker (Kaminsky attack) can inject forged DNS records into recursive resolver caches, redirecting the domain to attacker-controlled infrastructure. DNSSEC cryptographically signs each DNS response with the zone's signing key — resolvers that validate DNSSEC reject forged responses. This finding applies only to public hosted zones. Route 53 private hosted zones serve VPC-internal DNS and do not support DNSSEC; the VPC resolver handles internal DNS without the public internet attack surface. DNSSEC protects validating resolvers and is increasingly required by compliance frameworks and enterprise security standards.

**Remediation:** Enable DNSSEC signing for the Route 53 hosted zone in the AWS console or via CLI: aws route53 enable-hosted-zone-dnssec --hosted-zone-id [ID]. After enabling signing, create a DS record at the parent zone (your domain registrar, or Route 53 if you registered through AWS) to complete the DNSSEC chain of trust. Without the DS record, resolvers cannot validate the zone's signatures. Monitor key rotation — Route 53 manages KSK rotation automatically if configured. For zones registered through Route 53, the DS record can be added via the console.

---

### CTL.ROUTE53.DOMAIN.AUTORENEW.001

**Route 53 Domain Auto-Renew Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC6.1;

Route 53 registered domain does not have auto-renew enabled. If the domain expires, it enters a grace period during which the registrar holds it and renewal is possible but may incur a premium. After the grace period, the domain enters redemption and eventually deletion — at which point anyone can register it. An attacker who registers the expired domain controls everything: DNS (all records), email (all mail to the domain), TLS certificates (via DNS validation), and all services that used the domain. Domain sniping services monitor expiring domains specifically because domains with existing traffic, backlinks, and email are valuable targets. The domain's SEO history, inbound links, and existing DNS caches all work in the attacker's favor. Auto-renew is a single configuration change that prevents accidental expiration. Domain expiration is the accidental equivalent of a domain transfer — same outcome, different mechanism.

**Remediation:** Enable auto-renew on the domain: aws route53domains enable-domain-auto-renew --domain-name [DOMAIN]. Verify the domain expiry date and ensure auto-renew is configured far enough in advance of expiry — Route 53 attempts renewal 30 days before the expiry date. Also ensure the account has a valid payment method to prevent renewal failure. Consider setting a CloudWatch alarm for domains approaching expiry as a secondary safeguard.

---

### CTL.ROUTE53.EMAIL.DMARC.MISSING.001

**Route 53 Zone Has No DMARC Record**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Route 53 public hosted zone has no DMARC (Domain-based Message Authentication, Reporting and Conformance) TXT record at _dmarc.[zone]. Without DMARC, there is no policy telling receiving mail servers what action to take when email fails SPF and DKIM authentication. Even with SPF and DKIM configured, the receiving server decides independently whether to accept, quarantine, or reject unauthenticated email — and most default to accepting. DMARC with p=reject tells receivers to reject email that fails authentication. DMARC also enables aggregate reporting (rua=) so the domain owner learns who is sending email as their domain — the only mechanism for discovering unauthorized use of the domain in email campaigns. Without DMARC, there is no enforcement layer and no visibility.

**Remediation:** Create a TXT record at _dmarc.[zone] with a DMARC policy. Start with p=none to collect reports without enforcement: "v=DMARC1; p=none; rua=mailto:dmarc-reports@[zone]". Monitor aggregate reports for 2-4 weeks to identify legitimate senders. Progress to p=quarantine (deliver to spam) then p=reject (reject outright). Add sp=reject to cover subdomain spoofing. Target state: "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@[zone]"

---

### CTL.ROUTE53.EMAIL.DMARC.NOENFORCE.001

**Route 53 Zone DMARC Record Has No Enforcement Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Route 53 public hosted zone has a DMARC record with p=none — monitoring-only mode, no enforcement. Receiving servers report authentication failures to the domain owner (via rua= aggregate reports) but do not reject or quarantine spoofed email. The DMARC record exists and appears in DNS audits as "DMARC configured." It provides no protection. Spoofed email is delivered to recipients. p=none is the intended starting point for DMARC deployment — observe the sending landscape, fix legitimate sources, then progress to enforcement. Organizations that enable p=none and never advance create false confidence: the DMARC record exists, security scans pass, but phishing email is still delivered. The enforcement states are p=quarantine (deliver to spam) and p=reject (reject outright). p=quarantine is acceptable enforcement; p=reject is the strongest and recommended target.

**Remediation:** Progress DMARC from p=none to enforcement. Review aggregate reports (rua= destination) to identify all legitimate mail sources and ensure they pass SPF or DKIM. Move to p=quarantine (spoofed email goes to spam folder) to validate enforcement doesn't break legitimate delivery. Then advance to p=reject (spoofed email is rejected at the mail server). Target: "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@[zone]"

---

### CTL.ROUTE53.EMAIL.DMARC.NOSUBDOMAIN.001

**Route 53 Zone DMARC Record Has Subdomain Policy Set to None**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Route 53 public hosted zone has a DMARC record with sp=none — explicitly setting no enforcement for subdomains. When a DMARC record omits the sp= tag, subdomains inherit the parent domain's p= policy. When sp=none is explicitly set, subdomains have no enforcement regardless of the parent domain's p= value: a domain with p=reject and sp=none rejects spoofed @example.com email but allows spoofed @billing.example.com, @hr.example.com, and @payroll.example.com email through. Subdomain addresses are especially effective for phishing — they appear credible (billing@subdomain.example.com) while bypassing the parent domain's DMARC enforcement. This finding fires only when sp=none is explicitly set, overriding the natural inheritance. A DMARC record with no sp= tag is not flagged — the parent p= applies.

**Remediation:** Remove sp=none from the DMARC record or replace it with sp=quarantine or sp=reject. If the parent p= is already reject, simply removing the sp= tag causes subdomains to inherit p=reject automatically — the strongest protection with no additional configuration. If some subdomains legitimately send email with different sources, configure their own DMARC records at _dmarc.[subdomain] rather than setting sp=none at the parent.

---

### CTL.ROUTE53.EMAIL.SPF.LOOKUPLIMIT.001

**Route 53 Zone SPF Record Exceeds 10 DNS Lookup Limit**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Route 53 public hosted zone has an SPF record that requires more than 10 DNS lookups to evaluate. RFC 7208 limits SPF evaluation to 10 DNS-querying mechanisms (include, a, mx, ptr, exists, redirect). When the limit is exceeded, the receiving server returns a PermError — permanent error — and may treat the domain as having no SPF record, allowing all senders through. SPF lookups exceeding the limit cause SPF to fail silently for legitimate email and provide no protection against spoofing. Nested includes compound the problem: include:provider.com may itself include 3-4 further domains, each consuming lookup budget. Common cause: accumulation of cloud mail provider includes over time (Google, SES, Sendgrid, Mailchimp, Salesforce) without consolidation.

**Remediation:** Reduce the number of DNS-querying mechanisms to 10 or fewer. Audit all include: directives and remove those for services no longer used. Replace multiple provider includes with a single macro- flattened SPF record using ip4:/ip6: directives (which don't consume lookup budget). Use SPF flattening tools or a managed SPF provider (Dmarcian, Valimail) to stay within limits. The mechanisms that count toward the 10-lookup limit are: include, a, mx, ptr, exists, and redirect. The ip4:, ip6:, and all mechanisms do not count.

---

### CTL.ROUTE53.EMAIL.SPF.MISSING.001

**Route 53 Zone Apex Has No SPF Record**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Route 53 public hosted zone apex has no SPF (Sender Policy Framework) TXT record. Without SPF, any mail server on the internet can send email appearing to be from this domain. There is no mechanism for receiving mail servers to verify that the sending server is authorized. Domain spoofing for phishing is trivial — an attacker sends email from ceo@[domain] and receiving servers have no check to perform. SPF is the foundational layer of email authentication: it restricts which servers are authorized to send as the domain.

**Remediation:** Add a TXT record at the zone apex with value "v=spf1 ... -all" listing the mail servers authorized to send for this domain. Use -all (hardfail) to reject unauthorized senders, or ~all (softfail) as a transition step. Do not use +all or ?all — these provide no protection. Include all legitimate sending sources: MX records, cloud mail providers (include:_spf.google.com for Google Workspace, include:amazonses.com for SES), and any authorized third-party senders.

---

### CTL.ROUTE53.EMAIL.SPF.MULTIPLE.001

**Route 53 Zone Has Multiple SPF Records**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Route 53 public hosted zone has more than one TXT record beginning with "v=spf1". RFC 7208 states a domain MUST NOT publish multiple SPF records. When multiple SPF records exist, the behavior is undefined — receiving servers may select any one record, return a PermError, or produce inconsistent validation results. One record may be restrictive (-all) while the other is permissive (+all), making the effective policy depend on which record the receiving server evaluates. SPF validation becomes unpredictable across different mail providers. Multiple SPF records typically result from multiple administrators independently adding records, or from a failed migration between mail providers where the old record was not removed.

**Remediation:** Consolidate all SPF records into a single TXT record. Merge the include: directives, ip4:, and ip6: mechanisms from all existing records into one record. Delete all but the consolidated record. Verify the merged record is syntactically valid and does not exceed 10 DNS lookups. Note: other TXT records (DKIM selectors, domain verification tokens, Google Site Verification) are not SPF records — only TXT records starting with "v=spf1" are SPF.

---

### CTL.ROUTE53.EMAIL.SPF.PERMISSIVE.001

**Route 53 Zone SPF Record Is Too Permissive**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Route 53 public hosted zone has an SPF record that uses +all or ?all — providing no restriction on which servers can send email as this domain. +all explicitly authorizes every mail server on the internet. ?all (neutral) provides no opinion on unauthorized senders. Both qualifiers are effectively equivalent to having no SPF record. The SPF record exists and passes a superficial "does SPF exist?" audit check, creating false confidence that email authentication is in place. Receiving servers that check SPF see a record and take no restrictive action. The correct qualifiers are -all (hardfail — reject unauthorized senders) or ~all (softfail — mark as suspicious). -all is the strongest and recommended target state.

**Remediation:** Update the SPF TXT record to use -all (hardfail) or at minimum ~all (softfail). Replace +all or ?all with -all at the end of the SPF record value. -all tells receiving servers to reject email from servers not listed in the SPF record. ~all tells servers to mark unauthorized email as suspicious (SoftFail). The transition path is ~all first (observe, fix false positives), then -all for full enforcement.

---

### CTL.ROUTE53.FAILOVER.NOSECONDARY.001

**Route 53 Failover Record Has No Secondary Record**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-7; soc2: A1.1;

Route 53 failover routing has a primary record but no secondary (failover) record. Failover routing requires two records — primary and secondary. The primary receives traffic when its health check reports healthy. When the primary's health check fails, Route 53 returns the secondary record's value. Without a secondary record, when the primary fails its health check, Route 53 has no fallback: it returns NXDOMAIN or continues serving the unhealthy primary depending on the record type. The failover mechanism is configured — an auditor sees "failover routing configured" — but there is nothing to fail over to. This is a false confidence pattern: the infrastructure appears to have high availability but the failover path does not exist. The secondary record typically points to a different ALB, CloudFront distribution, or S3 static error page in another region.

**Remediation:** Create a secondary failover record pointing to a backup endpoint in a different region or availability zone. The secondary record uses the same record name and type as the primary but with Failover=SECONDARY. Unlike the primary, the secondary does not require a health check — it is the last resort when the primary is unhealthy. Common secondary targets: an S3 bucket configured for static website hosting with an error page, a CloudFront distribution serving a maintenance page, or an ALB in a different region. Ensure the secondary record's TTL is low enough for rapid failover.

---

### CTL.ROUTE53.FAILOVER.SECONDARYNOHEALTH.001

**Route 53 Failover Secondary Record Has No Health Check**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.2;

Route 53 failover routing has a health check on the primary record but no health check on the secondary (failover) record. When the primary fails its health check, Route 53 fails over to the secondary — which may itself be unhealthy. Without a health check on the secondary, failover moves traffic from a known-broken primary to a potentially-broken secondary with no verification. Customers experience a double failure: the primary is down, and the failover destination is also unavailable. A health check on the secondary provides a signal: if the secondary is also unhealthy, the operator knows the entire failover mechanism has failed and can take manual action. Without the signal, the operator sees the failover trigger but has no visibility into whether the secondary is actually serving traffic correctly.

**Remediation:** Add a health check to the failover secondary record. Create a health check for the secondary endpoint: aws route53 create-health-check. Update the secondary record set to include the HealthCheckId. Route 53 will then mark the secondary as unhealthy if it fails, providing a signal that both endpoints are down. Note that if the secondary is unhealthy and there are no other healthy records, Route 53 returns the unhealthy secondary anyway as a last resort — but the health check ensures the team knows the state.

---

### CTL.ROUTE53.GHOST.001

**Route53 Records Must Not Point to Deleted AWS Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

Route53 records (A, AAAA, CNAME, Alias) must not point to AWS resources that have been deleted — ELBs, CloudFront distributions, S3 website endpoints, Elastic IPs, or API Gateways. For reclaimable resources (released EIPs, deleted S3 bucket names), an attacker claims the target and receives all traffic the DNS record directs. This extends CTL.ROUTE53.DANGLING.001 (dangling IPs) and CTL.DNS.DANGLING.001-003 (external hosting takeover) to cover deleted AWS resources specifically.

**Remediation:** Remove or update the DNS record to point to an existing resource.

---

### CTL.ROUTE53.HEALTH.MISSING.001

**Route 53 Routing Policy Record Has No Health Check**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-7; soc2: A1.1;

Route 53 record with a routing policy that depends on endpoint health — failover, weighted, latency, or multi-value — does not have an associated health check. Without a health check, Route 53 cannot detect when the endpoint is unhealthy and routes traffic to the endpoint regardless of its state. Failover routing never triggers failover (the primary is always considered healthy, even when returning 500 errors). Weighted routing sends traffic to unhealthy endpoints proportionally — an endpoint with weight 50 receives 50% of traffic even when it is down. Latency routing sends traffic to the nearest but potentially unhealthy endpoint. Simple routing does not use health checks for routing decisions and is excluded from this control. Geolocation routing uses health checks for availability but the key safety gap for geolocation is the missing default record (see CTL.ROUTE53.ROUTING.GEO.NODEFAULT.001).

**Remediation:** Create a health check for the endpoint: aws route53 create-health-check. Associate the health check with the record by updating the record set to include HealthCheckId. For failover routing, the primary record must have a health check — without it, failover never triggers. For weighted routing, each weighted record should have a health check so Route 53 excludes unhealthy endpoints from the weighted distribution. For latency routing, health checks ensure Route 53 does not route to the lowest-latency endpoint when that endpoint is unhealthy.

---

### CTL.ROUTE53.HEALTH.NOALARM.001

**No CloudWatch Alarm for Route 53 Health Check Status**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-4; soc2: A1.1;

Route 53 health check exists but no CloudWatch alarm monitors its HealthCheckStatus metric. When the health check transitions from healthy to unhealthy, nobody is notified. Route 53 automatically fails over traffic if failover routing is configured, but the team does not know the primary endpoint is down until someone checks the console or receives a customer report. A CloudWatch alarm on the HealthCheckStatus metric sends an alert the moment the health check detects failure — giving the team immediate visibility before customers are affected and before the automatic failover becomes the team's only signal. Without the alarm, the failover is silent from the team's perspective: traffic moves, but there is no notification, no incident trigger, and no audit trail that the primary endpoint was down.

**Remediation:** Create a CloudWatch alarm for the health check: aws cloudwatch put-metric-alarm with Namespace=AWS/Route53, MetricName= HealthCheckStatus, Dimensions=[{Name=HealthCheckId,Value=[ID]}], Threshold=1, ComparisonOperator=LessThanThreshold. Set AlarmActions to an SNS topic that pages on-call. The alarm fires when HealthCheckStatus drops below 1 (unhealthy). Use a short evaluation period (1-2 minutes) so the alarm fires quickly after failure detection.

---

### CTL.ROUTE53.HEALTHCHECK.001

**Route 53 Health Checks Must Be Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: A1.1;

Route 53 health checks must be configured for DNS records pointing to critical endpoints. Without health checks, DNS routes to failed endpoints.

**Remediation:** Create health checks: aws route53 create-health-check and associate with failover routing.

---

### CTL.ROUTE53.HEALTHCHECK.GHOST.001

**Route 53 Health Checks Must Not Target Deleted Endpoints**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance

Route 53 health checks must monitor endpoints that still exist — an EIP that has been released, a CloudFront distribution that has been disabled, a load balancer that has been deleted, or an FQDN whose A record was removed. A health check pointed at a deleted endpoint reports persistent unhealthy status, which is treated as routine noise by the team and fails to trigger any failover (because Route 53 has no record group to fail over from). More dangerously, the health check continues to incur cost and occupy the per-account quota (200 by default), and if the endpoint's IP is later reassigned to a different tenant, the health check will silently begin probing — and reporting on — a stranger's infrastructure. Health checks are the resource-side twin of CTL.ROUTE53.DANGLING (which handles the DNS-record side); both leak from incomplete decommission flows.

**Remediation:** Delete the orphan health check or update it to target a current endpoint.

---

### CTL.ROUTE53.INCOMPLETE.001

**Complete Data Required for Route 53 Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Route 53 properties.

**Remediation:** Ensure the extractor calls aws route53 list-hosted-zones and list-health-checks.

---

### CTL.ROUTE53.LIFECYCLE.ORPHANHEALTH.001

**Route 53 Health Check Not Associated with Any Record**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC8.1;

Route 53 health check exists but is not referenced by any DNS record's HealthCheckId association. The health check monitors an endpoint but no routing decision uses the health status. The check consumes per-month cost, occupies the per-account quota (default 200 health checks), and may emit CloudWatch alarms, but does not affect DNS resolution. This typically indicates incomplete cleanup after a record was deleted (the health check was created for the record but the record was removed without removing the check), or that a planned routing change never completed (the check was created in advance for a record that was never created). Distinct from CTL.ROUTE53.HEALTHCHECK.GHOST.001 which detects health checks pointing at deleted target endpoints — this control detects health checks not referenced by any DNS record, regardless of whether the target endpoint still exists.

**Remediation:** Determine whether the health check is still needed. If a planned record creation is in progress: associate the health check with the record by setting HealthCheckId on the record. If the health check is leftover from a deleted record: delete the health check via aws route53 delete-health-check --health-check-id {id}. Audit health-check inventory periodically (the per-account default quota is 200) so unreferenced checks do not exhaust the quota and block creation of new checks. If the check was used for a CloudWatch alarm independent of DNS routing, document the intentional standalone use so future audits do not re-flag it.

---

### CTL.ROUTE53.LIFECYCLE.ORPHANZONE.001

**Route 53 Hosted Zone Has No Matching Domain Registration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC6.1;

Route 53 hosted zone exists but no domain registered in this account (or any organizational account whose registration is visible to the observer) delegates to this zone's name servers. The zone has records but no domain's NS records point to it — the zone serves no DNS resolution. This typically indicates: the zone was created for a domain registered elsewhere and the registration was moved, the zone was created for a planned domain that was never registered, or the zone is a leftover from testing. The dead zone retains records — potentially internal hostnames, IP addresses, and service endpoints — visible to anyone with route53:ListResourceRecordSets permission, while serving no DNS function. Note: this control can verify delegation only for domains registered through Route 53 in this account; for domains registered through external registrars, delegation must be verified out-of-band. The control fires only when the zone has no matching domain AND no NS delegation in the visible scope, to avoid false positives from externally-registered domains that do delegate to the zone.

**Remediation:** Determine whether the domain associated with this zone is still in use. If the domain was moved to an external registrar: verify the external registrar's NS records delegate to this zone — if so, the finding is a false positive (annotate the zone with the registrar information so future audits do not re-flag it). If the domain is no longer in use: review the zone's records for internal infrastructure information, document anything that should be tracked (in case it reveals historical service architecture), then delete the zone — first delete all resource record sets except SOA and NS, then delete the zone itself. If the domain registration is pending: the zone is reserving the configuration in advance; ensure the domain registration is completed before the zone accumulates further records.

---

### CTL.ROUTE53.LIFECYCLE.STALE.TXT.001

**Route 53 TXT Records Contain Old Verification Tokens**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC8.1;

Route 53 hosted zone contains TXT records with domain verification tokens from completed verifications — google-site- verification, ms= (Microsoft 365), atlassian-domain-verification, _amazonses, docusign=, facebook-domain-verification, and similar — that are no longer needed by the verification service. These records: clutter the zone (a busy zone obscures meaningful records), may contain tokens that could be reused if the verification service is reconfigured, and indicate incomplete cleanup after a service change. Stale verification tokens are detected heuristically by matching known verification-token patterns and flagging tokens that have not been refreshed in a long time. The heuristic cannot determine with certainty that a verification is no longer required — some services require the token to remain in DNS as long as the integration is active. The finding is a prompt to audit the verification tokens and remove those whose corresponding services have been decommissioned.

**Remediation:** Audit TXT records in the zone. For each verification token, confirm with the team responsible for the corresponding service (Google Workspace, Microsoft 365, SES, Atlassian, DocuSign, Facebook, etc.) whether the token is still required. For tokens whose service has been decommissioned: delete the TXT record. For tokens whose service is still in use: re-issue the token through the verification service to confirm it is current (most services allow re-verification, which rotates the token). Maintain an inventory of intentional verification tokens with their owning service and last-verified date so future audits can distinguish stale tokens from active ones.

---

### CTL.ROUTE53.LOG.001

**Route53 Public Hosted Zones Must Enable Query Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Public hosted zones must have DNS query logging enabled to CloudWatch Logs. Without logging, DNS queries — including reconnaissance and potential DNS tunneling — go undetected.

**Remediation:** Enable query logging to CloudWatch Logs.

---

### CTL.ROUTE53.PRIVACY.001

**Route53 Domains Must Enable WHOIS Privacy Protection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3;

Registered domains must have WHOIS privacy protection enabled to redact registrant contact details from public queries.

**Remediation:** Enable privacy protection on the domain registration.

---

### CTL.ROUTE53.PRIVATE.NOVPC.001

**Route 53 Private Hosted Zone Not Associated with Any VPC**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC6.1;

Route 53 private hosted zone exists but is not associated with any VPC. A private hosted zone resolves DNS names only within the VPCs it is associated with — VPC resources query the zone's records when resolving names in that zone's namespace. Without any VPC association, no resource can resolve the zone's records: the zone is a dead configuration. DNS records in the zone (typically internal service endpoints, database hostnames, RDS instance addresses, internal API endpoints) are permanently unresolvable. The zone retains those records — potentially containing the organization's complete internal service map — visible to anyone with route53:ListResourceRecordSets permission. This typically indicates: the zone was created but VPC association was never completed (incomplete provisioning); or all VPC associations were removed during decommissioning but the zone itself was not deleted (incomplete cleanup). Either way, the zone serves no function and documents internal infrastructure for no operational benefit.

**Remediation:** Determine whether the zone is still needed. If needed: associate the zone with the appropriate VPC — aws route53 associate-vpc- with-hosted-zone --hosted-zone-id {zone-id} --vpc VPCRegion= {region},VPCId={vpc-id}. If not needed: delete the zone — first delete all resource record sets (excluding the SOA and NS records), then delete the zone itself. Before deleting, verify that no application depends on the zone's records. Check CloudTrail for recent route53:ListResourceRecordSets API calls targeting the zone-id to identify if any service is still attempting resolution.

---

### CTL.ROUTE53.PRIVATE.PUBLICRECORDS.001

**Route 53 Private Hosted Zone Contains Records Pointing to Public IP Addresses**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC6.1;

Route 53 private hosted zone contains A records pointing to public IP addresses (addresses outside RFC 1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Private zones are designed for internal DNS resolution — internal service names should resolve to private IPs within the VPC. When an A record in a private zone resolves to a public IP, traffic from VPC resources querying that internal-looking name traverses the internet: it exits the VPC via NAT gateway or internet gateway, travels over the public internet to the public IP, and returns the same way. This is a misconfiguration pattern: a service endpoint was changed to a public IP (during troubleshooting, migration, or vendor IP change) and the DNS record was updated but never reverted. From a security standpoint, DNS resolution that appears internal but routes to the internet creates an unexpected egress path — traffic destined for what looks like an internal name actually leaves the VPC. This control does not fire on CNAME records (which point to hostnames, not IPs) or on link-local addresses (169.254.x.x, which are expected for some AWS-internal services).

**Remediation:** Identify the records: aws route53 list-resource-record-sets --hosted-zone-id {zone-id} and filter A records with non-RFC-1918 values. For each: determine whether the service was migrated to a public IP intentionally. If the service should be private, update the record to point to the internal IP or internal load balancer DNS name. If the service is now genuinely public and internal name resolution is not needed, delete the record from the private zone and use the public zone instead. If the service uses an internal ALB with a private IP, update the A record to the ALB's private IP or convert to an alias record pointing to the internal ALB.

---

### CTL.ROUTE53.QUERYLOG.ENCRYPT.001

**Route 53 Query Log Group Not Encrypted with CMK**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-9; pci_dss_v4.0: 10.5.1; soc2: CC6.1;

Route 53 DNS query log CloudWatch log group is not encrypted with a customer-managed KMS key (CMK). Query logs contain the source resolver IP addresses for every DNS query (revealing which clients queried which names), the queried domain names (which may include internal service names, database hostnames, and API endpoints encoded in subdomains), query types, and response codes. The resolver IP combined with the queried name reveals behavioral patterns: which workload queried which internal service, when, and how often. CloudWatch Logs encrypts at rest by default with an AWS-managed key (aws/logs). A CMK adds the ability to revoke key access immediately (disabling log access without deleting logs), to audit all decryption operations via CloudTrail, and to enforce fine-grained access control on who can decrypt query logs. This control fires only when query logging is enabled — zones without logging are caught by the QUERYLOG.PUBLIC/PRIVATE controls.

**Remediation:** Associate a CMK with the query log group: aws logs associate-kms- key --log-group-name {log-group-name} --kms-key-id {kms-key-arn}. The KMS key policy must grant CloudWatch Logs permission to use the key (kms:Encrypt, kms:Decrypt, kms:ReEncrypt*, kms: GenerateDataKey*, kms:Describe*) for the CloudWatch Logs service principal (logs.{region}.amazonaws.com). Existing log events in the group are not retroactively encrypted with the new key — only new events use it. To encrypt all events, create a new log group with the CMK, re-enable query logging pointing to the new group, and archive the old group before deleting it.

---

### CTL.ROUTE53.QUERYLOG.PRIVATE.001

**Route 53 Private Hosted Zone Has No Resolver Query Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

Route 53 private hosted zone (or the associated VPC's resolver) does not have resolver query logging enabled. Internal DNS queries from VPC resources — EC2 instances, Lambda functions, ECS tasks, RDS connections to internal hostnames — are unaudited. Private zones resolve internal service names, database hostnames, and configuration endpoints. An attacker who compromises any VPC resource can query internal DNS names to discover the internal service map (what databases exist, what internal APIs are reachable, what microservices are running) without any log record of the reconnaissance. Resolver query logging captures all DNS queries from VPC resources: the queried name, query type, response code, the source IP of the querying instance, and the VPC ID. Unlike public zone query logging (which captures external resolver queries), resolver query logging captures internal workload DNS activity — the signals needed to detect internal lateral movement and internal reconnaissance that public zone logs cannot see.

**Remediation:** Enable Resolver Query Logging for the VPC(s) associated with the private zone. Create a query logging config: aws route53resolver create-resolver-query-log-config --name {name} --destination-arn {cloudwatch-log-group-arn or s3-bucket-arn}. Associate it with the VPC: aws route53resolver associate-resolver-query-log-config --resolver-query-log-config-id {config-id} --resource-id {vpc-id}. Resolver query logging applies to all DNS queries from resources in the VPC, not just queries to private hosted zones — enabling it once per VPC covers all private zone resolution from that VPC.

---

### CTL.ROUTE53.QUERYLOG.PUBLIC.001

**Route 53 Public Hosted Zone Has No DNS Query Logging**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 3.1; nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

Route 53 public hosted zone does not have DNS query logging enabled. DNS query logs are the only visibility into DNS resolution patterns for the zone — every query received by Route 53 is recorded: the queried domain name, query type (A, AAAA, MX, TXT), response code (NOERROR, NXDOMAIN, SERVFAIL), the resolver IP that sent the query, and the timestamp. Without query logging: DNS tunneling (encoding data in DNS queries to exfiltrate information to an attacker- controlled authoritative server) is completely invisible — the attacker's queries arrive and are answered but no log records them. Reconnaissance (probing for internal subdomain names to map internal infrastructure) is undetectable. Anomalous query patterns (sudden spike in queries to a single subdomain, systematic enumeration of subdomains, query patterns consistent with DGA-based C2) leave no forensic trail. Public zones are the primary surface for DNS-layer threat detection because they receive external resolver traffic — any client on the internet can query a public zone, making these zones the entry point for DNS-based attacks and surveillance.

**Remediation:** Enable DNS query logging for the hosted zone. Create a CloudWatch Logs log group for query logs: aws logs create-log-group --log- group-name /aws/route53/{zone-name}. Grant Route 53 permission to write to the log group via a resource-based policy. Enable query logging: aws route53 create-query-logging-config --hosted-zone-id {zone-id} --cloud-watch-logs-log-group-arn {log-group-arn}. Query logs are written to CloudWatch Logs within a few minutes of enabling. Note: DNS query logging is only available for public hosted zones. Private zone resolver query logging uses Resolver Query Logging (CTL.ROUTE53.QUERYLOG.PRIVATE.001).

---

### CTL.ROUTE53.QUERYLOG.RETENTION.001

**Route 53 Query Log Group Has Insufficient Retention**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-11; pci_dss_v4.0: 10.7; soc2: CC7.2;

Route 53 DNS query log CloudWatch log group has no retention policy or a retention period below 365 days. DNS query logs document every query received by the hosted zone. When a security incident is investigated — DNS tunneling detected, domain compromise suspected, unauthorized subdomain queries found — the investigation window typically extends 6 to 12 months. Logs deleted before the investigation window closes make root-cause analysis impossible. Compliance frameworks (PCI-DSS, NIST 800-53, SOC2) require audit logs to be retained for periods that exceed typical CloudWatch default retention (which is none — logs never expire unless a retention policy is set, but the billing cost motivates teams to set short retention policies). This control fires only when query logging is already enabled — zones without logging are caught by CTL.ROUTE53.QUERYLOG.PUBLIC.001 and CTL.ROUTE53.QUERYLOG.PRIVATE.001.

**Remediation:** Set a retention policy on the query log group: aws logs put- retention-policy --log-group-name {log-group-name} --retention- in-days 365. For compliance frameworks requiring longer retention (HIPAA: 6 years, some PCI auditors: 12 months minimum), increase accordingly. Consider exporting logs to S3 with an S3 lifecycle policy for long-term retention — CloudWatch Logs is expensive for multi-year retention of high-volume DNS query logs. Use CloudWatch Logs Insights for interactive queries on recent logs; archive to S3 for historical investigation.

---

### CTL.ROUTE53.RECORD.A.DATABASE.001

**DNS Record Points Directly to Database Endpoint**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3; soc2: CC6.1;

Route 53 record resolves to a database endpoint directly — RDS (*.rds.amazonaws.com), ElastiCache (*.cache.amazonaws.com), Redshift (*.redshift.amazonaws.com), or DocumentDB (*.docdb.amazonaws.com) — without an application tier or proxy in between. The database is DNS-addressable from any client that can resolve the name. If the record is in a public hosted zone, the database endpoint is discoverable by anyone — combined with a misconfigured security group, the database is directly accessible from the internet. If the record is in a private zone, internal-network access to the database does not require service discovery via tagged resources or environment variables; the database is one DNS query away from any compromised resource in the VPC. The control flags this architectural pattern: a database that is reachable directly from clients (rather than through an application tier with its own credentials, rate limiting, and audit log) increases blast radius for any client compromise. The detection heuristic matches AWS database service hostname patterns and should be extended as new database services are added.

**Remediation:** Determine why the database is exposed via DNS. If the record was added for application configuration convenience, change the application to read the database endpoint from secrets manager or parameter store rather than from public/private DNS. If the DNS abstraction is required (failover, environment-specific endpoints), point the record at an application proxy or RDS Proxy that fronts the database — preserving the indirection while removing direct addressability. For records in public zones: this is severity-elevated — combined with an unrestricted security group, the database is internet-accessible. Audit the security group for the database; if 0.0.0.0/0 is allowed on the database port, this is a critical exposure pair (resolve both the DNS record and the SG). For records in private zones: review whether the application tier is still required as a control point — direct database addressability removes the application's role as an authorization boundary.

---

### CTL.ROUTE53.RECORD.ALIAS.NOHEALTH.001

**Route 53 Alias Record Has EvaluateTargetHealth Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-7; soc2: A1.1;

Route 53 alias record has evaluateTargetHealth set to false. Alias records can propagate health from the target resource (ALB, CloudFront, API Gateway, S3 website endpoint, another Route 53 record) — when the target is unhealthy, Route 53 stops returning this alias for queries. With evaluateTargetHealth disabled, Route 53 always returns the alias regardless of whether the target is healthy: traffic is routed to unhealthy or unreachable targets, defeating the resilience benefit of alias records. The control is medium severity because evaluateTargetHealth=false is sometimes intentional — the target handles its own health management (CloudFront origin failover, ALB internal target health), or the target type does not support target health evaluation (S3 buckets, certain API Gateway configurations). The finding is a prompt to confirm that the disabled health evaluation is intentional and that another mechanism (CloudWatch alarm, application-level circuit breaker, secondary DNS-level health check) handles unhealthy-target detection.

**Remediation:** For alias records pointing to ALBs, NLBs, or other Route 53 records: enable evaluateTargetHealth — aws route53 change-resource-record-sets and set EvaluateTargetHealth=true in the AliasTarget block. Route 53 will stop returning the alias when the target is unhealthy. For alias records where target health evaluation is not supported (S3, some CloudFront cases) or is intentionally handled by the target itself: document the decision in the record's owner-tag or an out-of-band registry so future audits do not re-flag the finding, and verify the compensating mechanism (CloudFront origin failover, ALB target group health, application circuit breaker) is operational and tested.

---

### CTL.ROUTE53.RECORD.INTERNAL.EXPOSED.001

**Public Hosted Zone Contains Records Exposing Internal Infrastructure**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Route 53 public hosted zone contains CNAME or A records that reference internal infrastructure — RFC 1918 IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), internal AWS hostnames (RDS endpoints, internal ALB names, EC2 private DNS), or SRV records exposing internal ports. Public DNS is queryable by anyone — no authentication, no access control. Records like internal.example.com → 10.0.1.50 or db.example.com → rds-prod.c9abcdef.us-east-1.rds.amazonaws.com expose internal architecture in public DNS. An attacker queries the domain and discovers the internal IP addressing scheme (10.0.1.0/24 for production, 10.0.2.0/24 for staging), database endpoints (RDS identifiers reveal engine type, region, and account), and service topology. This information aids targeted attacks once the attacker has internal network access — they no longer need to enumerate from inside. The check fires only on PUBLIC hosted zones; private zones containing internal IPs is expected behavior.

**Remediation:** Identify the internal records: aws route53 list-resource-record-sets --hosted-zone-id {zone-id} and filter A records with RFC 1918 values (10.x, 172.16-31.x, 192.168.x) and CNAME records pointing to internal AWS hostnames. For each record: if the service is public-facing, repoint to the public DNS name (the ALB DNS name, the CloudFront distribution name) rather than the internal IP. If the service is internal-only, move the record to a private hosted zone associated with the appropriate VPC and remove it from the public zone. Audit SRV records exposing internal port numbers — these reveal service topology (database ports, Kerberos ports, internal RPC ports) and should not appear in public DNS.

---

### CTL.ROUTE53.RECORD.WILDCARD.001

**Route 53 Wildcard Record Catches All Subdomains**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Route 53 hosted zone has a wildcard record (*.example.com) that matches every subdomain not explicitly defined in the zone. Wildcard records resolve typos, test subdomains, and any subdomain an attacker probes — all to the wildcard target. This: masks dangling DNS detection (a deleted service's subdomain still resolves via the wildcard, suppressing the NXDOMAIN signal that flags dangling records), hides reconnaissance (an attacker probing for subdomains always gets a response — they cannot distinguish real subdomains from wildcard matches), and routes unintended traffic to one endpoint regardless of intended audience. Wildcard records have legitimate uses (catch-all for SaaS multi-tenancy, fallback landing pages) — the finding is a request to review whether the wildcard is intentional, and to understand that it suppresses the organization's primary subdomain takeover detection signal.

**Remediation:** Review whether the wildcard record is required. If it exists for historical reasons or convenience, replace it with explicit records for the subdomains the organization actually uses. If it is required (SaaS multi-tenancy, customer-facing catch-all), document the business justification and compensate by: (1) auditing explicit records monthly to detect dangling entries that the wildcard would otherwise mask, (2) using application-level checks on the wildcard target to distinguish real tenants from probes, (3) routing wildcard traffic to a dedicated landing page rather than a production application. For zones that mix wildcards and explicit records, ensure every legitimate subdomain has an explicit record so dangling detection works for those names — only typos and unknown probes resolve via the wildcard.

---

### CTL.ROUTE53.RESOLVER.GHOST.FORWARDER.001

**Route 53 Resolver Forwarding Rule Points to Unreachable Target**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CP-7; soc2: A1.1;

Route 53 resolver outbound forwarding rule specifies target IP addresses (typically on-premises DNS servers reached via VPN or Direct Connect) that are unreachable. DNS queries matching the forwarding rule's domain (e.g., corp.example.com) are forwarded to the target IPs. When the targets are unreachable, every DNS query for the forwarded domain times out — the resolver sends the query to the configured IPs, receives no response, and returns SERVFAIL. Every VPC resource that resolves any name under the forwarded domain fails. The forwarding rule appears correctly configured in the console — it has a domain, it has targets, it is associated with a VPC. The targets do not respond. This is the ghost reference pattern applied to DNS resolver targets: the rule was configured when the on-premises DNS servers were live; the servers were decommissioned, the VPN was reconfigured, or the on-premises IPs changed; the forwarding rule was never updated. The rule continues to look correct while silently failing every query that matches its domain. For outbound forwarding rules pointing to corporate DNS, the blast radius covers every internal hostname that VPC resources query.

**Remediation:** Identify unreachable targets: check connectivity to the target IPs over port 53 (UDP and TCP) from within the VPC — if Direct Connect or VPN is the path, verify the connection is active first. Update the forwarding rule with correct target IPs: aws route53resolver update-resolver-rule --resolver-rule-id {rule-id} --config TargetIps=[{Ip={new-ip},Port=53}]. If the on-premises DNS servers were decommissioned with no replacement, delete the forwarding rule — aws route53resolver delete-resolver-rule — and disassociate it from any VPCs first. If the forwarded domain names should resolve via Route 53 public DNS instead, remove the forwarding rule to let queries fall through to the default Route 53 resolver.

---

### CTL.ROUTE53.RESOLVER.SINGLEAZ.001

**Route 53 Resolver Endpoint in Single Availability Zone**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CP-7; soc2: A1.2;

Route 53 resolver endpoint (inbound or outbound) has IP addresses assigned in only one Availability Zone. Resolver endpoints are the DNS bridge between VPCs and on-premises networks: an inbound endpoint allows on-premises DNS resolvers to forward queries for Route 53 private zones to Route 53, enabling on-premises systems to resolve internal AWS service names; an outbound endpoint allows VPC resources to forward DNS queries for on-premises domains to on-premises DNS resolvers via forwarding rules, enabling VPC workloads to resolve internal corporate hostnames. With IP addresses in a single AZ, an AZ failure renders the endpoint unavailable: for inbound endpoints, on-premises systems receive resolution failures for all private zone names — hybrid application connectivity breaks; for outbound endpoints, VPC resources receive resolution failures for all forwarded domains — any workload that depends on on-premises DNS names fails. This is the DNS equivalent of a single-AZ database: the endpoint works under normal conditions but becomes a single point of failure during the AZ events that DNS redundancy is specifically designed to survive. Resolver endpoints should have IPs in at least two AZs.

**Remediation:** Add IP addresses in a second AZ to the resolver endpoint: aws route53resolver update-resolver-endpoint --resolver-endpoint-id {endpoint-id} --actions Operation=ADD,IpId=... The endpoint requires a subnet in the target AZ — create the subnet first if needed. Each AZ needs at least one IP address assigned. Route 53 Resolver automatically load-balances queries across all endpoint IPs; adding a second AZ IP creates redundancy without any configuration change to forwarding rules. Best practice is two IPs in two different AZs; three IPs across three AZs for higher availability in regions with three AZs.

---

### CTL.ROUTE53.ROUTING.GEO.NODEFAULT.001

**Route 53 Geolocation Routing Has No Default Record**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-22; soc2: A1.1;

Route 53 geolocation routing policy has records for specific countries or continents but no default record. Geolocation routing matches viewer location to DNS records by country or continent. If the viewer's location does not match any configured record, Route 53 needs a default record to return. Without a default record, viewers from countries not covered by any geolocation record receive NXDOMAIN — the domain appears to not exist for those viewers. A user in a country not listed in the geolocation configuration gets a complete DNS resolution failure. This is a silent failure: the organization does not know viewers in unlisted countries cannot reach the domain, and those viewers have no way to distinguish between "the service does not exist" and "the service exists but did not configure DNS for my location." A default record catches all unmatched locations and provides a fallback — typically the same endpoint as the nearest region or a global endpoint.

**Remediation:** Add a default geolocation record to the record set. In the AWS console, add a record with Location=Default. Via CLI, include GeoLocation={CountryCode=*} in the resource record set. The default record receives traffic from any location not matched by a more specific geolocation record. Point the default to the nearest global endpoint or to a global load balancer. Ensure the default record has a health check if the endpoint may become unhealthy — otherwise viewers in unmatched locations will route to an unhealthy endpoint with no fallback.

---

### CTL.ROUTE53.TRANSFER.001

**Route53 Domains Must Enable Transfer Lock**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Registered domains must have transfer lock (clientTransferProhibited) enabled to prevent unauthorized domain transfers. Without transfer lock, an attacker who compromises registrar credentials can transfer the domain to another registrar.

**Remediation:** Enable transfer lock on the domain registration.

---

### CTL.ROUTE53.ZONE.CAA.MISSING.001

**Route 53 Zone Has No CAA Record**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-20; soc2: CC6.1;

Route 53 public hosted zone has no CAA (Certificate Authority Authorization) record. Without CAA, any of the hundreds of public certificate authorities can issue SSL/TLS certificates for the domain. The CA/Browser Forum requires CAs to check CAA records before certificate issuance. An attacker who compromises a CA with weak domain validation, or who social-engineers a CA's issuance process, can obtain a legitimately signed certificate for the domain. With a valid certificate, the attacker can intercept HTTPS traffic without triggering browser security warnings. CAA limits certificate issuance to the CAs the organization actually uses — typically one or two (Amazon, Let's Encrypt, DigiCert). This control is medium severity because CAA is a defense-in-depth measure: a compromised CA may ignore the CAA check, and most organizations use reputable CAs with strong issuance controls. CAA is most effective against legitimate CAs with weak validation processes.

**Remediation:** Add CAA records to Route 53 restricting which CAs can issue certificates for the domain. Add one CAA record per authorized CA: example.com CAA 0 issue "amazon.com" — for ACM certificates. example.com CAA 0 issue "letsencrypt.org" — if using Let's Encrypt. Add a CAA record with tag "issuewild" to restrict wildcard certificate issuance separately (optional, defaults to issue policy if absent). Add iodef to report unauthorized issuance attempts: example.com CAA 0 iodef "mailto:security@example.com"

---

### CTL.ROUTE53.ZONE.DELEGATION.UNVERIFIED.001

**Route 53 NS Record Delegates Subdomain to External Name Servers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-20; soc2: CC6.1;

Route 53 has an NS record that delegates a subdomain to name servers outside the organization's Route 53 infrastructure. NS delegation transfers DNS authority for the subdomain to the specified name servers — the delegated name servers control all DNS records for the subdomain. When the delegated name servers are external (not Route 53, not the organization's own DNS infrastructure), the external operator controls DNS resolution for the subdomain. If the external service is discontinued (lame delegation — the name servers no longer serve the zone), compromised (attacker modifies DNS records), or misconfigured, the organization has no control over the subdomain's DNS. For subdomains hosting production services, email, or customer-facing applications, external NS delegation is a control gap requiring documented authorization. This control identifies unverified external delegation — NS records pointing to name servers not under organizational control.

**Remediation:** Audit the NS delegation: verify the external name servers are intentionally used and the delegation is authorized. If authorized, document the delegation with the business justification and owner. If the external service has been discontinued: remove the NS delegation record from Route 53 immediately (lame delegation creates subdomain takeover risk). If the subdomain should remain on Route 53: create a hosted zone in Route 53 for the subdomain and update the NS record to Route 53 name servers. Unverified external delegation is a control gap regardless of intent.

---


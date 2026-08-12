# Control Reference — WAF

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.WAF.API.NORULES.001

**WAF Protecting API Endpoint Must Have API Rule Group**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

Web ACL protects an API endpoint but has no managed rule group for API-specific attack detection. API attacks (GraphQL query abuse, JWT token anomalies, SSRF via API parameters, prototype pollution, credential brute force on login endpoints) are not covered by generic AWS managed rules (AWSManagedRulesCommonRuleSet). API-specific rule groups detect these patterns.

**Remediation:** Subscribe to a WAF managed rule group with API threat detection. Options include Salt Security and other Marketplace vendors with API-specific rules. Add in BLOCK mode alongside existing AWS managed rules.

---

### CTL.WAF.CLASSIC.DEPRECATED.001

**No Resource Must Use WAF Classic (Retired September 2025)**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC6.1;

A WAF Classic WebACL exists in the account. AWS retired WAF Classic on September 30, 2025. Resources still associated with WAF Classic WebACLs are running on unsupported infrastructure that receives no rule updates, no new features, and no security patches. WAF Classic resources are invisible to the entire WAFv2 control family — every existing WAF control in the catalog evaluates wafv2: resources only. A WAF Classic WebACL is a SILENT_RISK: the resource appears to have WAF protection but is excluded from all WAF compliance checks. Source: AWS breaking_changes repo, WAF Classic retirement announcement (2024).

**Remediation:** Migrate the WebACL to WAFv2 using the AWS WAF Classic migration wizard or manual recreation. Associate the new WAFv2 WebACL with the same resources (ALB, CloudFront, API Gateway). Delete the Classic WebACL after migration.

---

### CTL.WAF.DELIVERY.HEALTH.001

**WAF Logging Must Be Delivering**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-6; nist_800_53_r5: AU-6; pci_dss_v4.0: 10.3.1; soc2: CC7.2;

WAF logging is configured on the web ACL but log data is not reaching the destination. WAF logs can target Kinesis Data Firehose, S3, or CloudWatch Logs. When the destination fails — Firehose delivery errors, S3 bucket policy changes, or CloudWatch Logs quota exceeded — WAF continues processing requests but silently stops delivering log data. The web ACL shows logging as enabled. Security teams believe they have request-level visibility but the logs have a gap. This is the delivery health pattern applied to WAF: inspection is functioning but the audit trail is broken.

**Remediation:** Check the WAF logging destination for errors. For Kinesis Data Firehose: check DeliveryToS3.Errors and ThrottledRecords metrics. For S3: verify bucket policy allows WAF service principal writes. For CloudWatch Logs: check quota limits. Set up CloudWatch alarms on destination error metrics to detect future delivery failures.

---

### CTL.WAF.EVASION.OBSERVE.001

**WAF Must Have Full Body Inspection and Request Sampling Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; hipaa: 164.312(b); nist_800_53_r5: SI-4; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

WAF Web ACLs must have full request body inspection enabled and sampled allowed-request logging active. Signature-based WAF rules can be evaded through encoding techniques such as CRLF injection, Unicode surrogate pairs, and HTML parser confusion. HackerOne report #2921905 documents a WAF bypass using CRLF and HTML attribute confusion that evaded Cloudflare rule matching entirely. Prevention of encoding evasion is a vendor responsibility, but the organization must ensure that when evasion occurs it is observable. Without full body inspection, payloads in POST bodies, JSON fields, and multipart uploads are invisible to all WAF rules. Without sampled allowed-request logging, successful bypass attempts leave no forensic trace — the organization cannot distinguish between no attacks and undetected attacks. This control differs from CTL.WAF.LOGGING.001 (which checks logging is enabled) by verifying the logging and inspection configuration captures enough detail to detect evasion patterns. This control is the **evasion observability** check in the seven-control WAF safety envelope: presence (CTL.WAF.RULES.001), enforcement (CTL.WAF.RULES.BLOCKMODE.001), coverage (CTL.WAF.RULES.OWASP.001), visibility (CTL.WAF.LOGGING.001), architectural prerequisite (CTL.WAF.ORIGIN.LOCKDOWN.001), parser overflow protection (CTL.WAF.PARSERLIMIT.PROTECT.001), and evasion observability (CTL.WAF.EVASION.OBSERVE.001). All seven may fire on the same Web ACL simultaneously; each addresses a distinct failure mode.

**Remediation:** Enable full request body inspection on the Web ACL and increase the body size inspection limit beyond the default 8KB to cover modern API payloads. Enable sampled request logging for allowed requests — not only blocked requests. For AWS WAF, configure the Web ACL body inspection to inspect the full body and enable request sampling via the AWS WAF console or UpdateWebACL API. Reference: HackerOne report #2921905 documents a WAF bypass via CRLF injection that would be detectable with full body inspection and request sampling.

---

### CTL.WAF.INCOMPLETE.001

**Complete Data Required for WAF Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

WAF assessment data is incomplete. The extractor must populate waf.rules.has_managed_rules to evaluate protection controls.

**Remediation:** Re-run the extractor with WAF permissions: wafv2:GetWebACL, wafv2:ListWebACLs, wafv2:GetLoggingConfiguration.

---

### CTL.WAF.IPSET.EMPTY.001

**WAF IP Set Has No Addresses**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC6.1;

A WAF IP set exists but contains no IP addresses. Any rule referencing this IP set matches nothing. If used in an allow rule, no traffic is allowed through that path. If used in a block rule, no traffic is blocked. Either case indicates a misconfiguration or stale resource.

**Remediation:** Add IP addresses to the IP set or delete the unused IP set. Use aws wafv2 update-ip-set to add addresses.

---

### CTL.WAF.LOGGING.001

**WAF Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; nist_800_53_r5: AU-2; soc2: CC7.1;

WAF web ACLs must have logging enabled to record blocked and allowed requests. Without logging, attacks cannot be detected, investigated, or correlated with other security events. This control is the **visibility** check in the seven-control WAF safety envelope: presence (CTL.WAF.RULES.001), enforcement (CTL.WAF.RULES.BLOCKMODE.001), coverage (CTL.WAF.RULES.OWASP.001), visibility (CTL.WAF.LOGGING.001), architectural prerequisite (CTL.WAF.ORIGIN.LOCKDOWN.001), parser overflow protection (CTL.WAF.PARSERLIMIT.PROTECT.001), and evasion observability (CTL.WAF.EVASION.OBSERVE.001). All seven may fire on the same Web ACL simultaneously; each addresses a distinct failure mode.

**Remediation:** Enable WAF logging to S3, CloudWatch Logs, or Kinesis Data Firehose via aws wafv2 put-logging-configuration.

---

### CTL.WAF.LOGGING.OVERREDACTED.001

**WAF Logging Redacts All Request Fields**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-3; soc2: CC7.1;

The WAF logging configuration redacts all request fields. Logs contain rule match results but no request details. Incident investigation cannot determine what triggered a rule or what the attacker was targeting. Redaction is appropriate for sensitive fields (authorization headers, cookies) but redacting everything eliminates forensic value.

**Remediation:** Reduce the redaction scope to only sensitive fields (authorization headers, cookies). Use aws wafv2 put-logging-configuration to update RedactedFields.

---

### CTL.WAF.MANAGED.COUNTONLY.001

**WAF Managed Rule Groups Must Not All Be in COUNT Mode**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

All managed rule groups on this Web ACL are configured with COUNT override action — rules detect threats but do not block them. This is false protection: the WAF logs show detections but malicious requests pass through to the application. Managed rule groups should use BLOCK mode (or no override, which defaults to the rule group's action) for active protection.

**Remediation:** Change the override action on managed rule groups from COUNT to NONE (use the rule group's default action, which is BLOCK for most rules). If specific rules need COUNT for tuning, override individual rules within the group rather than the entire group.

---

### CTL.WAF.MANAGEDRULE.IPREP.MISSING.001

**WAF Web ACL Missing IP Reputation Managed Rule Group**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

The Web ACL does not include the Amazon IP Reputation List or Anonymous IP List managed rule group. Traffic from known-bad sources — botnets, Tor exit nodes, hosting providers used for attacks — is not automatically blocked. This control differs from CTL.WAF.RULES.001 (any managed rules) and CTL.WAF.RULES.OWASP.001 (OWASP core coverage) by checking specifically for IP reputation intelligence.

**Remediation:** Add the AWSManagedRulesAmazonIpReputationList managed rule group to the Web ACL. Consider also adding AWSManagedRulesAnonymousIpList for Tor and VPN traffic.

---

### CTL.WAF.MCP.NORULES.001

**WAF Protecting MCP Endpoint Must Have MCP Rule Group**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-3; soc2: CC6.6;

Web ACL protects a resource serving MCP/AI agent traffic but has no managed rule group for MCP threat detection. MCP endpoints accept tool calls, function invocations, and agent-to-agent communication — attack patterns that generic WAF rules do not cover. Without MCP-specific rules, unauthenticated MCP access, prompt injection via tool parameters, and MCP-based SSRF go undetected at the WAF layer.

**Remediation:** Subscribe to a WAF managed rule group with MCP threat detection (e.g., Salt Security AI Agent & API Security from AWS Marketplace). Add the rule group to the Web ACL in BLOCK mode.

---

### CTL.WAF.METRICS.DISABLED.001

**WAF Web ACL CloudWatch Metrics Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.1;

The Web ACL VisibilityConfig does not enable CloudWatch metrics. Rule match counts and default action counts are not tracked. Attack detection alarms and rule effectiveness measurement are not possible without metrics. This control fires independently of logging — metrics track aggregate counts while logging captures per-request details.

**Remediation:** Enable CloudWatchMetricsEnabled and SampledRequestsEnabled in the Web ACL VisibilityConfig. Set a meaningful MetricName.

---

### CTL.WAF.ORIGIN.LOCKDOWN.001

**WAF Origin Must Not Accept Direct Internet Traffic**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

When a WAF Web ACL is associated with an origin server (ALB, API Gateway, EC2 instance), the origin's network ingress controls must not permit inbound connections on application ports from the public internet. A WAF that sits in front of an origin provides zero protection if the origin also accepts direct connections from 0.0.0.0/0 or ::/0 — an attacker who discovers the origin IP address through Censys, Shodan, certificate transparency logs, historical DNS records, or timing analysis can send traffic directly to the origin, bypassing every WAF rule, DDoS protection, and rate limit. This is the architectural prerequisite for all other WAF controls — without origin lockdown, the entire WAF safety envelope is irrelevant regardless of how well the WAF rules are configured. HackerOne report (Linode) documents this exact pattern: an origin behind Cloudflare was discoverable via Censys, allowing direct unfiltered payload delivery and denial-of-service against the unprotected origin. This control is the **architectural prerequisite** in the seven-control WAF safety envelope: presence (CTL.WAF.RULES.001), enforcement (CTL.WAF.RULES.BLOCKMODE.001), coverage (CTL.WAF.RULES.OWASP.001), visibility (CTL.WAF.LOGGING.001), architectural prerequisite (CTL.WAF.ORIGIN.LOCKDOWN.001), parser overflow protection (CTL.WAF.PARSERLIMIT.PROTECT.001), and evasion observability (CTL.WAF.EVASION.OBSERVE.001). All seven may fire on the same Web ACL simultaneously; each addresses a distinct failure mode.

**Remediation:** Restrict the origin's security group inbound rules on application ports (80, 443, custom) to allow traffic only from WAF or CDN provider IP ranges. For CloudFront, use the AWS-managed prefix list com.amazonaws.global.cloudfront.origin-facing in the security group rule. For regional ALBs behind AWS WAF, restrict to the WAF endpoint subnet CIDRs. Remove all 0.0.0.0/0 and ::/0 ingress rules on application ports.

---

### CTL.WAF.PARSERLIMIT.PROTECT.001

**WAF Must Block Requests That Exceed Parser Limits**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10; hipaa: 164.312(e)(1); nist_800_53_r5: SI-10; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

WAF Web ACLs must contain a highest-priority rule that detects when the WAF's internal parser limits have been exceeded and blocks the request. Every WAF has parser limits — maximum header count, maximum header size, maximum body size, maximum cookie count. When a request exceeds these limits, rule evaluation silently stops at the truncation point. Rules configured to inspect content beyond the limit never fire. The request passes through as if clean. A Cloudflare HackerOne report (High severity, $1,250 bounty, 2025-11-18) documented this: 94+ HTTP headers caused all WAF rules, cache key evaluation, and cache rules to bypass simultaneously. Cloudflare's mitigation: a rule checking http.request.headers.truncated at highest priority in BLOCK mode. This vulnerability class applies to every WAF vendor — the invariant is vendor-neutral. The parser limit protection rule must execute before all other rules. A rule at lower priority allows other rules to evaluate truncated content before the overflow is detected, creating a race condition attackers can exploit. This control is the prerequisite for all other WAF rule controls — if the parser can be overflowed, managed rules, OWASP coverage, and custom rules are irrelevant for any request designed to exceed the limit. This control is the **parser overflow protection** check in the seven-control WAF safety envelope: presence (CTL.WAF.RULES.001), enforcement (CTL.WAF.RULES.BLOCKMODE.001), coverage (CTL.WAF.RULES.OWASP.001), visibility (CTL.WAF.LOGGING.001), architectural prerequisite (CTL.WAF.ORIGIN.LOCKDOWN.001), parser overflow protection (CTL.WAF.PARSERLIMIT.PROTECT.001), and evasion observability (CTL.WAF.EVASION.OBSERVE.001). All seven may fire on the same Web ACL simultaneously; each addresses a distinct failure mode.

**Remediation:** Add a rule at the highest priority position (priority 0 or the lowest numeric value) that detects parser overflow and blocks the request. For Cloudflare, check http.request.headers.truncated == true. For AWS WAF, use a size constraint rule checking header count or total header size against the documented parser limit. The rule must be in BLOCK mode — COUNT mode detects but does not prevent the bypass. Verify the rule has higher priority than all managed rule groups and custom rules in the Web ACL.

---

### CTL.WAF.RATELIMIT.MISSING.001

**WAF Web ACL Has No Rate-Based Rule**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

The Web ACL has rules but none are rate-based. HTTP flood attacks pass through because no rule limits request volume per source IP. Rate-based rules are the primary WAF defense against volumetric application-layer DDoS. Without them, an attacker can exhaust backend capacity with high request rates that each individually pass rule evaluation.

**Remediation:** Add a rate-based rule with an appropriate threshold (e.g. 2000 requests per 5-minute window per IP). Use aws wafv2 update-web-acl with a RateBasedStatement.

---

### CTL.WAF.RULEGROUP.NOMETRICS.001

**WAF Rule Group Has No CloudWatch Metrics**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

A custom rule group does not enable CloudWatch metrics. Individual rule match counts within the group are not tracked. Rule effectiveness cannot be measured and attack patterns targeting specific rules cannot be detected via alarms.

**Remediation:** Enable CloudWatchMetricsEnabled in the rule group VisibilityConfig. Use aws wafv2 update-rule-group.

---

### CTL.WAF.RULES.001

**WAF Must Have Managed Rule Groups Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

WAF web ACLs must include AWS managed rule groups for common attack patterns (SQLi, XSS, known bad inputs). Without managed rules, the WAF provides no baseline protection against OWASP Top 10 attacks. This control is the **presence** check in the seven-control WAF safety envelope: presence (CTL.WAF.RULES.001), enforcement (CTL.WAF.RULES.BLOCKMODE.001), coverage (CTL.WAF.RULES.OWASP.001), visibility (CTL.WAF.LOGGING.001), architectural prerequisite (CTL.WAF.ORIGIN.LOCKDOWN.001), parser overflow protection (CTL.WAF.PARSERLIMIT.PROTECT.001), and evasion observability (CTL.WAF.EVASION.OBSERVE.001). All seven may fire on the same Web ACL simultaneously; each addresses a distinct failure mode.

**Remediation:** Add AWS managed rule groups to the web ACL: AWSManagedRulesCommonRuleSet, AWSManagedRulesSQLiRuleSet, AWSManagedRulesKnownBadInputsRuleSet.

---

### CTL.WAF.RULES.BLOCKMODE.001

**WAF Rules Must Be in BLOCK Mode, Not COUNT Mode**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

All WAF rules and rule groups must have their effective action set to BLOCK. A rule in COUNT mode observes and logs attacks but does not block them. AWS WAF defaults newly added rules to COUNT mode during tuning. This becomes a permanent misconfiguration when teams never transition to BLOCK. The WAF appears active in every compliance report while blocking nothing. COUNT mode may be intentional during tuning — the stave/waf-count-mode-justified tag documents this exception. This control is the **enforcement** check in the seven-control WAF safety envelope: presence (CTL.WAF.RULES.001), enforcement (CTL.WAF.RULES.BLOCKMODE.001), coverage (CTL.WAF.RULES.OWASP.001), visibility (CTL.WAF.LOGGING.001), architectural prerequisite (CTL.WAF.ORIGIN.LOCKDOWN.001), parser overflow protection (CTL.WAF.PARSERLIMIT.PROTECT.001), and evasion observability (CTL.WAF.EVASION.OBSERVE.001). All seven may fire on the same Web ACL simultaneously; each addresses a distinct failure mode.

**Remediation:** Transition COUNT-mode rules to BLOCK mode. If COUNT mode is intentional during tuning, add a stave/waf-count-mode-justified tag to the WebACL with the justification (e.g., ticket number).

---

### CTL.WAF.RULES.OWASP.001

**WAF Must Have OWASP Core Rule Coverage**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; owasp_top10_2021: A03; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

WAF web ACLs must include the three core AWS managed rule groups that cover OWASP Top 10 attack categories: AWSManagedRulesCommonRuleSet (XSS, path traversal, HTTP violations), AWSManagedRulesSQLiRuleSet (SQL injection), and AWSManagedRulesKnownBadInputsRuleSet (Log4Shell, deserialization, known CVE payloads). All three groups must be attached and enforcing in BLOCK mode. A WAF with custom rules only, or with managed rule groups that cover IP reputation or bot management but not OWASP attack categories, provides incomplete coverage. This control differs from CTL.WAF.RULES.001 (which checks for any managed rules) by requiring the specific groups needed for baseline OWASP coverage. HackerOne report #382625 documents a stored XSS bypass against a production WAF that was active and blocking with custom rules but lacked AWSManagedRulesCommonRuleSet — the payload used a marquee element with an inline event handler, a known vector covered by the CrossSiteScripting_BODY rule in the common rule set. This control is the **coverage** check in the seven-control WAF safety envelope: presence (CTL.WAF.RULES.001), enforcement (CTL.WAF.RULES.BLOCKMODE.001), coverage (CTL.WAF.RULES.OWASP.001), visibility (CTL.WAF.LOGGING.001), architectural prerequisite (CTL.WAF.ORIGIN.LOCKDOWN.001), parser overflow protection (CTL.WAF.PARSERLIMIT.PROTECT.001), and evasion observability (CTL.WAF.EVASION.OBSERVE.001). All seven may fire on the same Web ACL simultaneously; each addresses a distinct failure mode.

**Remediation:** Add the following AWS managed rule groups to the web ACL and ensure each is in BLOCK mode with no COUNT override at the group level or rule action override level: (1) AWSManagedRulesCommonRuleSet — covers XSS, path traversal, common exploits, (2) AWSManagedRulesSQLiRuleSet — covers SQL injection attack patterns, (3) AWSManagedRulesKnownBad InputsRuleSet — covers known CVE exploits including Log4j and Spring4Shell.

---

### CTL.WAF.WEBACL.DEFAULTALLOW.001

**WAF Web ACL Default Action is ALLOW**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

The Web ACL default action allows requests that do not match any rule. Requests not explicitly blocked or rate-limited pass through. Default should be BLOCK with explicit ALLOW rules for known-good patterns. A default-allow ACL with managed rules only blocks known bad patterns — novel attacks, zero-days, and uncovered attack categories pass through silently.

**Remediation:** Change the Web ACL default action to Block. Add explicit Allow rules for known-good request patterns. Use aws wafv2 update-web-acl to change the DefaultAction to Block.

---

### CTL.WAF.WEBACL.NORULES.001

**WAF Web ACL Has No Rules**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

A Web ACL exists but has zero rules — no managed rule groups, no custom rules, no rate-based rules. Every request matches the default action. The WAF provides no filtering regardless of the default action setting. An auditor checking "is WAF configured?" sees the ACL and marks it compliant while the WAF evaluates nothing.

**Remediation:** Add at minimum the AWS managed core rule set (AWSManagedRulesCommonRuleSet), the SQL injection rule set (AWSManagedRulesSQLiRuleSet), and a rate-based rule for IP-level throttling.

---


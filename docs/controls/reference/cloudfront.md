# Control Reference — CLOUDFRONT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CLOUDFRONT.ACCESS.GEORESTRICTION.BLOCKLIST.001

**CloudFront Geo-Restriction Uses Blocklist Instead of Allowlist**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

CloudFront geographic restriction uses a blocklist (specific countries blocked, all others allowed by default) rather than an allowlist (specific countries permitted, all others blocked by default). A blocklist is weaker than an allowlist as a security control: it explicitly enumerates threats while unknowns are allowed. New threat origins (recently sanctioned countries, newly observed attack sources, typosquatted country codes) are not blocked until explicitly added to the list. An allowlist applies the principle of least privilege to geography: only explicitly permitted countries can access the distribution. For organizations that serve known geographic markets, an allowlist is both more restrictive and easier to maintain — adding a new market is an intentional change rather than a gap in the blocklist. Complements CTL.CLOUDFRONT.GEO.001 (geo restriction required but not configured at all) — this control fires when restriction is configured but uses the weaker approach.

**Remediation:** Replace the CloudFront blocklist with an allowlist if the distribution serves a known set of geographic markets. Identify the countries where legitimate users are located, then change the restriction type to whitelist with those countries. This blocks all others including future threat origins automatically. If the distribution must serve global audiences, maintain the blocklist but review and update it regularly as new sanctions and threat sources emerge.

---

### CTL.CLOUDFRONT.ACCESS.LEGACYKEY.001

**CloudFront Signed URLs Use Legacy Root Account Key Pair**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.4; soc2: CC6.1;

CloudFront distribution uses legacy CloudFront key pairs associated with the root account for signed URL or signed cookie verification, rather than trusted key groups with IAM-managed public keys. Legacy key pairs have fundamental limitations: they can only be created, rotated, and deleted by the root account — there is no IAM delegation for key management, no CloudTrail audit of key operations, and no separation of duties between the root account and signing key management. Key rotation requires root account login. Trusted key groups use IAM-managed public keys — created through IAM, audited in CloudTrail, manageable without root access, and supporting multiple keys simultaneously for graceful rotation. This control gates on has_signed_content to avoid firing on distributions that don't use signed URLs or cookies.

**Remediation:** Create an RSA key pair and upload the public key to CloudFront via CreatePublicKey. Create a key group via CreateKeyGroup containing the new public key. Update each cache behavior that uses signed URLs to reference the new key group via UpdateDistribution, replacing TrustedSigners with TrustedKeyGroups. Update application signing code to use the new private key. After traffic shifts to the new key, disable and delete the legacy root account key pair.

---

### CTL.CLOUDFRONT.ACCESS.NOSIGNING.001

**CloudFront Behavior Serving Restricted-Looking Path Has No Signing**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

CloudFront cache behavior path pattern matches a restricted-looking prefix (/premium/*, /member/*, /protected/*, /api/*, /secure/*, /private/*) but does not require signed URLs or signed cookies for access. This control uses a path-pattern heuristic — it does not know from observation data whether the content actually needs access control, only that the path pattern appears to indicate restricted content. The finding should be treated as "verify whether access control is needed here." If the path genuinely serves public content (a public API, static assets in a /protected/ prefix for historical reasons), this is a false positive. If the path serves content that should be user-specific or subscription-restricted, the absence of signed URL enforcement means anyone with a CloudFront URL for that path can access the content without authentication at the CDN layer.

**Remediation:** If this path serves content that requires user authentication or subscription verification: enable signed URL enforcement on the cache behavior (set TrustedKeyGroups to a key group), update the application to generate signed URLs for all links to this path, and set the URL expiration appropriately for the content type (short-lived for premium streams, longer for download links). If this path serves public content that happened to match the path heuristic, no action is needed — but consider renaming the path prefix to avoid confusing future security reviews.

---

### CTL.CLOUDFRONT.ACCESS.SIGNED.LONG.EXPIRY.001

**CloudFront Signed URL / Cookie Default Expiration Window Is Days or Weeks**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, IA-5, SC-12; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AC-3, IA-5, SC-12; pci_dss_v4.0: 8.2, 8.3; soc2: CC6.1, CC6.7;

CloudFront distribution issues signed URLs or signed cookies whose default expiration window exceeds 24 hours (often days or weeks). The expiration timestamp is encoded into the signed URL itself; once issued, the URL stays valid until expiry regardless of subsequent revocation. A leaked long-lived signed URL grants access for days; the attacker doesn't need to maintain credentials, just retain the URL. Most signed-URL use cases tolerate expiration windows in minutes (single-page download) to hours (a viewing session). Days-or-weeks expiration is appropriate only for content meant to be widely distributable — at which point the signing requirement itself is questionable.

**Remediation:** Reduce the default expiration window in the application code that issues signed URLs to the minimum the use case allows (15 minutes for one-shot downloads, a few hours for streaming sessions). Issue per-request URLs rather than reusing them across viewing sessions. For use cases that genuinely need long-lived access (e.g., podcast episodes, public-asset CDN content), reconsider whether signed URLs are the right primitive — public distribution may suit better, paired with rate limits and WAF.

---

### CTL.CLOUDFRONT.ACCESS.SIGNED.MIXEDACCESS.001

**CloudFront Cache Behavior Allows Both Signed and Unsigned Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, IA-5; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, IA-5; pci_dss_v4.0: 7.1, 8.2; soc2: CC6.1, CC6.6;

CloudFront cache behavior is configured with TrustedKeyGroups or TrustedSigners — meaning signed URLs are nominally required — but the same content is also reachable via another behavior on the same distribution (or a different path pattern) that has no signing requirement. The signing requirement on the protected behavior is bypassable by addressing the same content through the unprotected path. Common cause: catch-all default behavior with no signing while specific path patterns enforce signing — but the catch-all matches the same content; or a static-asset behavior with no signing that serves the same files as a signed-asset behavior.

**Remediation:** Audit every behavior on the distribution: identify which require signing and which don't. Either require signing on all behaviors that can reach the protected content, or split protected content onto a separate origin fronted by a separate distribution where the signing requirement is consistent across behaviors. The default catch-all behavior frequently matches more paths than the operator realizes — explicit per-path signing requirements should pair with a default behavior that also requires signing or returns 403.

---

### CTL.CLOUDFRONT.ALARM.4XX.001

**No CloudWatch Alarm for CloudFront 4xx Error Rate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.2;

No CloudWatch alarm monitors the CloudFront 4xxErrorRate metric. 4xx errors have multiple operational and security interpretations: 403 Forbidden — OAC misconfiguration, expired signed URL, or geo-restriction blocking a legitimate user; 404 Not Found — content removed, origin path mismatch, or an attacker scanning for paths and files; 400 Bad Request — malformed request, often from vulnerability scanners or malicious clients. A 4xx spike may indicate: OAC configuration drift (403 surge), content migration gap (404 surge), active reconnaissance (high-volume 404 from a single IP), or a legitimate traffic pattern change. Without an alarm, these patterns are invisible. 4xxErrorRate is one of CloudFront's default metrics — no additional subscription required.

**Remediation:** Create a CloudWatch alarm on the 4xxErrorRate metric in us-east-1. Use a higher threshold than 5xx (e.g., 10-20%) because legitimate 4xx errors are more common (bots, crawlers, typos). Set evaluation to 3 periods of 5 minutes to avoid transient spikes triggering alerts. Monitor for sustained elevated 4xx rates rather than brief spikes.

---

### CTL.CLOUDFRONT.ALARM.5XX.001

**No CloudWatch Alarm for CloudFront 5xx Error Rate**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.2;

No CloudWatch alarm monitors the CloudFront 5xxErrorRate metric. 5xx errors indicate origin failures: 502 (Bad Gateway — origin returned an invalid response or is unreachable), 503 (Service Unavailable — origin overloaded), 504 (Gateway Timeout — origin too slow to respond). For ghost origins (deleted S3 bucket, deleted ALB), every cache miss returns 502 — the 5xx rate climbs from 0% toward 100% as the cache empties. Without an alarm, this failure is invisible: the application is breaking for viewers while no notification is sent. 5xxErrorRate is one of CloudFront's default metrics — it requires no additional metrics subscription. An alarm threshold of 5% provides lead time before complete service failure; 1% catches issues earlier.

**Remediation:** Create a CloudWatch alarm on the 5xxErrorRate metric for the distribution. Note: CloudFront metrics are published to the us-east-1 region — the alarm must be created in us-east-1. aws cloudwatch put-metric-alarm --alarm-name "CF-5xx-DIST_ID" --namespace "AWS/CloudFront" --metric-name "5xxErrorRate" --dimensions Name=DistributionId,Value=DIST_ID Name=Region,Value=Global --threshold 5 --comparison-operator GreaterThanThreshold --evaluation-periods 2 --period 300 --statistic Average --alarm-actions SNS_ARN.

---

### CTL.CLOUDFRONT.ALARM.BYTESDOWNLOAD.001

**No CloudWatch Alarm on CloudFront BytesDownloaded**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.25, A.8.16; nist_800_53_r5: AU-6, AU-13, SI-4; pci_dss_v4.0: 10.4; soc2: CC7.2, CC7.3;

CloudFront publishes BytesDownloaded to CloudWatch — total bytes served to viewers — but no alarm watches it for spikes. Volume excursions on bytes-downloaded signal legitimate viral traffic, scraping campaigns, or data-exfiltration through compromised credentials. A viewer who has obtained valid signed URLs (or has bypassed signing) can stream large amounts of content without producing error spikes — request-count and 4xx alarms don't fire on successful downloads. BytesDownloaded excursion is the signal that catches large-volume exfiltration patterns the request-count and error-rate alarms miss.

**Remediation:** Create a CloudWatch alarm on AWS/CloudFront namespace, BytesDownloaded metric, dimensioned by DistributionId. Use a deviation-from-baseline threshold (e.g., 5x rolling average over 1 hour) so legitimate traffic growth doesn't trigger but rapid exfiltration does. aws cloudwatch put-metric-alarm with --metric-name BytesDownloaded.

---

### CTL.CLOUDFRONT.ALARM.CACHEHIT.001

**No CloudWatch Alarm for CloudFront Cache Hit Rate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

No CloudWatch alarm monitors the CacheHitRate metric. A dropping cache hit rate may indicate: cache poisoning (an attacker deliberately crafting requests to populate the cache with malicious responses), cache key misconfiguration (too many cache variants causing a cache miss for every request), application changes that broke caching, or a cache invalidation storm. When the hit rate drops, more requests reach the origin — origin load increases, latency rises, and backend costs grow. A security-relevant drop: cache poisoning by response header manipulation can cause cached responses to be delivered to different users than intended. CacheHitRate requires the additional CloudWatch metrics subscription — it is not available by default. This control checks that the alarm exists; CTL.CLOUDFRONT.METRICS.ADDITIONAL.001 checks that the metrics subscription is active.

**Remediation:** First enable additional CloudWatch metrics on the distribution (CTL.CLOUDFRONT.METRICS.ADDITIONAL.001) — CacheHitRate is not available without the metrics subscription. Then create a CloudWatch alarm in us-east-1 on the CacheHitRate metric with a threshold based on your expected cache efficiency (e.g., alarm when CacheHitRate drops below 80% for 3 consecutive 5-minute periods).

---

### CTL.CLOUDFRONT.ALARM.CONFIGCHANGE.001

**No Alarm on CloudFront Distribution / Origin / WAF Configuration Changes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.7; fedramp_moderate: AU-6, AU-12, SI-4; iso_27001_2022: A.5.25, A.8.16; nist_800_53_r5: AU-6, AU-12, SI-4; pci_dss_v4.0: 10.4, 12.10; soc2: CC7.2, CC8.1;

No CloudWatch alarm fires on CloudFront management API events (CreateDistribution, UpdateDistribution, DeleteDistribution, AssociateAlias, CreateOriginAccessControl, changes to the WAF web ACL associated with a distribution). CloudTrail captures the events — the data exists. Without an alarm, configuration drift on production distributions surfaces only when someone audits the trail manually. Distribution changes (origin protocol downgraded, WAF disassociated, signed-URL requirement removed, geo- restriction removed) are high-priority signals that warrant real-time visibility.

**Remediation:** Create a CloudWatch metric filter on the CloudTrail log group matching CloudFront management events: eventSource=cloudfront.amazonaws.com AND eventName=(CreateDistribution|UpdateDistribution| DeleteDistribution|AssociateAlias|UpdateWebACL| DisassociateWebACL|...). aws logs put-metric-filter, then aws cloudwatch put-metric-alarm with --threshold 1 so any event reaches on-call. Deletion and disassociate events warrant a higher-priority pager target than create/update.

---

### CTL.CLOUDFRONT.ALARM.ORIGINLATENCY.001

**No CloudWatch Alarm on CloudFront Origin Latency**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, IR-4, SI-4; iso_27001_2022: A.5.25, A.8.6, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.4; soc2: CC7.2, A1.1, A1.2;

CloudFront publishes the OriginLatency metric to CloudWatch (when additional metrics are enabled — see CTL.CLOUDFRONT.METRICS.ADDITIONAL.001) but no alarm watches it. OriginLatency measures the time CloudFront waits for the origin to respond to a request that misses the edge cache. Origin slowdowns are the leading cause of viewer- visible latency on cached content (cache hits stay fast, cache misses suffer). Without an alarm, origin degradation surfaces as customer complaints rather than early-warning signal. Alarming on a P99 threshold tied to the origin's SLO is the standard pattern.

**Remediation:** Enable additional metrics on the distribution if not already (the existing CTL.CLOUDFRONT.METRICS.ADDITIONAL.001 covers that prerequisite). Create a CloudWatch alarm on AWS/CloudFront namespace, OriginLatency metric, dimensioned by DistributionId, with a P99 threshold matching the origin's SLO. aws cloudwatch put-metric-alarm with --metric-name OriginLatency --extended-statistic p99 --threshold <ms>.

---

### CTL.CLOUDFRONT.ALARM.REQUESTS.001

**No CloudWatch Alarm for CloudFront Request Count**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.2;

No CloudWatch alarm monitors the CloudFront Requests metric. A sudden traffic spike may indicate: DDoS attack at the application layer (L7 DDoS exploiting CloudFront rate limiting gaps), bot traffic at scale (credential stuffing, content scraping, API abuse), hotlinking (another site linking directly to content), or a legitimate traffic event (product launch, viral content). Without a request count alarm, traffic anomalies are invisible until they cause performance degradation or cost spikes. Shield Standard provides volumetric DDoS protection but does not alert on application-layer request anomalies. A request count alarm provides the first signal that traffic has changed. Requests is one of CloudFront's default metrics — no additional subscription required.

**Remediation:** Create a CloudWatch alarm on the Requests metric in us-east-1. Threshold depends on normal traffic baseline — set to 3-5x the typical peak to catch genuine anomalies without excessive alerts. Review CloudFront access logs or existing metric history to determine the baseline before setting the threshold.

---

### CTL.CLOUDFRONT.CACHE.AUTHORIZATION.001

**Cache Behavior Caches Responses to Requests With Authorization Header**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, IA-2, SC-7; hipaa: 164.312(a)(1), 164.312(c)(1); iso_27001_2022: A.5.10, A.5.16, A.8.16; nist_800_53_r5: AC-3, IA-2, SC-7; pci_dss_v4.0: 8.2, 8.3; soc2: CC6.1, CC6.6;

CloudFront cache behavior caches responses to requests that carry an Authorization header without including the Authorization header in the cache key. Authenticated responses get cached and served to any subsequent request for the same URL — regardless of whether that request carries a different Authorization or no Authorization at all. The first authenticated user's response, including any per-user content the backend personalizes, becomes the response for everyone else hitting the same URL. Caching authenticated content is sometimes intentional (per-user content where the cache key includes Authorization), but the default cache policy doesn't include Authorization in the key — operators have to enable it explicitly.

**Remediation:** Either disable caching on authenticated routes (point the cache behavior at the AWS-managed CachingDisabled cache policy) or configure a custom cache policy that includes Authorization in HeadersConfig with HeaderBehavior set to "whitelist" and Authorization in the included headers. For paths that mix authenticated and unauthenticated requests, the safer pattern is two behaviors: one for authenticated, one for not, on distinct path patterns.

---

### CTL.CLOUDFRONT.CACHE.LEGACY.001

**CloudFront Distribution Uses Legacy Cache Settings Instead of Cache Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SC-7; iso_27001_2022: A.5.10, A.8.9; nist_800_53_r5: CM-2, SC-7; soc2: CC6.1, CC8.1;

CloudFront cache behavior is configured with the legacy ForwardedValues / MinTTL / MaxTTL / DefaultTTL block rather than referencing a cache policy via CachePolicyId. The legacy block was the original CloudFront caching configuration; AWS introduced cache policies (and the related origin-request and response-headers policies) in 2020 to provide cleaner separation of concerns and reusable configurations. Behaviors that still use the legacy block carry forward the older limitations: cookie / header / query-string forwarding is bundled with cache-key computation, the configuration can't be reused across behaviors or distributions, and it's harder to express modern patterns like cookie / Authorization in the cache key. New behaviors should use cache policies; existing legacy behaviors should be migrated when convenient.

**Remediation:** Migrate the behavior to use a cache policy: aws cloudfront create-cache-policy with the equivalent parameters as the legacy block, then update-distribution to set CachePolicyId on the behavior. AWS provides several managed cache policies (CachingOptimized, CachingDisabled, CachingOptimizedForUncompressedObjects) that cover most use cases. Custom cache policies allow operators to express cookie / Authorization / header inclusion in the cache key cleanly. After migration, the legacy ForwardedValues block can be removed.

---

### CTL.CLOUDFRONT.CACHE.SETCOOKIE.001

**Cache Behavior Caches Responses Containing Set-Cookie Headers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, IA-2, SC-7; hipaa: 164.312(a)(1), 164.312(c)(1); iso_27001_2022: A.5.10, A.5.16, A.8.16; nist_800_53_r5: AC-3, IA-2, SC-7; pci_dss_v4.0: 8.2, 8.3; soc2: CC6.1, CC6.6;

CloudFront cache behavior is configured with a cache policy whose ResponseHeadersInCacheKey or origin-response handling caches responses that contain Set-Cookie headers without per-user cache key partitioning. Set-Cookie headers carry session tokens, CSRF tokens, and login state — when CloudFront caches one user's Set-Cookie response and serves it to a different user requesting the same path, the second user receives the first user's session. The pattern is the most common form of cross-user cache leakage on authenticated paths. Cache policies should either exclude Set-Cookie from cached responses, partition cache keys by cookie / Authorization, or disable caching entirely on authenticated routes.

**Remediation:** Configure the cache policy to either exclude Set-Cookie from cacheable responses (cache only static, non- personalized content) or partition cache keys by cookie / Authorization header / signed-cookie value so each user sees their own cached response. For authenticated routes, the cleanest pattern is to disable caching entirely (CachePolicyId pointing at the AWS-managed CachingDisabled policy). Audit which paths are authenticated and ensure their cache behaviors have appropriate partitioning or are excluded from caching.

---

### CTL.CLOUDFRONT.CONFIG.CNAME.NODNS.001

**CloudFront Distribution CNAME Has No DNS Record**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3; soc2: CC8.1;

CloudFront distribution has an alternate domain name (CNAME) configured but DNS for that domain does not resolve to this distribution. The CNAME claim is registered on the distribution but no traffic routes through it. This has two interpretations: DNS is intentionally pointed elsewhere (configuration drift — the distribution thinks it owns the domain but traffic goes to a different infrastructure, bypassing all CloudFront controls), or DNS was removed and the CNAME is orphaned on the distribution (the domain is claimed but unused — blocking the CNAME from being used on a different distribution without removing it first). In either case, the CNAME configuration and DNS state are inconsistent — either the DNS should be updated to point to this distribution, or the CNAME should be removed from the distribution.

**Remediation:** Verify the intended state: If traffic should route through CloudFront for this domain, add or update the DNS CNAME record to point to the distribution's *.cloudfront.net domain. If traffic should not route through CloudFront, remove the CNAME from the distribution's alternate domain names list via UpdateDistribution. If the CNAME is a stale reference from a previous configuration, remove it to free the domain claim.

---

### CTL.CLOUDFRONT.CONFIG.NOERRORRESPONSES.001

**CloudFront Distribution Has No Custom Error Responses Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-11, SC-7; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SI-11, SC-7; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

CloudFront distribution has no CustomErrorResponses configured. When the origin returns 4xx / 5xx status codes, CloudFront serves the default CloudFront error pages — generic AWS-branded responses that include CloudFront-specific headers, the request ID, and details about the underlying failure. These pages are fingerprinting-friendly (they identify the service as CloudFront), reveal that something failed at the CloudFront layer, and may surface origin-specific error detail that would otherwise be transformed by the origin's own error pages. Custom error responses let the operator return application-shaped error pages instead, hiding the CloudFront fingerprint.

**Remediation:** Configure custom error responses for the common error codes (403, 404, 5XX): aws cloudfront update-distribution with CustomErrorResponses pointing at application-shaped error pages on the origin (or static pages on a separate bucket). Set ErrorCachingMinTTL appropriately so origin errors don't get cached too long. Common pattern: /errors/403.html, /errors/404.html, /errors/500.html served from S3 with branded styling matching the application.

---

### CTL.CLOUDFRONT.CONFIG.NOHTTP2.001

**CloudFront Distribution Does Not Enable HTTP/2**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.6;

CloudFront distribution is configured for HTTP/1.1 only. HTTP/2 provides multiplexing (multiple requests over a single TCP connection — reduces latency for pages with many resources), header compression (HPACK reduces request/response header overhead), and stream prioritization (browser indicates which resources are more important). HTTP/2 also requires TLS in practice — all major browsers only use HTTP/2 over HTTPS, which provides an incidental security benefit. HTTP/3 (QUIC) provides further improvements. CloudFront supports http1.1, http2, http2and3, and http3 as the supported HTTP versions. There is no operational reason to restrict to HTTP/1.1 for CloudFront distributions — all current viewers support HTTP/2.

**Remediation:** Update the distribution via UpdateDistribution to set HttpVersion to http2 (or http2and3 to also support HTTP/3). This is a non-breaking change — viewers that don't support HTTP/2 fall back to HTTP/1.1 automatically.

---

### CTL.CLOUDFRONT.CONFIG.NOROOTOBJECT.001

**CloudFront Distribution Has No Default Root Object**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-6; soc2: CC6.1;

CloudFront distribution does not have a default root object configured. When a viewer requests the root URL (https://domain/), CloudFront forwards the request for the root path (/) to the origin rather than serving a specific object. For S3 origins with ListBucket permission granted, the response is an XML object listing that exposes every file name, size, and last-modified timestamp in the bucket — full content inventory disclosure. For S3 origins without ListBucket, the response is 403 Access Denied. For custom origins, the request is forwarded to the origin's root handler. Setting the default root object to index.html (or another appropriate object) ensures root URL requests serve the intended content and eliminates the S3 object listing exposure.

**Remediation:** Set the default root object in the CloudFront distribution configuration via UpdateDistribution with DefaultRootObject: "index.html" (or the appropriate root document for the application). For S3 static websites, this is typically index.html. For applications, it should be the root path that serves the entry point.

---

### CTL.CLOUDFRONT.CONFIG.WILDCARD.CNAME.001

**CloudFront Distribution Uses Wildcard CNAME Covering Broader Subdomain Set**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SC-7; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: CM-2, SC-7; soc2: CC6.1, CC8.1;

CloudFront distribution is configured with a wildcard alternate domain name (e.g., *.example.com) on its Aliases list. The wildcard matches every direct subdomain of example.com — including subdomains the operator may not have provisioned yet. Wildcard CNAMEs break the DNS-takeover defense: when an operator later creates a new subdomain pointing at a different service, the wildcard distribution still claims the name; the operator's intended service may end up at a different CNAME or fail to deploy. Worse, an attacker who provisions a CNAME under the wildcard's parent domain can route through the wildcard distribution by manipulating their own DNS, potentially taking advantage of the distribution's certificate, WAF, or signed-URL configuration intended for legitimate subdomains.

**Remediation:** Replace the wildcard alias with explicit per-subdomain aliases: aws cloudfront update-distribution with Aliases listing each specific subdomain rather than the wildcard. Issue / re-issue the viewer certificate with SANs covering the explicit list. For genuinely-needed wildcard scenarios (multi-tenant SaaS where each customer subdomain routes to the same distribution), document the rationale and pair with strict DNS-zone governance ensuring no foreign CNAME can land under the wildcard.

---

### CTL.CLOUDFRONT.CORS.001

**Response Headers Policy Must Not Combine Wildcard Origin With Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 6.4.1; soc2: CC6.1;

CloudFront response headers policies can attach a CorsConfig block whose AccessControlAllowOrigins and AccessControlAllowCredentials values are propagated to every distribution that references the policy. A policy that sets AccessControlAllowOrigins to "*" and AccessControlAllowCredentials to true encodes the intent that any origin may make credentialed requests against every distribution using this policy. Browsers refuse wildcard-plus-credentials, but the configuration signals that the origin allowlist and credentials policy have not been reasoned about together. Because response headers policies are shared across distributions, a single misconfigured policy can propagate the misconfiguration to unrelated workloads. Observation fields mirror the CorsConfig block returned by "aws cloudfront get-response-headers-policy".

**Remediation:** Update the policy so AccessControlAllowCredentials is false or the AccessControlAllowOrigins list does not contain "*". Use "aws cloudfront update-response-headers-policy" with a patched ResponseHeadersPolicyConfig.CorsConfig block. Audit which distributions reference this policy via "aws cloudfront list-distributions" — every referencing distribution inherits the change.

---

### CTL.CLOUDFRONT.FLE.001

**CloudFront Distribution Not Using Field-Level Encryption**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; scs_c02: 11.6; soc2: CC6.1;

A CloudFront distribution serving sensitive form data does not use field-level encryption (FLE). FLE encrypts specific POST body fields at the edge using a public key, so the origin application receives ciphertext for sensitive fields. Without FLE, sensitive data transits from edge to origin in plaintext within the HTTPS tunnel, accessible to any intermediate processing layer.

**Remediation:** Create an FLE profile and configuration, then associate it with the cache behavior that handles sensitive form submissions.

---

### CTL.CLOUDFRONT.GEO.001

**CloudFront Distributions Requiring Geo Restriction Must Configure It**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3;

CloudFront distributions that are required to enforce geographic restrictions must have geo restriction configured. Geo restriction limits content delivery to approved countries and blocks requests from sanctioned or high-risk regions. When geo restriction is required by compliance policy but not configured on the distribution, content is served globally without geographic controls. This creates regulatory exposure for organizations subject to export controls, data sovereignty requirements, or sanctions compliance. CloudFront geo restriction operates at the edge location level and is the primary mechanism for enforcing geographic access boundaries on CDN-delivered content.

**Remediation:** Configure geo restriction on the CloudFront distribution. Use either an allow list to restrict delivery to approved countries or a deny list to block specific regions. Set the restriction type and country codes in the distribution configuration. Verify the geo restriction configuration aligns with the organization's compliance requirements for geographic content delivery boundaries.

---

### CTL.CLOUDFRONT.GHOST.CERT.001

**CloudFront Distribution References Deleted or Expired ACM Certificate**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

CloudFront distribution references an ACM certificate that has been deleted, has expired, or is expiring within 30 days. Clients connecting via the custom domain receive TLS errors — browsers show certificate warnings or refuse the connection entirely. The default *.cloudfront.net domain uses CloudFront's own certificate and continues to work, but any custom domain fails. For expired certificates, the distribution was likely working until the certificate was not renewed. For deleted certificates, someone deleted the certificate while it was still in use — intentional or accidental removal of a dependency.

**Remediation:** Request a new ACM certificate for the distribution's custom domain in us-east-1 (required for CloudFront). Validate DNS ownership, wait for ACM to issue the certificate, then associate it with the distribution via UpdateDistribution. For expiring certificates, ACM auto-renews certificates it manages — check whether the DNS validation record (CNAME) still exists in your DNS configuration. Deleted validation records prevent auto-renewal.

---

### CTL.CLOUDFRONT.GHOST.FUNCTION.001

**CloudFront Distribution References Deleted Lambda@Edge or CloudFront Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC8.1;

CloudFront distribution behavior references a Lambda@Edge function or CloudFront Function that has been deleted. The failure impact depends on the trigger type: viewer-request — function runs before the request reaches the cache or origin; if deleted, every request returns 502 (complete failure); origin-request — function runs on cache misses before the request reaches the origin; cache hits still work but misses fail; viewer-response or origin-response — function runs when assembling the response; requests reach the origin successfully but response processing fails. Lambda@Edge functions run globally at CloudFront edge locations — deletion of the function in us-east-1 (where Lambda@Edge functions must exist) removes the function from all edge locations simultaneously. CloudFront Functions are regional — deletion is immediate.

**Remediation:** Identify the deleted function's purpose from the distribution behavior configuration (event type and ARN). Re-create the function with the same logic and associate it with the behavior. For Lambda@Edge, the function must be in us-east-1, must have the correct execution role with edgelambda.amazonaws.com trust, and must be a published version (not $LATEST). Remove the ghost function association while recreating to prevent errors.

---

### CTL.CLOUDFRONT.GHOST.KEYGROUP.001

**CloudFront Trusted Key Group References Deleted Public Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-13; pci_dss_v4.0: 3.7.5; soc2: CC6.1;

CloudFront trusted key group references a public key that has been deleted. CloudFront uses trusted key groups to validate signed URL and signed cookie signatures — the key group contains public key IDs, and CloudFront verifies that signed URLs or cookies were signed with the corresponding private key. If the public key in the key group is deleted, CloudFront cannot verify signatures. The behavior depends on the distribution's viewer access policy: if signed URLs are required, all access fails (CloudFront rejects signatures it cannot verify); if signed URLs are optional, the signed URL requirement may be bypassed entirely — unsigned requests succeed because signature verification is not enforced when the key is missing.

**Remediation:** Generate a new RSA key pair. Upload the new public key to CloudFront via CreatePublicKey. Add the new public key to the trusted key group via UpdateKeyGroup. Update application signing code to use the new private key. Remove the deleted public key reference from the key group. Audit signed URL access during the gap — if signature verification was bypassed, review CloudFront access logs for requests that should have been rejected.

---

### CTL.CLOUDFRONT.GHOST.LOGBUCKET.001

**CloudFront Standard Logging Destination Bucket Has Been Deleted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-9; pci_dss_v4.0: 10.3.2; soc2: CC7.2;

CloudFront standard logging is configured but the destination S3 bucket has been deleted. Access logs are not delivered. The distribution configuration shows the bucket name — logging appears enabled. No log records are written because the destination doesn't exist. CloudFront silently drops log entries when the destination is unavailable. Without access logs, there is no record of requests served — no IP addresses, no request URIs, no response codes, no cache hit data, no evidence of scanning or exploitation attempts. Same ghost logging pattern as CTL.CLOUDFRONT.GHOST.WAF.001 — apparent security control that silently failed. Complements CTL.CLOUDFRONT.LOGGING.001 (logging not configured) by catching cases where logging was configured but the destination was removed.

**Remediation:** Re-create the logging destination S3 bucket in us-east-1 (or the region the distribution delivers logs to). Apply the bucket ACL granting the CloudFront log delivery service write access (s3:PutObject for awslogsdelivery). Update the distribution logging configuration to reference the new bucket. Review the gap in log coverage since the bucket was deleted.

---

### CTL.CLOUDFRONT.GHOST.ORIGIN.001

**CloudFront Distribution Origin References Deleted or Unreachable Resource**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC8.1;

CloudFront distribution origin references an S3 bucket, ALB, API Gateway, or custom HTTP endpoint that has been deleted or is unreachable. Every request to the distribution fails. For deleted S3 origins this is the highest-severity ghost reference in the catalog: S3 bucket names are globally unique but reclaimable after deletion. An attacker can create a bucket with the same name in their own account — the CloudFront distribution then serves content from the attacker's bucket through a trusted distribution and custom domain. For ALB, API Gateway, or custom origins the failure is visible (502 Bad Gateway) but not a takeover risk. For S3 origins, the failure may look like a permissions error (403) while the bucket name remains available for attacker registration. Complements CTL.S3.DANGLING.ORIGIN.001 (S3-side view) by adding the ALB/custom origin failure modes and the S3 takeover narrative.

**Remediation:** For S3 origins: immediately check if the bucket name has been re-registered by another account. If so, disable the distribution immediately. If the name is unclaimed, re-create the bucket in your account before it is registered by an attacker. Update the distribution to reference the restored bucket and re-apply the bucket policy restricting access to OAC. For ALB/custom origins: restore the backend resource or update the distribution to remove the deleted origin.

---

### CTL.CLOUDFRONT.GHOST.RESPONSEHEADERS.001

**CloudFront Distribution References Deleted Response Headers Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-2, CM-3, SC-7; iso_27001_2022: A.5.10, A.8.9; nist_800_53_r5: CM-2, CM-3, SC-7; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC8.1;

CloudFront cache behavior has a ResponseHeadersPolicyId pointing at a response headers policy that no longer exists. The behavior runs without the policy's headers — no HSTS, no X-Frame-Options, no Permissions-Policy, no custom Server header removal. Deletion of the policy doesn't break the distribution: CloudFront silently serves responses without the policy's headers. Operators see "policy attached" in the distribution config; the actual behavior is "policy ID dangles, no headers applied." Common cause: operator deletes a response headers policy intending to replace it, deletes the old before creating the new, and the distribution is briefly in the dangling state.

**Remediation:** Either recreate the policy with the same headers configuration and update the behavior to point at the new policy ID: aws cloudfront create-response-headers-policy followed by update-distribution with the new ResponseHeadersPolicyId. Or repoint the behavior at an existing policy that delivers equivalent headers. Audit other distributions for the same dangling reference if the deletion was widespread.

---

### CTL.CLOUDFRONT.GHOST.WAF.001

**CloudFront Distribution References Deleted WAF Web ACL**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SC-7; soc2: CC6.6;

CloudFront distribution references a WAF web ACL that has been deleted. The distribution configuration shows a web ACL ARN — it appears protected. The web ACL does not exist. CloudFront does not apply any WAF rules. SQL injection, XSS, bot traffic, rate limiting, IP reputation filtering, and all other WAF rules are inactive while the configuration reports WAF as associated. This creates false confidence: an auditor checking the distribution sees a WAF ACL ARN and concludes WAF protection is active. An automated security scanner reporting on WAF association sees the ARN. Nobody detects the absence of actual filtering because the reference exists — only the referenced resource does not. Complements CTL.CLOUDFRONT.WAF.001 (no WAF configured at all): this control catches the more dangerous case where WAF appears configured but the ACL was silently removed.

**Remediation:** Create a new WAF web ACL in us-east-1 with equivalent rules (AWSManagedRulesCommonRuleSet, rate limiting, IP reputation). Associate it with the distribution via UpdateDistribution to replace the deleted ACL ARN. Investigate why the WAF ACL was deleted — if it was accidental, audit IAM permissions for wafv2:DeleteWebACL. If intentional, determine if the WAF association was supposed to be removed from this distribution.

---

### CTL.CLOUDFRONT.HEADERS.001

**CloudFront Distributions Must Enforce Security Response Headers**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; nist_800_53_r5: SC-8; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

CloudFront distributions must have a response headers policy attached that includes Strict-Transport-Security (HSTS) with max-age >= 31536000, X-Frame-Options set to DENY or SAMEORIGIN, X-Content-Type-Options set to nosniff, and Referrer-Policy set to a restrictive value. Without these headers, browsers do not enforce transport security, framing protection, MIME type enforcement, or referrer leakage prevention. Content-Security-Policy (CSP) is not required — it requires application-specific source definitions outside Stave's scope. This pairs with CTL.CLOUDFRONT.TLS.001: TLS enforces encrypted transport, response headers enforce browser-layer security.

**Remediation:** Create or update a response headers policy with the four required headers: Strict-Transport-Security (max-age=31536000; includeSubDomains), X-Frame-Options (DENY or SAMEORIGIN), X-Content-Type-Options (nosniff), and Referrer-Policy (strict-origin-when-cross-origin or no-referrer). Attach the policy to the distribution via the CloudFront console or UpdateDistribution API.

---

### CTL.CLOUDFRONT.HEADERS.NOCSP.001

**CloudFront Response Headers Policy Missing Content-Security-Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-10; soc2: CC6.6;

CloudFront response headers policy does not include a Content-Security-Policy (CSP) header. CSP is the primary browser- enforced defense against Cross-Site Scripting (XSS) — it restricts which origins the browser can load scripts, stylesheets, images, fonts, and other resources from. Without CSP, an XSS vulnerability allows the attacker to inject and execute arbitrary scripts, load external resources from attacker-controlled origins, and exfiltrate data. CTL.CLOUDFRONT.HEADERS.001 requires HSTS, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy, but explicitly excludes CSP because it requires application-specific source definitions. This control fills that gap — it checks for CSP presence without validating the value, because any CSP (even a permissive initial policy) is better than none and indicates intentional deployment.

**Remediation:** Add a Content-Security-Policy header to the CloudFront response headers policy. Start with a report-only policy to gather violation data before enforcing: Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; report-uri /csp-report. Once you've tuned the policy using violation reports, switch to enforcement mode. Avoid unsafe-inline and unsafe-eval in the script-src directive — these negate most XSS protection.

---

### CTL.CLOUDFRONT.HEADERS.NOFRAMEOPTIONS.001

**CloudFront Distribution Doesn't Send X-Frame-Options or frame-ancestors CSP**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7, SI-10; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SC-7, SI-10; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

CloudFront distribution's response headers policy doesn't include X-Frame-Options (or the modern equivalent frame-ancestors directive in Content-Security-Policy). Without either header, browsers allow the response to be embedded in iframes on any origin. An attacker hosts a page that frames the legitimate site, overlays invisible controls, and tricks users into clicking through to destructive actions (clickjacking). The pattern is one of the older browser-side attacks but remains effective against any site that doesn't explicitly forbid framing.

**Remediation:** Add X-Frame-Options to the response headers policy with FrameOptions: DENY (or SAMEORIGIN if the site legitimately frames its own pages). For modern browser coverage, also add frame-ancestors to a Content- Security-Policy header. aws cloudfront update-response-headers-policy with the new SecurityHeadersConfig.FrameOptions block.

---

### CTL.CLOUDFRONT.HEADERS.NOHSTS.001

**CloudFront Distribution Doesn't Send Strict-Transport-Security Header**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8, SC-23; iso_27001_2022: A.5.10, A.8.20; nist_800_53_r5: SC-8, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

CloudFront distribution serves over HTTPS but its response headers policy doesn't include Strict-Transport-Security (HSTS). Without HSTS, browsers don't know to refuse HTTP on subsequent requests — a first visit over HTTP (typed URL, redirect chain, ad-injected http:// link) reaches the distribution at HTTP, the redirect-to-HTTPS that CTL.CLOUDFRONT.HTTPS.ONLY.001 enforces is itself interceptable. HSTS instructs browsers to upgrade http://hostname to https://hostname for a max-age window (typically 1 year), eliminating the redirect-attack window after the first successful HTTPS visit.

**Remediation:** Attach a response headers policy with Strict-Transport- Security configured: aws cloudfront create-response-headers-policy with StrictTransportSecurity AccessControlMaxAgeSec=31536000 IncludeSubdomains=true Preload=true. Update the distribution's default cache behavior (and any other behaviors) to reference the policy via ResponseHeadersPolicyId. The 1-year max-age is the common default; set Preload=true only if the domain is submitted to the HSTS preload list.

---

### CTL.CLOUDFRONT.HEADERS.NOPERMISSIONSPOLICY.001

**CloudFront Distribution Doesn't Send Permissions-Policy Header**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7, AC-3; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SC-7, AC-3; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

CloudFront distribution's response headers policy doesn't include a Permissions-Policy directive. Permissions-Policy (the successor to Feature-Policy) lets the operator declare which browser features the page is allowed to use: camera, microphone, geolocation, payment, USB, notifications, autoplay, full-screen, and more. Without the header, the browser allows whatever feature the origin or any embedded iframe attempts. An attacker who finds an XSS or includes a compromised third-party resource can request access to camera, microphone, or geolocation; with no Permissions-Policy, the browser prompts the user without operator-side opt-in. The control flags the absence; the safe state is an explicit allowlist of features the page legitimately uses with everything else implicitly denied.

**Remediation:** Add Permissions-Policy to the response headers policy via the policy's CustomHeadersConfig (since SecurityHeadersConfig doesn't include Permissions- Policy directly): set the Header to "Permissions-Policy" and the Value to an allowlist matching the page's legitimate feature use, e.g., "camera=(), microphone=(), geolocation=(), payment=()" to deny all four. Sites that need a feature should list it explicitly with an origin allowlist.

---

### CTL.CLOUDFRONT.HEADERS.NOREFERRER.001

**CloudFront Distribution Doesn't Send Referrer-Policy Header**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7, SI-12; iso_27001_2022: A.5.10, A.8.10; nist_800_53_r5: SC-7, SI-12; pci_dss_v4.0: 8.3; soc2: CC6.1, CC6.7;

CloudFront distribution's response headers policy doesn't include a Referrer-Policy directive. Without one, browsers default to sending the full URL of the previous page in the Referer request header on outbound navigation — including sensitive paths, query strings with auth tokens, and account-identifying URL segments. Third-party services (analytics, ads, embedded widgets, font CDNs) receive the referrer; logs persist it; URL- embedded credentials and one-time tokens leak to parties the operator didn't intend. Setting Referrer-Policy (typical values: no-referrer, strict-origin, strict-origin-when-cross-origin) constrains what gets sent.

**Remediation:** Add Referrer-Policy to the response headers policy: aws cloudfront update-response-headers-policy with SecurityHeadersConfig.ReferrerPolicy. Reasonable values by use case: no-referrer for high-sensitivity sites, strict-origin for APIs and apps that don't need cross-origin context, strict-origin-when-cross-origin as a balanced default that preserves same-origin referrer detail while truncating cross-origin to the origin only.

---

### CTL.CLOUDFRONT.HEADERS.NOXCTO.001

**CloudFront Distribution Doesn't Send X-Content-Type-Options Header**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10, SC-7; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SI-10, SC-7; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

CloudFront distribution's response headers policy doesn't include X-Content-Type-Options: nosniff. Without it, browsers may MIME-sniff response bodies — overriding the Content-Type header and treating a file as a different type than declared. An image upload that contains embedded HTML/JavaScript can be sniffed as text/html and executed; a JSON response with embedded script content can be treated as JavaScript. The nosniff directive forces browsers to honor the declared Content-Type, closing a class of MIME-confusion attacks.

**Remediation:** Add X-Content-Type-Options: nosniff to the response headers policy: aws cloudfront update-response-headers-policy with SecurityHeadersConfig.ContentTypeOptions Override=true. Then update the distribution's cache behaviors to reference the policy.

---

### CTL.CLOUDFRONT.HEADERS.SERVEREXPOSED.001

**CloudFront Responses Expose Server Technology Stack Headers**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

CloudFront response headers policy does not remove the Server or X-Powered-By response headers from origin responses. These headers disclose the backend technology stack: Server: Apache/2.4.58, Server: nginx/1.24.0, X-Powered-By: Express, X-Powered-By: ASP.NET. Technology disclosure aids reconnaissance — an attacker who knows the exact server version and framework can search targeted CVE databases, use version-specific exploit payloads, and skip techniques that don't apply to the detected stack. CloudFront response headers policies can remove arbitrary response headers before delivering the response to the viewer. A Remove header action on Server and X-Powered-By eliminates this disclosure at the CDN layer without requiring any origin changes.

**Remediation:** Add Remove header actions to the CloudFront response headers policy for the Server and X-Powered-By headers. In the CloudFront response headers policy, under "Remove headers," add Server and X-Powered-By. CloudFront will strip these headers from all origin responses before delivering to viewers. This eliminates technology disclosure without modifying the origin.

---

### CTL.CLOUDFRONT.HTTPS.ONLY.001

**CloudFront Distributions Must Enforce HTTPS-Only Viewer Protocol**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: CloudFront.3; mitre_attack: TA0006; nist_800_53_r5: SC-8;

CloudFront distributions that allow HTTP (allow-all viewer protocol policy) serve content over plaintext connections. Session cookies, authentication tokens, and sensitive data transmitted over HTTP are visible to network-level attackers. Both the default cache behavior and all custom cache behaviors must enforce HTTPS. A single HTTP-permitting behavior is sufficient for session hijacking.

**Remediation:** Update viewer protocol policy to redirect-to-https or https-only for all cache behaviors (default and custom) in the distribution configuration.

---

### CTL.CLOUDFRONT.LIFECYCLE.DISABLED.001

**CloudFront Distribution Is Disabled With Alternate Domain Names Claimed**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3; soc2: CC8.1;

CloudFront distribution is in a Disabled state but has alternate domain names (CNAMEs) configured. A disabled distribution serves no traffic — it is not a security risk in the conventional sense. But it retains its CNAME claims: the alternate domain names are registered as belonging to this distribution, blocking those domains from being associated with any other distribution. If the disabled distribution has an expired or deleted certificate, the CNAME claim blocks future use of the domain. If the distribution is being decommissioned, the CNAMEs should be removed before or alongside disabling. If it is temporarily disabled (maintenance, cost management), the state is acceptable but should be documented and time-bounded. This control fires only on disabled distributions with CNAMEs — a disabled distribution without CNAMEs has no impact and is low governance priority.

**Remediation:** If the distribution is permanently decommissioned: remove the alternate domain names via UpdateDistribution before or after disabling. If the distribution is temporarily disabled: document the expected duration and review in the next operational cycle. If the distribution should be deleted: first remove all CNAMEs, then delete the distribution.

---

### CTL.CLOUDFRONT.LIFECYCLE.DORMANT.001

**CloudFront Distribution Has No Request Traffic in 90+ Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC8.1;

CloudFront distribution is enabled but has received no viewer requests in more than 90 days. The distribution retains its full operational configuration: origins (potentially with live data), WAF associations, TLS certificates, S3 OAC grants, IAM policies granting origin access, and Lambda@Edge or CloudFront Functions that execute for every request. Nobody monitors a dormant distribution for anomalous access because it is assumed unused. But the *.cloudfront.net domain is permanently assigned and publicly reachable — anyone who discovers the URL (via web archives, referrer logs, prior shared links, or OSINT) can reach the origin through the distribution. 90-day threshold matches Lambda, IAM, DynamoDB, ECS, and EC2 dormant controls for consistency across the lifecycle category.

**Remediation:** Verify whether the distribution is needed. If it is a permanent part of the infrastructure but currently unused (e.g., a staging environment), document the expected dormancy and set a reminder to review again in 90 days. If the distribution is no longer needed, disable it and schedule deletion after verifying no active dependencies. Disabling prevents any new traffic and removes the distribution from attack surface without losing the configuration.

---

### CTL.CLOUDFRONT.LIFECYCLE.ORPHAN.FUNCTION.001

**CloudFront Function Not Associated With Any Distribution**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-8; iso_27001_2022: A.5.10, A.8.9; nist_800_53_r5: CM-2, CM-8; soc2: CC6.1, CC8.1;

CloudFront Function exists in the account but is not associated with any cache behavior on any distribution. The function is inert — no traffic invokes it. Common cause: experimental function that was rolled back without cleanup; function authored for a distribution that was decommissioned; refactored function where the new version replaced the association but the old function wasn't deleted. Orphan functions clutter the inventory view and accumulate small storage cost; their configuration drifts from current standards if they later get reused.

**Remediation:** Either associate the function with the cache behavior that should use it: aws cloudfront update-distribution with FunctionAssociations on the appropriate behavior. Or delete the orphan function: aws cloudfront delete-function --name <name> --if-match <etag>.

---

### CTL.CLOUDFRONT.LIFECYCLE.ORPHAN.KEYGROUP.001

**CloudFront Trusted Key Group Not Used By Any Distribution**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-8, IA-5; iso_27001_2022: A.5.10, A.5.16, A.8.9; nist_800_53_r5: CM-2, CM-8, IA-5; soc2: CC6.1, CC8.1;

CloudFront key group exists in the account but no distribution cache behavior references it via TrustedKeyGroups. The key group's public keys hold no signing role; the corresponding private keys (held off-AWS by the operator's signing service) sit unused. Common cause: signing migration where a new key group replaced the old one and the old key group wasn't deleted; key rotation where the rotated-out key group remained for rollback safety and was forgotten. Orphan key groups clutter the inventory and represent stale signing material — if the corresponding private keys leak, the attacker can sign URLs that no distribution accepts (low immediate impact) but the orphan represents long-lived cryptographic material that should be retired.

**Remediation:** Audit the key group to confirm no current or pending distribution uses it. Either repoint a current distribution at the key group or delete the key group and its associated public keys: aws cloudfront delete-key-group followed by delete-public-key for each public key. Confirm the corresponding private keys are decommissioned in the operator's signing service.

---

### CTL.CLOUDFRONT.LIFECYCLE.ORPHAN.LAMBDAEDGE.001

**Lambda@Edge Function Not Associated With Any CloudFront Behavior**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-8; iso_27001_2022: A.5.10, A.8.9; nist_800_53_r5: CM-2, CM-8; soc2: CC6.1, CC8.1;

Lambda@Edge function (a Lambda function published in us-east-1 with edge-replication enabled) is not associated with any CloudFront distribution cache behavior. The function exists across edge locations — replicated at publish time — but no traffic triggers it. Common cause: experimental edge function rolled back without cleanup; function used by a decommissioned distribution; refactored function where the LambdaFunctionAssociation was updated to a new ARN and the old function version remained. Orphan Lambda@Edge functions accumulate Lambda invocation cost only when invoked (which is zero), but the function versions persist in every edge location until cleaned up — and Lambda@Edge cleanup has a longer-than-usual delay because edge replicas have to drain before deletion.

**Remediation:** Either associate the function with the behavior that should use it: aws cloudfront update-distribution with LambdaFunctionAssociations on the appropriate behavior referencing the function ARN with version. Or delete the orphan function: aws lambda delete-function -- note that Lambda@Edge functions can't be deleted immediately after disassociation; AWS retains the edge replicas until they drain (typically a few hours to a day). Plan the deletion for the next cleanup cycle.

---

### CTL.CLOUDFRONT.LIFECYCLE.ORPHAN.OAC.001

**CloudFront Origin Access Control Not Referenced by Any Distribution**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3; soc2: CC8.1;

A CloudFront Origin Access Control (OAC) exists but is not referenced by any distribution's S3 origin. The OAC was either created for a distribution that has since been deleted or modified to remove the OAC association, or it was created but never attached to any distribution. An unreferenced OAC has no security impact — it cannot grant or deny access to anything because no distribution uses it. However, it accumulates in the CloudFront configuration as governance clutter: IAM-review tools may flag it as an unattached identity, it appears in CloudFront ListOriginAccessControls output inflating the apparent configuration complexity, and it may mislead operators into thinking a distribution is protected by an OAC that is not actually configured.

**Remediation:** Verify whether the OAC was created for a distribution that is in progress (not yet associated) or is a remnant of a deleted distribution. If it is a remnant, delete it via aws cloudfront delete-origin-access-control --id OAC_ID. If it will be used by a future distribution, document the intent and track the pending association.

---

### CTL.CLOUDFRONT.LIFECYCLE.ORPHAN.POLICY.001

**CloudFront Cache or Response Headers Policy Not Referenced**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3; soc2: CC8.1;

A CloudFront cache policy or response headers policy exists but is not attached to any distribution's cache behavior. The policy was either created for a distribution that was deleted, or was created but never attached. An unreferenced policy has no operational effect — it neither caches content nor adds headers. However, it creates governance ambiguity: security teams reviewing the CloudFront response headers policies may see a policy that appears to be enforcing security headers for a distribution that is actually using a different (potentially weaker) policy. Cache policies accumulate silently in the CloudFront configuration and may represent investment (complex cache key configurations) that should be preserved, or dead weight that should be cleaned up. The finding distinguishes between the two by surfacing the unreferenced state for review.

**Remediation:** Review whether the policy should be attached to an existing distribution or deleted. For response headers policies: if it was intended for a specific distribution, attach it to that distribution's behaviors via UpdateDistribution. For cache policies: verify the policy is not needed before deleting — some policies represent significant configuration work. Delete via aws cloudfront delete-cache-policy or aws cloudfront delete-response-headers-policy.

---

### CTL.CLOUDFRONT.LOG.BUCKET.NOENCRYPT.001

**CloudFront Access Log Bucket Not Encrypted With Customer-Managed Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-9; pci_dss_v4.0: 10.3.2; soc2: CC7.2;

CloudFront access logging is enabled but the destination S3 bucket does not use a customer-managed KMS key for default encryption. Access logs contain viewer IP addresses, full request URIs (including query strings with potential PII), HTTP status codes, referer headers, and user-agents. This is the full request audit trail for the internet edge. Without CMK encryption on the log bucket: there is no key-policy control over which principals can decrypt the logs, no CloudTrail audit of decrypt operations (who read the logs and when), and no ability to revoke log access by disabling or deleting the key. Same pattern as S3 server access log buckets and CloudTrail S3 destinations — the log store should have at least as strong encryption as the resources it audits. This control gates on logging_enabled to avoid false positives on distributions without logging.

**Remediation:** Configure the log destination S3 bucket's default encryption to use SSE-KMS with a customer-managed key. Existing log files must be re-encrypted or archived. Update the bucket default encryption via aws s3api put-bucket-encryption. Ensure the CloudFront log delivery service principal can write to the bucket (requires bucket ACL for awslogsdelivery — verify after changing encryption).

---

### CTL.CLOUDFRONT.LOG.BUCKET.NOLIFECYCLE.001

**CloudFront Access Log Bucket Has No Lifecycle Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-11; pci_dss_v4.0: 10.7; soc2: CC7.2;

CloudFront access logging is enabled but the destination S3 bucket has no lifecycle policy to transition or expire old logs. A busy CloudFront distribution generates log files continuously — hundreds of small files per hour, each containing a few minutes of request data. Without a lifecycle policy, log objects accumulate indefinitely: storage costs grow linearly with traffic over time, viewer IP addresses and request patterns (PII under GDPR and similar regulations) persist beyond any retention requirement, and log analysis tools degrade as the dataset grows. Most compliance frameworks mandate a maximum log retention period as well as a minimum — logs must be deleted after the retention window closes. A lifecycle policy should transition logs to Glacier after 90 days and expire them after the required retention period. This control gates on logging_enabled to avoid false positives.

**Remediation:** Create an S3 lifecycle rule on the log bucket: transition to S3 Standard-IA after 30 days, transition to Glacier after 90 days, and expire objects after your required retention period (commonly 365 days for PCI-DSS, 6+ years for HIPAA). Apply via aws s3api put-bucket-lifecycle-configuration or via the console. Also apply S3 Intelligent-Tiering if log access patterns are unpredictable.

---

### CTL.CLOUDFRONT.LOGGING.001

**CloudFront Distributions Must Have Access Logging Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: CloudFront.5; mitre_attack: TA0005; nist_800_53_r5: AU-12;

CloudFront access logs record every request served by the distribution — viewer IP, request URI, response code, bytes transferred, and cache hit/miss status. Without access logs, there is no record of attempted exploitation, data exfiltration via large response payloads, reconnaissance scanning, or suspicious geographic access patterns. A distribution without logging is a blind spot in the organization's visibility.

**Remediation:** Enable access logging in the distribution configuration, specifying an S3 bucket as destination. The S3 bucket must grant CloudFront write access via bucket ACL or bucket policy.

---

### CTL.CLOUDFRONT.METRICS.ADDITIONAL.001

**CloudFront Distribution Does Not Have Additional CloudWatch Metrics Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-6; soc2: CC7.1;

CloudFront distribution does not have the additional CloudWatch metrics subscription enabled. By default, CloudFront publishes 6 metrics to CloudWatch: Requests, BytesDownloaded, BytesUploaded, 4xxErrorRate, 5xxErrorRate, and TotalErrorRate. The additional metrics subscription provides: CacheHitRate (essential for cache poisoning detection and cache efficiency monitoring), OriginLatency (measures how fast the origin responds — baseline for anomaly detection), and per-status-code error rates (detailed breakdown of which 4xx/5xx codes are occurring). These metrics are essential for operational monitoring and security analysis of the CDN layer. Without CacheHitRate, cache poisoning and cache misconfiguration are undetectable. Without OriginLatency, origin performance degradation that precedes 5xx errors is invisible. The additional subscription has a per-distribution cost.

**Remediation:** Enable the additional metrics subscription via the CloudFront console (Distribution → Monitoring → Enable additional metrics) or via the API: aws cloudfront create-monitoring-subscription --distribution-id DIST_ID --monitoring-subscription RealtimeMetricsSubscriptionConfig={RealtimeMetricsSubscriptionStatus=Enabled}. Note: This has a per-distribution hourly cost. Review your monitoring requirements before enabling for all distributions.

---

### CTL.CLOUDFRONT.MULTIDIST.SAMEORIGIN.001

**Multiple CloudFront Distributions Front the Same Origin With Inconsistent Security**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.1.5; fedramp_moderate: AC-3, CM-2, SC-7; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, CM-2, SC-7; pci_dss_v4.0: 1.2, 6.4.2; soc2: CC6.1, CC8.1;

Multiple CloudFront distributions are configured with the same origin but different security configurations. One distribution has a WAF ACL; another doesn't. One enforces HTTPS-only; another allows HTTP. One requires signed URLs; another doesn't. The origin is reachable through every distribution — whichever has the weakest configuration becomes the de facto front door for attackers who find both. Operators provisioning a second distribution typically don't realize the first distribution's protections are bypassable via the second; the second is often a dev / staging / experimental distribution that was provisioned for testing and never decommissioned.

**Remediation:** Audit every distribution sharing the origin: identify each distribution's WAF, viewer protocol policy, signed- URL requirement, geo-restriction, and response headers policy. Either tighten the loosest distributions to match the strictest, or decommission the redundant distributions and consolidate to one. For dev / staging distributions sharing a production origin, route them to a separate origin or restrict the origin's bucket policy / SG to refuse the dev distribution.

---

### CTL.CLOUDFRONT.ORIGIN.BYPASS.001

**CloudFront Custom Origin Is Accessible Directly — Bypass Possible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

CloudFront custom origin (ALB, API Gateway, EC2) has no mechanism to verify that requests came from CloudFront — no custom origin header and no security group restriction to CloudFront's origin- facing IP ranges. An attacker can bypass CloudFront entirely by connecting directly to the origin's public IP or DNS name. All CloudFront security controls are bypassed: WAF (SQL injection, XSS, rate limiting, IP reputation blocking), geo-restrictions (country-level blocking), signed URL/cookie enforcement, field- level encryption, and custom response headers (HSTS, CSP). Two mechanisms verify CloudFront origin identity: (1) a custom origin header — a secret that CloudFront forwards and the origin validates; (2) security group restriction — ALB SG allows inbound only from CloudFront's managed prefix list (com.amazonaws.global.cloudfront.origin-facing). If either mechanism is in place, direct access is blocked. Complements CTL.WAF.ORIGIN.LOCKDOWN.001 (WAF asset side) — this control fires on the CloudFront distribution side.

**Remediation:** For ALB origins: restrict the ALB security group inbound to the CloudFront managed prefix list (pl-XX for your region) for HTTP/HTTPS. For API Gateway: disable the default endpoint (CTL.APIGATEWAY.ENDPOINT.DEFAULT.001) and require requests to include a custom header via resource policy. For any origin: configure CloudFront to forward a secret custom header (X-Origin-Verify with a random value) and validate it in the origin's access control logic. Rotate the header secret periodically.

---

### CTL.CLOUDFRONT.ORIGIN.FAILOVER.001

**CloudFront Distributions Must Have Origin Failover Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** aws_security_hub: CloudFront.4; mitre_attack: TA0040; nist_800_53_r5: CP-7;

CloudFront origin failover automatically routes requests to a secondary origin when the primary returns specific HTTP error codes (502, 503, 504). Without failover, a primary origin outage causes all requests to fail — a DoS condition on the distribution. A secondary origin (cross-region S3 bucket, secondary ALB, or backup API endpoint) ensures availability during primary origin failures.

**Remediation:** Configure an origin group with primary and secondary origins. Specify failover criteria (HTTP status codes that trigger failover to the secondary origin).

---

### CTL.CLOUDFRONT.ORIGIN.HTTP.001

**CloudFront Custom Origin Uses HTTP — Origin Connection Is Plaintext**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

CloudFront custom origin (ALB, API Gateway, EC2, custom HTTP endpoint) is configured with OriginProtocolPolicy http-only or match-viewer. The viewer connection from browser to CloudFront uses HTTPS — the browser shows a padlock. CloudFront terminates TLS and connects to the origin over HTTP — unencrypted. Request headers (Authorization, Cookie, X-API-Key, session tokens), request bodies (API payloads, form data, user input), and response bodies (user data, API responses, credentials) traverse the network in plaintext between CloudFront and the origin. match-viewer is equally dangerous: HTTP requests from viewers cause plaintext connections to the origin. The false-HTTPS pattern: the user sees encryption that doesn't exist end-to-end. https-only is the only safe origin protocol policy for custom origins. For S3 origins, CTL.S3.CDN.TRANSPORT.001 covers the equivalent check.

**Remediation:** Update the origin OriginProtocolPolicy to https-only via UpdateDistribution. Ensure the origin (ALB, API Gateway, EC2) has a valid TLS certificate installed. For ALBs: use ACM to provision a certificate and configure the HTTPS listener. For API Gateway: ensure the custom domain has a certificate. After updating to https-only, test end-to-end that CloudFront can reach the origin over HTTPS.

---

### CTL.CLOUDFRONT.ORIGIN.NOACCESS.001

**CloudFront S3 Origin Must Have Origin Access Control**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

CloudFront distributions with S3 origins must have Origin Access Control (OAC) or at minimum Origin Access Identity (OAI) configured. Without either, CloudFront accesses the bucket via its public endpoint, requiring the bucket to have a public or permissive policy. This makes CloudFront's authentication, WAF, and geo-restriction bypassable by hitting the S3 endpoint directly.

**Remediation:** Configure Origin Access Control (OAC) on the distribution. Update the S3 bucket policy to grant access only to the CloudFront distribution via the OAC principal. Remove any public access from the bucket policy.

---

### CTL.CLOUDFRONT.ORIGIN.NOCUSTOMHEADER.001

**Custom Origin Has No CloudFront-Verification Custom Header**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, IA-3, SC-7; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, IA-3, SC-7; pci_dss_v4.0: 1.2, 6.4.2; soc2: CC6.1, CC6.6;

CloudFront custom origin (ALB, API Gateway, EC2, custom HTTP endpoint) is configured without a CustomOriginHeaders entry containing a secret token that the origin verifies. The origin can't tell whether a request came through CloudFront or arrived directly from the public internet. An attacker who finds the origin's hostname or IP can bypass CloudFront entirely — bypassing WAF, signed URLs, geo-restriction, security headers, and rate-based rules. CloudFront supports adding origin headers per-distribution whose value is a secret; the origin checks for the secret and refuses requests that don't carry it. Pair with the existing ORIGIN.BYPASS.001 control which catches the origin-publicly-reachable side; this control catches the no-shared-secret-verification side.

**Remediation:** Add a CustomOriginHeader to the CloudFront origin configuration with a name like X-Origin-Verify and a secret-grade value (rotated periodically and stored as a secret on the origin side). Configure the origin to reject any request that doesn't carry the header with the expected value. For ALB origins, implement the check in target-group rules or the application; for API Gateway, use a Lambda authorizer.

---

### CTL.CLOUDFRONT.ORIGIN.OAI.LEGACY.001

**CloudFront S3 Origin Uses Legacy Origin Access Identity**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.1;

CloudFront S3 origin uses the legacy Origin Access Identity (OAI) mechanism instead of the current Origin Access Control (OAC). OAI is a legacy authentication mechanism that pre-dates SigV4 — it uses a special IAM user identity that CloudFront manages internally. OAI has critical limitations: it cannot read S3 objects encrypted with a customer-managed KMS key (CloudFront cannot assume the KMS Decrypt permission through the OAI identity), it does not support S3 Object Lambda access points, it does not support S3 in opt-in regions (GovCloud, China), and AWS has stated it is being deprecated. OAC uses SigV4 for request signing (the same standard AWS authentication used by all services) and supports all S3 features including SSE-KMS. Migration from OAI to OAC is non-disruptive and requires only a configuration change. Complements CTL.S3.CDN.OAC.001 (S3 bucket side) — this control fires on the CloudFront distribution side.

**Remediation:** Create an OAC for the distribution via CreateOriginAccessControl with OriginAccessControlOriginType=s3 and SigningBehavior=always. Update the distribution's S3 origin to reference the OAC. Update the S3 bucket policy to allow Principal: cloudfront.amazonaws.com with Condition: StringEquals aws:SourceArn to the distribution ARN. Remove the old OAI bucket policy statement. The migration is non-disruptive — no TTL or cache invalidation required.

---

### CTL.CLOUDFRONT.ORIGIN.S3.DUALACCESS.001

**S3 Origin Bucket Allows OAC Signed Access AND Direct Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.5; fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, SC-7; pci_dss_v4.0: 1.2, 6.4.2; soc2: CC6.1, CC6.6;

S3 origin bucket policy grants access to the CloudFront Origin Access Control (or legacy OAI) — meaning CloudFront can read the bucket — AND separately allows public access via Principal=* or via a missing PublicAccessBlock. The OAC is still functional but redundant: every object is also reachable directly at the S3 hostname with no CloudFront protections. Common cause: legacy bucket that was public before CloudFront was added; bucket policy that wasn't tightened after OAC was configured; ACL allowing public reads alongside the OAC-friendly bucket policy.

**Remediation:** Remove public access from the S3 bucket: aws s3api put-public-access-block with all four flags set to true, then tighten the bucket policy to allow only the OAC service principal (cloudfront.amazonaws.com) with the AWS:SourceArn condition matching the distribution ARN. Audit any remaining ACLs that grant AllUsers or AuthenticatedUsers read. Pair with the existing CTL.S3.PUBLIC.001 control which catches the public- access side of the issue.

---

### CTL.CLOUDFRONT.ORIGIN.S3.MULTIDIST.001

**S3 Origin Bucket Reachable From Multiple CloudFront Distributions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.5; fedramp_moderate: AC-3, CM-2; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, CM-2; pci_dss_v4.0: 1.2, 6.4.2; soc2: CC6.1, CC8.1;

S3 origin bucket policy grants OAC signed access from multiple CloudFront distributions (the AWS:SourceArn condition lists multiple distribution ARNs, or omits the condition entirely so any CloudFront distribution in any account can sign). The bucket has more than one CloudFront-shaped front door — content fronted by distribution A is also reachable via distribution B, potentially with different WAF / security-headers / signed- URL configurations. Operators provisioning the second distribution typically don't realize the first distribution's access path still works; the edge protections of distribution A become bypassable via distribution B if B has weaker configuration.

**Remediation:** Tighten the bucket policy's AWS:SourceArn condition to list only the specific distribution ARN that should front this bucket. Identify the other distributions using the bucket and either decommission them or split them onto distinct origin buckets so each distribution has a single bucket and each bucket has a single distribution.

---

### CTL.CLOUDFRONT.ORIGIN.S3.WEBSITE.001

**CloudFront S3 Origin Uses Website-Hosting Endpoint, OAC Incompatible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.5; fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, SC-7; pci_dss_v4.0: 1.2, 6.4.2; soc2: CC6.1, CC6.6;

CloudFront distribution has an S3 origin pointing at the bucket's static-website endpoint (bucket-name.s3-website-region.amazonaws.com) rather than the REST API endpoint (bucket-name.s3.region.amazonaws.com). Origin Access Control and Origin Access Identity both require the REST API endpoint — they don't function with website-hosting endpoints. Operators using the website endpoint either accept that the bucket must be public (so CloudFront can reach it) or attempt to combine OAC with the website endpoint and find that signed requests are silently ignored. The CloudFront access pattern collapses to "public S3 bucket fronted by CloudFront" — anyone who knows the bucket's website hostname bypasses CloudFront entirely.

**Remediation:** Repoint the CloudFront origin at the bucket's REST API endpoint (bucket-name.s3.region.amazonaws.com or just bucket-name.s3.amazonaws.com), then enable OAC and apply a bucket policy that grants only the OAC's signed requests. Migrate website-hosting features (index docs, error docs) to CloudFront default-root-object and custom-error-responses configuration. After the migration, disable static website hosting on the bucket and tighten the bucket policy to deny public access.

---

### CTL.CLOUDFRONT.ORIGIN.SHIELD.001

**High-Traffic CloudFront Distributions Should Have Origin Shield Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** mitre_attack: TA0040; nist_800_53_r5: SC-5;

Origin Shield adds an additional caching layer between CloudFront edge locations and the origin, reducing the number of requests that reach the origin server. Without it, high-traffic distributions can overwhelm origins with cache-miss requests — a potential vector for cache-busting DoS attacks where attackers force cache misses by varying request parameters.

**Remediation:** Enable Origin Shield in each origin configuration, selecting the region closest to the origin.

---

### CTL.CLOUDFRONT.ORIGIN.TLS.VERSION.001

**CloudFront Origin Accepts Weak TLS Version**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

CloudFront custom origin SSL protocols include SSLv3, TLSv1, or TLSv1.1. The connection from CloudFront to the origin can negotiate a deprecated, vulnerable TLS version. Even if the viewer-facing TLS enforces TLS 1.2, the CloudFront→origin segment may use TLS 1.0 — the weakest link in the end-to-end chain. The same attacks that affect viewer-facing TLS (BEAST on TLS 1.0, POODLE on SSLv3, lack of AEAD in TLS 1.1) apply to the origin connection. CloudFront requires that the origin present a valid certificate for HTTPS connections — the origin SSL protocols define which TLS versions CloudFront attempts when connecting. Acceptable: TLSv1.2 only, or TLSv1.2 and TLSv1.3. The minimum acceptable origin SSL protocol is TLSv1.2.

**Remediation:** Update the origin SSL protocols configuration in the CloudFront distribution to allow only TLSv1.2 (and optionally TLSv1.3 if the origin supports it). Remove SSLv3, TLSv1, and TLSv1.1 from the allowed protocol list. This requires that the origin's web server or load balancer supports TLS 1.2 — most modern servers do. If the origin cannot support TLS 1.2, upgrade the origin before restricting CloudFront protocols.

---

### CTL.CLOUDFRONT.TLS.001

**CloudFront Distributions Must Enforce TLS 1.2 or Higher**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

CloudFront distributions must use a security policy that enforces TLS 1.2 or higher for all viewer connections. TLS 1.0 and TLS 1.1 have known cryptographic weaknesses (BEAST, POODLE, SWEET32) that are structural properties of the protocol, not implementation bugs. The default CloudFront security policy permits TLS 1.0 for backwards compatibility with older clients. Organizations that accept this default are unknowingly accepting protocol-downgrade attacks. TLS 1.2 enforcement exists for ALB (CTL.ELB.TLS.001), API Gateway (CTL.APIGATEWAY.TLS.001), RDS (CTL.RDS.SSL.001), and OpenSearch (CTL.OPENSEARCH.HTTPS.001) — this control closes the CloudFront gap. PCI-DSS explicitly prohibits TLS 1.0 for cardholder data. NIST SP 800-52r2 requires TLS 1.2 minimum for federal systems. Acceptable policies: TLSv1.2_2021, TLSv1.2_2019, TLSv1.2_2018.

**Remediation:** Update the CloudFront distribution viewer certificate configuration to use TLSv1.2_2021 security policy. This requires a custom SSL certificate (not the default CloudFront certificate). Use ACM to provision a certificate in us-east-1, attach it to the distribution, and select TLSv1.2_2021 as the minimum protocol version. All modern browsers and clients released after 2015 support TLS 1.2.

---

### CTL.CLOUDFRONT.TLS.MINIMUM.001

**CloudFront Distributions Must Enforce TLS 1.2 Minimum Security Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: CloudFront.10; hipaa: 164.312(e)(2)(ii); mitre_attack: TA0006; nist_800_53_r5: SC-8;

CloudFront distributions using TLSv1 or TLSv1.1 security policies accept connections over deprecated TLS versions vulnerable to BEAST, POODLE, and other protocol attacks. The security policy controls the minimum TLS version and cipher suites accepted from viewers. TLSv1.2_2021 or TLSv1.3_2022 are recommended — they exclude all vulnerable cipher suites and protocol versions.

**Remediation:** Update the distribution viewer certificate configuration to use TLSv1.2_2021 or TLSv1.3_2022 as the minimum protocol version. Requires a custom SSL certificate from ACM in us-east-1.

---

### CTL.CLOUDFRONT.VIEWER.CERT.COVERAGE.001

**CloudFront Certificate Does Not Cover All Alternate Domain Names**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-23; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

CloudFront distribution has alternate domain names (CNAMEs) that are not covered by the ACM certificate's Subject Alternative Names (SANs). When a viewer connects via an uncovered CNAME, the TLS handshake presents a certificate for a different domain — the browser shows a certificate mismatch error and the connection is rejected or warned. The distribution partially works: CNAMEs matching the certificate's SANs or wildcard succeed; CNAMEs not covered by the certificate fail. For wildcard certificates (*.example.com), only one level of subdomain is covered — a wildcard on *.example.com does not cover sub.sub.example.com. All CNAMEs configured on the distribution must be explicitly listed in the certificate's SANs or matched by a wildcard in the certificate.

**Remediation:** Either expand the ACM certificate to include the uncovered CNAMEs as additional SANs (request a new certificate with all required names, or add SANs to the existing certificate if not yet issued), or use a wildcard certificate (*.example.com) that covers all required subdomains. Wildcard certificates cover only one level of subdomain — *.example.com does not cover sub.sub.example.com. After updating the certificate, associate it with the CloudFront distribution.

---

### CTL.CLOUDFRONT.VIEWER.CERT.EXPIRY.WARN.001

**CloudFront Viewer Certificate Expires Within 30 Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.5; fedramp_moderate: SC-12, SC-17; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: SC-12, SC-17; owasp_nhi: NHI7; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7, CC8.1;

CloudFront distribution viewer certificate (the certificate presented to browsers / clients connecting to the distribution's CNAMEs) expires within 30 days. ACM-issued certificates auto-renew when their DNS validation records are healthy; imported certificates do not. The 30-day window catches both auto-renewal failures (DNS validation records were deleted, validation broke) and imported-cert renewal oversights. Expired certificates produce hard TLS failures the moment the timestamp passes — every viewer sees a certificate-not-valid error, every cache miss fails, and the operator finds out from customer reports.

**Remediation:** For ACM-managed certificates, verify auto-renewal is healthy: aws acm describe-certificate to inspect RenewalSummary; failed renewal usually indicates a DNS validation record was deleted or moved. For imported certificates, request and import a renewal: aws acm import-certificate with --certificate, --private-key, --certificate-chain, replacing the existing certificate ARN. Verify the new ARN is associated with the distribution's ViewerCertificate after import.

---

### CTL.CLOUDFRONT.VIEWER.CERT.NOTACM.001

**CloudFront Viewer Certificate Imported Manually Instead of ACM-Issued**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12, SC-17; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: SC-12, SC-17, CM-2; pci_dss_v4.0: 4.2; soc2: CC6.7, CC8.1;

CloudFront viewer certificate is imported into ACM (or into IAM, the legacy alternative) rather than issued by ACM. Imported certificates are valid TLS certificates and ACM holds them, but ACM cannot auto-renew them — the operator must request a new certificate from the issuing CA, import the renewed cert, and re-associate it with the distribution before the existing cert expires. ACM-issued certificates renew automatically (provided DNS validation records remain valid) and the operator is notified before expiry. Manually-imported certs are a recurring operational burden; the manual step is precisely where renewals get missed.

**Remediation:** Migrate to an ACM-issued certificate when feasible: aws acm request-certificate with the same SAN list, complete DNS validation, then update the distribution's ViewerCertificate to point at the new ACM-issued ARN. ACM-issued certificates handle renewal silently. For cases where imported certs are required (third-party CA contracts, EV certificates, internal CA chains), document the rationale and implement an external monitor that alerts well before expiry.

---

### CTL.CLOUDFRONT.VIEWER.CERT.WEAKKEY.001

**CloudFront Viewer Certificate Uses Weak Key (RSA-1024 or Smaller)**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12, SC-13; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-13; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

CloudFront viewer certificate's public key is RSA-1024 or smaller. RSA-1024 has been below NIST's recommended minimum since 2014 and is treated as deprecated by browsers and standards bodies. The certificate still works for TLS handshakes but the asymmetric crypto can be broken by determined attackers with sufficient resources; certificates issued today should use RSA-2048 minimum (RSA-3072 / RSA-4096 for higher-trust use cases) or ECDSA P-256 / P-384. Most ACM-issued certificates use RSA-2048 by default; this control catches imported or legacy certs that haven't kept pace.

**Remediation:** Request a replacement certificate with RSA-2048 minimum (or ECDSA P-256): aws acm request-certificate (which issues RSA-2048 by default), complete DNS validation, and update the distribution's ViewerCertificate to point at the new ARN. For imported certificates, request the new key from the issuing CA at RSA-2048 or stronger.

---

### CTL.CLOUDFRONT.VIEWER.DEFAULTCERT.001

**CloudFront Distribution Uses Default CloudFront Certificate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-23; soc2: CC6.1;

CloudFront distribution uses the default *.cloudfront.net wildcard certificate instead of a custom ACM certificate bound to the organization's domain. Without a custom certificate: the distribution cannot serve content on a custom domain with a trusted certificate (all content is at d1234.cloudfront.net); the security policy is limited to TLSv1 (default CloudFront policy, which allows legacy TLS — CTL.CLOUDFRONT.TLS.001 may also fire), and the certificate lifecycle is not in the organization's control. Custom ACM certificates enable: binding to organizational domain names, stronger TLS security policies (TLSv1.2_2021), Certificate Transparency logging, and independent certificate lifecycle management. This is most relevant when the distribution is user-facing with a custom domain — a distribution deliberately using the cloudfront.net domain (internal tools, development environments) may intentionally use the default certificate.

**Remediation:** Request an ACM certificate for the custom domain in us-east-1 (required for CloudFront). Validate via DNS CNAME. Attach the certificate to the distribution and update ViewerCertificate to AcmCertificateArn. Set MinimumProtocolVersion to TLSv1.2_2021 and SSLSupportMethod to sni-only. Add the domain as an Alternate Domain Name (CNAME) in the distribution configuration.

---

### CTL.CLOUDFRONT.WAF.001

**CloudFront Distributions Must Have a WAF Web ACL Associated**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7;

CloudFront distributions must have an AWS WAF Web ACL associated for layer-7 protection against web application attacks. Without WAF, requests reach the origin without inspection for SQL injection, XSS, known exploit signatures, rate limiting, or IP reputation blocking.

**Remediation:** Create a WAF Web ACL in us-east-1 (required for CloudFront) with AWSManagedRulesCommonRuleSet and associate it with the distribution via UpdateDistribution API.

---

### CTL.CLOUDFRONT.WAF.PERBEHAVIOR.MISSING.001

**CloudFront WAF Web ACL Applies to Whole Distribution Without Per-Behavior Variation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, SC-7, SI-4; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, SC-7, SI-4; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

CloudFront distribution has a single WAF web ACL associated at the distribution level — every cache behavior shares the same WAF rule set. CloudFront supports per-behavior WAF associations, allowing operators to apply tighter rule sets to admin paths, login endpoints, or other high-sensitivity behaviors than to public static-asset behaviors. With one ACL for the whole distribution, every behavior runs the same rules — typically tuned for the loosest behavior to avoid false positives. The high-sensitivity behaviors don't get the tighter rate limits, sensitive-data inspection, or stricter managed- rule choices they'd benefit from. Per-behavior WAF configuration is the standard pattern for distributions with mixed-sensitivity behaviors.

**Remediation:** Create per-behavior WAF web ACLs: one tighter ACL for admin / login / payment / API behaviors with stricter rate limits, broader managed rule groups, and inspection of request bodies; a looser ACL for static-asset behaviors. aws cloudfront update-distribution with behavior-specific WebACLId values.

---

### CTL.CLOUDFRONT.WAF.RATELIMIT.001

**CloudFront WAF Has No Rate-Based Rules**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-5; pci_dss_v4.0: 6.4.3; soc2: CC6.6;

CloudFront distribution has a WAF web ACL but the ACL contains no rate-based rules. Rate-based rules limit the number of requests from a single IP within a 5-minute window and automatically block IPs that exceed the threshold. Without rate limiting: application- layer DDoS (HTTP floods targeting specific endpoints) can saturate origin resources without triggering WAF block actions, credential stuffing attacks can attempt thousands of password combinations per minute unimpeded, content scrapers can walk the entire distribution at full network speed, and API abuse has no throttling mechanism at the CDN layer. Rate-based rules are the WAF's primary defense against volumetric application-layer attacks that bypass Shield Standard's L3/L4 protections. This control gates on has_waf to avoid false positives on distributions without WAF (covered by CTL.CLOUDFRONT.WAF.001).

**Remediation:** Add a rate-based rule to the WAF web ACL associated with the distribution. In the WAF console, add a rule of type "Rate-based rule" with a threshold appropriate for your traffic baseline (e.g., 2,000 requests per 5 minutes for consumer apps, lower for internal APIs). Set the action to BLOCK. Consider adding separate rate rules for specific sensitive paths (login, registration, password-reset) with lower thresholds.

---


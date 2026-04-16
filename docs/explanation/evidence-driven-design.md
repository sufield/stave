# Evidence-Driven Design

Why every abstraction in Stave traces to real incident data.

---

## The Model Was Extracted, Not Invented

The Stave abstraction layers — System Invariants, observation contracts, compound chains, posture scoring — were not designed in a whiteboard session. They were extracted from analysis of real-world security incidents: HackerOne disclosures, AWS breach post-mortems, practitioner discussions, and disclosed CVEs.

Every abstraction has a source in real incident data. The model is verifiable — the public record can be examined by anyone who wants to check the claims.

## The Control Catalog Is Evidence-Backed

Each control in the catalog traces to at least one real incident or disclosed vulnerability.

**CTL.EC2.IMDSV2.001** traces to the Capital One breach (2019). A misconfigured WAF allowed SSRF to the EC2 metadata service. IMDSv1 returned IAM role credentials without requiring a session token. The attacker used those credentials to access 106 million customer records. If IMDSv2 had been enforced (requiring a PUT request with a hop limit), the SSRF would not have yielded credentials.

**CTL.EKS.VPC.CNI.NETPOL.TTL.001** traces to a HackerOne report documenting a specific VPC CNI behavior: when a pod with NetworkPolicy completes, its IP address is recycled, but the eBPF firewall rules for the original pod persist. A new pod receiving the recycled IP silently inherits the original pod's network access — bypassing NetworkPolicy enforcement entirely.

**CTL.S3.DANGLING.ORIGIN.001** traces to the RubyGems.org subdomain takeover disclosure. A CloudFront distribution pointed to an S3 bucket that had been deleted. An attacker created a new bucket with the same name in a different region and served malicious content through the legitimate domain.

**CTL.CLOUDTRAIL.STOP.DETECT.001** traces to multiple documented attack patterns where the first action after gaining IAM access is `cloudtrail:StopLogging` — eliminating the audit trail before operating.

**CTL.IAM.TRUST.CONFUSEDDEPUTY.001** traces to the confused deputy attack pattern documented in multiple HackerOne reports against AWS accounts where cross-account roles lacked ExternalId conditions.

## The Compound Chain Model Was Extracted from Breach Data

Analyzing breach post-mortems produced one consistent finding: no significant breach was caused by a single misconfiguration.

**Capital One (2019):** SSRF + IMDSv1 + overprivileged IAM role + no WAF origin lockdown. Four conditions, each individually remediable, composed into a complete attack path from internet to 106M records.

**Snowflake customer breaches (2024):** Credential reuse + no MFA enforcement + no IP allowlisting + broad data access permissions. Customer accounts were compromised through credentials obtained from infostealer malware. No single misconfiguration was the root cause — the attack required all four conditions.

**Toyota supplier portal (2022):** Public GitHub repository containing access keys + overprivileged service account + no key rotation + no CloudTrail alerting. The key was rotated only after a security researcher reported the exposure.

Each of these maps directly to a compound chain in the Stave catalog. The `defense_evasion_then_impact` chain models the CloudTrail-disabled + GuardDuty-disabled + no-backup pattern. The `ec2_exposed_instance_path` chain models the public snapshot + open security group + IMDSv1 pattern.

## The Vocabulary Was the Last Thing to Stabilize

The word "invariant" was not in the initial design. Early iterations used "control", "check", "rule", and "policy." Each was wrong in a specific way:

- "Policy" implies organizational intent with acceptable non-compliance. System Invariants do not tolerate non-compliance.
- "Rule" implies a decision point with exceptions. System Invariants have no exceptions — they either hold or they are violated.
- "Check" implies a periodic activity. System Invariants describe a property that must be continuously true.
- "Control" was closest, but it conflates the invariant (the property) with the mechanism (the YAML file that evaluates it).

"System Invariant" was adopted after enough real problems had been solved that the right name became obvious. The property "PHI data must be private and encrypted" is not a check, a rule, or a policy. It is an invariant — a property that must hold across all observable states.

## The Opposite of Top-Down Design

Most CSPM tools start with a compliance framework (CIS, HIPAA, FedRAMP) and build checks for each requirement. The framework comes first, the detection comes second.

Stave started with real incidents and asked: what configuration properties, if enforced, would have prevented each breach? The controls came from evidence. The compliance mappings came later — as a translation of the evidence-derived invariants into the frameworks that auditors recognize.

This is why the Stave catalog has controls that exist in no compliance framework. CTL.EKS.VPC.CNI.NETPOL.TTL.001 is not required by CIS, HIPAA, or FedRAMP. It exists because a real vulnerability was found in real infrastructure. The evidence demanded the control; the compliance frameworks have not caught up.

This is verifiable. The HackerOne reports are public. The breach post-mortems are public. The mapping from each control to its evidence source is traceable.

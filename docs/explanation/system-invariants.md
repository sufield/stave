# System Invariants

What a System Invariant is and why it is the right abstraction for infrastructure security.

---

## What a System Invariant Is

A System Invariant is a property of deployed infrastructure that must hold across all observable states. It is not a rule that can be waived, a policy that can be documented and ignored, or a check that runs periodically. It is a statement about the system that must be true at every moment the system is observed.

"PHI data must be private and encrypted" is a System Invariant. It must hold in every account, every region, at every point in time, regardless of who configured the resource, when it was deployed, or what exemption process exists. If the invariant does not hold, the system is in a violated state.

This is distinct from code-level invariants in the Dijkstra or Hoare logic sense. A code-level invariant is a property of a program's execution state — a loop invariant, a class invariant, a precondition. A System Invariant is a property of a *deployed system's configuration state*. The asset is not a variable in memory; it is an S3 bucket, an RDS database, a Kubernetes cluster. The evaluation is not a compiler or runtime assertion; it is a predicate evaluated against a JSON observation of infrastructure configuration.

## The Abstraction Level

System Invariants operate at the system level, not the application level. They describe properties of infrastructure configuration — encryption settings, access controls, network exposure, logging configuration — not application logic, business rules, or code behavior.

"S3 buckets must block public access" is a System Invariant. "The login page must rate-limit after 5 failed attempts" is not — that is application behavior, not observable in any infrastructure configuration snapshot.

This distinction is the boundary between what Stave can evaluate and what it cannot. If a property is visible in a configuration snapshot, Stave can enforce a System Invariant over it. If a property exists only in application runtime behavior, it is outside scope.

## The Duality: System Invariant and Attack Path

Every System Invariant has a dual: when the invariant is violated, a specific attack capability is enabled. "EBS volumes must be encrypted at rest" — when this invariant is violated, the capability "unencrypted disk data accessible to any attacker with volume access" is enabled.

This duality is not metaphorical. It is structurally encoded in the chain model. Each compound chain declares which capabilities its member invariant violations enable (postconditions) and which capabilities an attacker must already possess to exploit the violations (preconditions).

When three System Invariants fail simultaneously — public endpoint, no MFA on the IAM role, no CloudTrail logging — the capabilities they enable compose: internet access enables credential theft, which enables undetected data access. The chain is a path through simultaneously violated invariants.

## Why Chains Are Compound Simultaneous Violations

A single violated invariant creates a condition. A combination of violated invariants creates a capability. The distinction is not severity — it is *composability*.

An S3 bucket with public access is a condition. An S3 bucket with public access, containing PHI, with no access logging, and no CloudTrail data events is a *complete exfiltration path*: discoverable, accessible, containing valuable data, with no detection mechanism. Each individual invariant violation is a finding. The combination is a different class of risk — one that cannot be captured by summing individual severities.

This is why chains are separate from controls. A control evaluates one invariant on one asset. A chain evaluates whether a *set of simultaneously violated invariants* compose into an attack path. The chain is not a more complex control — it is a different kind of reasoning about the same data.

## The Positive Framing Consequence

The most counterintuitive property of System Invariants: the *absence* of a violation is positive evidence that the invariant holds.

Most security tools detect the presence of problems. A vulnerability scanner finds CVEs. A penetration test finds exploitable weaknesses. The absence of findings does not mean the system is secure — it means the tool did not find anything this time.

System Invariants invert this. When `stave apply` evaluates 630 controls against a snapshot and produces 0 violations, each passing control is positive evidence that the corresponding invariant holds for every observed asset at that point in time. The evidence is not "we looked and found nothing." It is "we proved, for each asset, that the required property is true."

This is the foundation of evidence-based compliance. An auditor asking "was encryption enabled on this database during Q1?" can receive 90 daily snapshots showing the invariant held on every observation. That is evidence, not assertion.

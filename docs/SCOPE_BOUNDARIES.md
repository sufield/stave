# What Stave Never Does

Stave evaluates AWS configuration snapshots against security controls. Three
architectural properties define what it can reason about — and what it cannot.
**Snapshot-bounded**: Stave evaluates what is captured in a snapshot; resources
not in the snapshot do not exist in Stave's universe. **Configuration-only**:
Stave evaluates how infrastructure is configured (IAM policies, security group
rules, bucket settings), not how it executes, how it was built, or who
understands it. **Offline and static**: Stave reasons about what a
configuration permits, not what is happening at runtime. These properties
enable credential-free evaluation, reproducible analysis, and air-gapped
operation. They also create structural blind spots. This document names them.

---

## Shadow IT (FM-020)

*Infrastructure that exists outside the organization's known inventory.*

A developer provisions resources in a personal AWS account. A team deploys to
a region nobody monitors. A contractor creates an S3 bucket outside the AWS
Organization. These resources are real, may hold production data, and are
completely invisible to any snapshot-based tool — including Stave. The snapshot
is a census of declared infrastructure. Shadow IT is the population that
evades the census. Stave cannot detect the absence of something it was never
told about. **Architectural property: snapshot-bounded.**

If shadow IT is eventually discovered and added to a snapshot, Stave evaluates
it like any other infrastructure. The exclusion is about discovery, not
evaluation.

**What you need alongside Stave.** Account enumeration across your cloud
organization (to find accounts outside the org boundary). Organizational
CloudTrail trails (to detect API calls from unknown accounts). Network-level
asset discovery. A Cloud Access Security Broker for SaaS-mediated shadow
resources.

---

## Ungoverned SaaS (FM-022)

*SaaS applications adopted without organizational oversight.*

An employee stores customer data in a personal file-sharing service. A team
authenticates to an unapproved tool via corporate SSO, creating an OAuth grant
the organization doesn't know about. These applications exist entirely outside
AWS infrastructure and have no representation in a configuration snapshot.
**Architectural property: snapshot-bounded and configuration-only.**

The boundary is precise: when a SaaS application integrates with AWS (e.g., a
cross-account IAM role), Stave evaluates the AWS-side configuration — the
role, the trust policy, the permissions. Stave cannot evaluate the SaaS
application itself, the data flowing through it, or whether its use was
authorized. The SaaS application's existence is not a configuration fact.

**What you need alongside Stave.** SSO/IdP audit logs to detect OAuth grants
to unapproved applications. Data loss prevention tooling to monitor data
movement to external endpoints. Procurement governance processes for SaaS
evaluation and approval.

---

## Cognitive Debt from AI-Generated Code (FM-298)

*The gap between what code does and what the developer can explain, debug,
and defend.*

AI coding assistants generate code faster than the developer's mental model
can absorb. The code passes tests and deploys, but the developer cannot trace
its logic or predict its behavior in novel cases. The debt is not in the code.
It is in the developer. No static analysis of infrastructure configuration
can detect whether the person who wrote the Lambda function understands how it
works. **Architectural property: configuration-only.** Cognitive debt is a
property of the relationship between a human and a codebase — a different
domain with different observation methods.

**What you need alongside Stave.** Code review practices that test
understanding, not just correctness. Architectural documentation that
externalizes the mental model. Semantic tests that encode invariants the
developer verified through manual trace-through. These are human processes,
not tool capabilities.

---

## Multi-Agent Coherence Failure (FM-299)

*Multiple AI agents producing contradictory actions in the same system.*

Agent A provisions a resource; Agent B deletes it. Agent A applies a security
policy; Agent C overrides it with a conflicting one. The failure is in the
interaction between agents' actions at runtime, not in any single
configuration artifact. **Architectural property: offline and static.** Stave
evaluates point-in-time state. Coherence failures are process failures — they
exist in the sequence of actions, the intent behind each action, and the
interaction between concurrent actors.

There is a real overlap: if agent incoherence produces a misconfigured
resource (an IAM policy that denies what it allows, a security group with
contradictory rules), Stave detects the misconfiguration. Stave diagnoses the
symptom without identifying the cause. A misconfiguration is a finding
regardless of whether a human or a fleet of agents created it.

**What you need alongside Stave.** Agent orchestration frameworks with
conflict detection and intent reconciliation. Audit logging that attributes
infrastructure changes to specific agents. Pipeline guardrails that serialize
conflicting changes. Runtime monitoring for configuration drift caused by
concurrent agent actions.

---

## Complementary Capability Map

| Gap | Architectural Property | Capability Needed |
|-----|----------------------|-------------------|
| Shadow IT (FM-020) | Snapshot-bounded | Cloud account enumeration, organizational trails, network discovery |
| Ungoverned SaaS (FM-022) | Snapshot-bounded, configuration-only | SSO/IdP audit, data loss prevention, SaaS governance |
| Cognitive debt (FM-298) | Configuration-only | Code review for understanding, architectural documentation, semantic tests |
| Agent incoherence (FM-299) | Offline and static | Agent orchestration, action attribution, conflict detection |

---

These boundaries are why Stave's findings are defensible. A tool that claims
to cover everything covers nothing with certainty. Stave evaluates
configuration snapshots against formal predicates — CEL, Datalog, SMT — and
produces deterministic verdicts. Every finding is reproducible, every absence
is explainable, and the scope of each assertion is unambiguous. Narrow scope
enables depth. Depth is what makes the findings worth trusting.

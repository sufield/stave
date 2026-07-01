# What Stave Does Not Detect

Stave evaluates AWS configuration snapshots against controls. Three
architectural properties define its scope: it is **snapshot-bounded**
(it reasons only about infrastructure represented in the snapshot),
**configuration-only** (it evaluates declared settings, not runtime
behavior or code quality), and **offline** (it operates on artifacts
with no live infrastructure access). These properties enable
credential-free evaluation, reproducible analysis, and the
snapshot-as-artifact model that supports M&A diligence and breach
reconstruction. They also create structural boundaries — failure
modes that Stave cannot detect by design. This document names them.

---

## Shadow IT

Undeclared infrastructure: accounts, resources, or services that exist
outside the organization's governed inventory.

Stave evaluates snapshots of known infrastructure. Shadow IT is
infrastructure that is not known — it has no representation in the
snapshot. Stave cannot detect the absence of something it was never
told to look for. This follows directly from the snapshot-bounded
property: the snapshot is a census of declared infrastructure; shadow
IT is the population that evades the census. No architectural
extension solves this within Stave's model.

If shadow IT is eventually discovered and snapshotted, Stave evaluates
it like any other infrastructure. The boundary is about discovery, not
evaluation.

**What you need alongside Stave.** Active discovery capabilities: AWS
Organizations account enumeration, organizational CloudTrail trails,
network-level scanning, cloud access security brokers for SaaS shadow
IT, and asset inventory reconciliation systems.

---

## Ungoverned SaaS

SaaS applications used by employees without organizational oversight
or security evaluation.

SaaS applications exist entirely outside AWS infrastructure. They
have no representation in a configuration snapshot. When a SaaS
application integrates with AWS (e.g., via a cross-account IAM role),
Stave can evaluate the AWS-side configuration — the role, the trust
policy, the permissions. Stave cannot evaluate the SaaS application
itself, the data flowing through it, or whether its use was
authorized. The boundary is precise: AWS configuration is in scope;
the SaaS application's existence and governance status are not.

**What you need alongside Stave.** Cloud access security brokers, SSO
and identity provider audit logs (to detect OAuth grants to unapproved
applications), data loss prevention tools for monitoring data movement
to external endpoints, and procurement processes for SaaS evaluation.

---

## Cognitive Debt from AI-Generated Infrastructure

The gap between what a system's configuration does and what the
operator can explain, debug, and defend.

Stave evaluates infrastructure configuration, not the operator's
comprehension of it. Cognitive debt is a property of the relationship
between a human and a system — it exists in the operator's mental
model, not in any JSON snapshot. This is a categorical boundary: Stave
operates on configuration artifacts (what is deployed and how it is
configured); cognitive debt operates on cognitive artifacts (what the
operator understands about what is deployed). Even code-level static
analysis tools can only approximate this through proxy metrics. None
can measure whether the operator owns the mental model.

**What you need alongside Stave.** Structured cognitive debt practices
(compress, compile, consolidate). Code and infrastructure review
processes that test understanding, not just correctness. Architectural
documentation that externalizes the mental model. Semantic tests that
encode invariants the operator verified through manual trace-through.

---

## Multi-Agent Coherence Failure

Contradictory, redundant, or incoherent actions produced by multiple
AI agents operating within the same system.

Stave evaluates the result of infrastructure changes, not the process
that produced them. Multi-agent coherence failures are process failures
— detecting them requires observing the sequence of actions, the
intent behind each action, and the interaction between concurrent
actors. These are runtime properties, not configuration properties.

There is a real overlap: if agent incoherence produces a misconfigured
resource (a security group with contradictory rules, an IAM policy
that denies what it simultaneously allows), Stave detects the
misconfiguration. It cannot detect the cause. This is the correct
scope boundary — a configuration auditor diagnoses the misconfiguration
regardless of its etiology.

**What you need alongside Stave.** Agent orchestration frameworks with
conflict detection, audit logging that attributes changes to specific
agents, pipeline guardrails that serialize conflicting changes, and
runtime monitoring that detects configuration drift from concurrent
agent actions.

---

## Complementary Capability Map

| Failure Mode | Architectural Boundary | Capability Needed |
|---|---|---|
| Shadow IT | Snapshot-bounded | Active infrastructure discovery |
| Ungoverned SaaS | Snapshot-bounded | Cloud access security broker, SSO audit |
| Cognitive debt | Configuration-only | Structured review, mental model practices |
| Multi-agent coherence | Offline / static | Agent orchestration, runtime monitoring |

---

These boundaries are the reason Stave's findings are defensible. A
tool that claims to detect everything detects nothing reliably. Stave
evaluates configuration snapshots with formal predicates against a
curated control catalog — and every finding it produces is
reproducible, auditable, and traceable to a specific invariant
violation at a specific point in time. Narrow scope enables depth.
Depth is what makes the output trustworthy.

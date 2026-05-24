# Stave vs. `turbot/steampipe-mod-aws-compliance`

## TL;DR

Per-resource framework checks would have passed; the breach
happened because of resource composition. Stave's job is the
composition — the chains and cross-resource invariants that
per-resource scanners can't see by construction. Run both.

---

## What the AWS Compliance Mod is

[`turbot/steampipe-mod-aws-compliance`](https://hub.powerpipe.io/mods/turbot/aws_compliance)
is the canonical per-resource framework-coverage tool for AWS.
540+ controls across 16+ frameworks (CIS AWS Benchmark v1.4 /
v3.0 / v4.0, PCI-DSS v3.2.1 / v4.0, HIPAA Security Rule,
NIST 800-53 Rev 5, SOC 2, FedRAMP Moderate, GxP, AWS Foundational
Security Best Practices, and more). Each control is a SQL check
against [Steampipe](https://steampipe.io) tables that wrap live
AWS APIs. The mod is mature, well-maintained, widely adopted, and
the right tool for "am I CIS-compliant?" or "do my IAM users
have MFA?"

Strengths the AWS Compliance Mod is genuinely good at:

- **Framework-cited evidence for auditors.** Every control maps
  to a specific framework citation; benchmarks render
  framework-aligned dashboards that auditors recognize.
- **Per-resource property checks.** "Bucket encryption enabled?
  Yes/no." Fast, deterministic, easy to debug.
- **Live AWS coverage.** Queries hit AWS APIs directly via
  Steampipe; you see your current cloud state, not a snapshot.
- **Ecosystem depth.** Used by thousands of organizations;
  contributor velocity; tight integration with the Powerpipe
  dashboard surface.

If your question is _"am I framework-compliant right now?"_, the
AWS Compliance Mod is the answer.

---

## What Stave is

[Stave](https://github.com/sufield/stave) is a deterministic
cloud-security evaluation engine for compound risk reasoning. It
operates on **snapshot-anchored facts** (`obs.v0.1`) — not live
APIs — and emits **deterministic verdicts** (`out.v0.1`) that
auditors and CI/CD can treat as evidence.

The catalog has two axes:

- **Atomic controls** (~96% of the catalog today) — single-asset
  property checks. Stave doesn't compete with the AWS Compliance
  Mod on this axis; the framework coverage and ecosystem
  maturity are AWS Compliance Mod's territory.
- **Compound controls** (~4% today, growing) — predicates that
  reason across multiple related assets. Cross-resource
  invariants, chain failures, ghost references (dangling
  cross-resource pointers single-resource scanners can't see).
  This is Stave's defensible territory.

Three additional properties that distinguish Stave architecturally:

- **Snapshot-anchored.** Evaluation runs against a frozen
  `obs.v0.1.json` snapshot. Re-running the same snapshot
  produces byte-identical output (`out.v0.1.json`). The verdict
  becomes auditable evidence rather than "the cloud was in this
  state when I asked, last Tuesday."
- **Engine-swappable predicates.** Controls are CEL predicates
  today; the same control surface can export to SMT-LIB (Z3),
  Soufflé Datalog, Clingo ASP, Prolog, or PRISM probabilistic
  model checker. The reasoning engine is replaceable; the
  contract isn't.
- **Compound-risk chain modeling.** Multiple co-failing controls
  compose into a single chain finding with its own severity. A
  chain isn't the sum of individual findings — it's an
  attack-path that the per-resource scanners can't represent.

If your question is _"would the Capital-One-shape of risk get
through my CI?"_, Stave is the answer.

---

## Where they overlap (atomic scope)

For the atomic-control set — "bucket encryption enabled," "user
MFA active," "root account access key present" — both tools
detect the same kinds of misconfigurations. The differences on
this axis are tactical, not strategic:

- AWS Compliance Mod queries live AWS APIs; Stave queries a
  snapshot. Same answer for the same state of the world.
- AWS Compliance Mod renders framework-aligned dashboards
  natively; Stave's framework citations exist (in the
  `compliance:` field on each control) but aren't the surface's
  primary organizing principle.
- AWS Compliance Mod has broader framework coverage today.

**Stave doesn't compete on framework coverage of atomic controls.**
For the atomic set, install AWS Compliance Mod. The current
baseline is honest: 96% of Stave's catalog is atomic
([control-classification-baseline](../control-classification-baseline.md)
once populated; `docs/control-classification-proposal.md` has the
proposal pass numbers). The catalog will grow more compound
controls; it won't try to match the AWS Compliance Mod's
framework breadth.

---

## Where they don't overlap (compound scope and beyond)

Four classes of risk single-resource framework scanners cannot
represent by construction:

1. **Compound risk chains.** A set of controls that, when they
   co-fail, create more risk than the sum of individual
   findings. Example: a public-read S3 bucket + access logging
   disabled isn't the sum of two findings — it's an exfiltration
   path with no audit trail. Stave's chain engine fires when the
   composition's escalation threshold is met; the compound
   finding carries its own severity that may exceed any member.
2. **Ghost references.** Dangling cross-resource pointers — a
   Cognito user pool referencing a deleted Lambda trigger, a
   CloudFront distribution whose S3 origin no longer exists, an
   ECS task naming a removed IAM role. The reference exists in
   one asset's configuration; the absence is in another asset's
   inventory. Per-resource scanners that don't model
   cross-resource invariants miss every one of these. Stave's
   catalog has ~100 ghost-reference controls today across
   APIGateway, CloudFront, Cognito, DynamoDB, ECS, EKS, ELB,
   EventBridge, Secrets Manager, SNS, SQS.
3. **Snapshot-anchored reproducibility.** Re-running the same
   `obs.v0.1` snapshot produces byte-identical output. Two
   weeks later, a different engineer points the same snapshot
   at Stave and gets the same verdict — useful for audit
   timelines, regression bisects, "what did we know at time T"
   questions. Live-API tools can't offer this property because
   the live API has moved on.
4. **Engine-swappable predicates with formal-method export.** CEL
   predicates are the default authoring vocabulary; the same
   semantics export to SMT-LIB for Z3 satisfiability checks,
   Soufflé Datalog for relational analysis, etc. A security
   research team that wants to verify a class of attack paths
   formally has the reasoning engine of their choice; the
   catalog stays the same.

---

## Concrete side-by-side

The two tools authoring the same intent. Both check "do not
allow cross-account role assumption without an external ID."

### AWS Compliance Mod (per-resource SQL check)

A typical IAM check in `turbot/steampipe-mod-aws-compliance`
under the CIS or PCI benchmarks (verify the exact file in
the live repo before quoting verbatim — the shape below is
representative; SQL is illustrative not copy-pasted):

```sql
-- Representative shape of an IAM control in the AWS Compliance Mod.
-- The control fires per IAM role; per-role property check.
select
  role_arn as resource,
  case
    when assume_role_policy_document ->> 'Statement'
         @> '[{"Effect": "Allow", "Condition": {"StringEquals": {"sts:ExternalId": "*"}}}]'
      then 'ok'
    else 'alarm'
  end as status,
  case
    when ... then role_name || ' requires external ID for cross-account assumption.'
    else role_name || ' does not require external ID for cross-account assumption.'
  end as reason
from
  aws_iam_role
where
  -- some predicate identifying cross-account trust
  ...
```

What this gives the operator: a per-role row, status, reason,
in a CIS-cited benchmark dashboard. Reads one role at a time;
the "is this role cross-account?" question is computed in SQL
from the role's own trust policy.

### Stave (compound, cross-asset-aware)

`controls/iam/identity/CTL.IAM.IDENTITY.BLASTRADIUS.002.yaml`
(verbatim, abridged for the relevant sections):

```yaml
dsl_version: ctrl.v1
id: CTL.IAM.IDENTITY.BLASTRADIUS.002
name: Cross-Account Role Must Require External ID
description: >
  IAM roles with cross-account blast radius (can reach resources in
  other AWS accounts) must require an external ID condition on the
  trust policy. Without an external ID, any principal in the trusted
  account can assume the role — including compromised service accounts
  and test tenants. Combined with cross-account reach, this is the
  maximum blast radius configuration.
domain: identity
severity: critical
applicable_asset_types:
  - aws_iam_role
classification: state_assertion
unsafe_predicate:
  all:
    - field: identity.kind
      op: eq
      value: role
    - field: identity.role.blast_radius_scope
      op: in
      value: ["account", "cross_account", "organization"]
    - field: identity.role.cross_account_trust_without_external_id
      op: eq
      value: true
```

The predicate checks three properties on a single role — but
two of those properties (`blast_radius_scope` and
`cross_account_trust_without_external_id`) are pre-computed by
the Stave observation extractor by **reasoning across the
role's trust policy, attached permissions, and the reachable
resources in other accounts**. The extractor walks the IAM
graph; the predicate evaluates the result. The control fires
when the composition produces the unsafe state — not when any
single property is independently wrong.

That composition is what AWS Compliance Mod's per-row SQL
shape can't express. The "is the trust missing an external
ID?" question is per-role and SQL-shaped; the "does the role
have cross-account reach AND does the trust permit assumption
from any principal in the trusted account?" question is
graph-shaped, computed once during observation extraction, and
predicated on at query time.

---

## Decision matrix

| Your question | Use |
|---|---|
| "Am I CIS-compliant right now?" | AWS Compliance Mod |
| "Am I PCI-DSS / HIPAA / SOC 2 / FedRAMP compliant?" | AWS Compliance Mod |
| "Do my IAM users have MFA?" (per-resource property check) | AWS Compliance Mod |
| "Would the Capital One pattern get through my CI?" | Stave |
| "Where are my dangling cross-resource references?" | Stave |
| "Can I prove this verdict was deterministic against this snapshot?" | Stave |
| "Can I export my detection logic to Z3 / Soufflé for formal analysis?" | Stave |
| "I want both auditor reporting and compound-risk detection" | Both, side by side |

---

## Running both together

Both tools render in Powerpipe and consume Steampipe / DuckDB
backends. Install side by side:

```bash
# AWS Compliance Mod — framework benchmarks against live AWS.
powerpipe mod install github.com/turbot/steampipe-mod-aws-compliance

# Stave Powerpipe mod — compound risk + ghost references over snapshots.
powerpipe mod install github.com/zepho/powerpipe-mod-stave

# Stave itself — produces the snapshot the powerpipe-mod-stave consumes.
go install github.com/sufield/stave/cmd/stave@latest
```

A typical operator workflow:

1. **Daily / on-snapshot:** `stave apply --format json > out.stave.json`
   produces the deterministic evaluation. CI fails on new
   compound-risk chains or ghost references via `stave ci gate`.
2. **Pre-audit:** `powerpipe benchmark run cis_v3 --mod
   aws_compliance` renders the framework-cited evidence pack
   auditors expect.
3. **Architecture review:** `powerpipe server` opens both
   dashboards. The AWS Compliance Mod's severity rollup answers
   the framework question; Stave's `stave_posture` dashboard
   answers the composition question.

The two surfaces are intentionally orthogonal — Stave's
Powerpipe mod deliberately does not render severity-count cards
([P2 retroactive cleanup](../../../powerpipe-mod-stave/dashboards/posture.pp)
removed those after the AWS Compliance Mod gap was clear), and
the AWS Compliance Mod does not render compound-risk chains
(by design — its job is per-resource framework coverage).

---

## Footnotes

- This doc is the **single source of truth** for the comparison.
  The Stave landing page, the Powerpipe mod README, the dev.to
  positioning article, and any whitepaper section that
  references the comparison all link here and reuse the
  Capital One wedge phrasing verbatim. Don't paraphrase across
  surfaces.
- Numbers cited (96% atomic, 4% compound, ~100 ghost-reference
  controls) are pinned to the
  [`docs/control-classification-proposal.md`](../control-classification-proposal.md)
  snapshot. The classifier-output is a conservative
  lower-bound; the
  [`docs/coverage/iam-compound.md`](../coverage/iam-compound.md)
  map documents the larger semantic-compound surface (~25
  additional IAM controls that reason cross-asset via
  observation extractors). The "growing" framing references the
  AWS compound authoring plan
  ([`aws-compound-control-authoring-plan.md`](../../../aws-compound-control-authoring-plan.md))
  whose IAM phase targets ~5.4% compound share after I2–I7 and
  ~8.6% after all six service phases.
- This doc reads charitably about the AWS Compliance Mod by
  design. A Turbot security engineer reading it should find the
  characterization fair. If any phrasing slips into competitive
  framing, file a PR to soften — the strategic frame is
  complementarity, not displacement.

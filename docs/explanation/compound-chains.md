# Compound Chains

Why compound risk exists and why chains are separate from controls.

---

## Single Misconfigurations Are Rarely Catastrophic

A public S3 bucket with no data is a policy violation, not a breach. An unencrypted RDS database behind a VPC with no internet route is a compliance gap, not a data exposure. Individual misconfigurations create *conditions* for compromise — they are not compromises themselves.

The catastrophic scenario is the combination: a public S3 bucket *containing PHI* with *no access logging* and *no CloudTrail data event monitoring*. Each individual control fires independently. No single control captures the compound risk that all three conditions together create a complete, undetectable exfiltration path.

Chains capture this compound risk.

## Why Chains Are Separate from Controls

A control is a predicate about a single asset property. It answers: "is this one thing configured correctly?" A chain is a relationship between multiple controls. It answers: "do these failures *together* create a risk greater than the sum of the parts?"

Making chains separate from controls preserves the single-responsibility property of controls. A control author does not need to know which chains reference their control. A chain author does not need to modify controls to create new compound risk definitions.

## Escalation Thresholds

A chain with 3 member controls and an `escalation_threshold: 2` activates when *any 2 of the 3* controls fail simultaneously. This models real attack paths where the attacker needs most — but not necessarily all — of the conditions to be present.

The threshold also prevents chain activation from noise: a single transient failure in one control does not trigger a critical compound finding.

## Capabilities and Attack Path Edges

Chains carry `preconditions` and `postconditions` from a closed capability vocabulary. If chain A's postcondition matches chain B's precondition, there is a directed edge from A to B in the attack path graph.

This is not a graph algorithm — it is a double loop over active chains performing set intersection. The graph structure is data, not computation. External tools (NetworkX, Neo4j) perform path finding, centrality analysis, and visualization.

The capability vocabulary is closed (19 terms) because open vocabularies produce unmaintainable, inconsistent annotations. Every capability string is validated at chain load time.

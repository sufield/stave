# The Observation Contract

What the contract is, what problem it solves, and why it is the integration boundary.

---

## What the Contract Defines

An observation contract specifies exactly what properties an extractor must emit for a given asset type. It is the schema that connects extractors (data producers) to controls (data consumers).

For an EKS cluster, the contract specifies that `properties.logging.all_types_enabled` is a boolean indicating whether all five control plane log types are enabled. A control can reference this path in a predicate. An extractor must emit this path in its output.

## The Problem It Solves

Without a contract, the relationship between extractors and controls is implicit. A control author writes a predicate referencing `properties.encryption.enabled`. An extractor author emits `properties.encrypted`. The control silently produces INCONCLUSIVE because the field name does not match — and no one knows why.

The contract makes the relationship explicit. Both the control author and the extractor author reference the same document. If the contract says the path is `properties.encryption.at_rest_enabled`, both sides agree.

## Why Vendor-Neutral Paths Matter

Stave evaluates AWS, Kubernetes, vSphere, Cisco IOS, and Active Directory with the same engine. A control predicate does not contain `aws ec2 describe-instances` — it references `properties.compute.kind == "instance"`. The vendor-neutral path allows the same control to evaluate assets from different vendors that share the same conceptual property.

This is not abstraction for abstraction's sake. It is the mechanism that allows a single control catalog to evaluate multi-cloud and hybrid infrastructure.

## The Contract as Integration Boundary

When a new infrastructure service needs Stave coverage, the integration path is:

1. Define the observation contract (what properties exist)
2. Write the extractor (produce conforming JSON)
3. Write the controls (reference contract properties)

The contract is the boundary. The extractor author needs the contract. The control author needs the contract. Neither needs the other. This allows independent development of extractors and controls.

Contracts are documented per service in `docs/contract/`.

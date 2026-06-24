# Multi-Cloud Architecture — Roadmap

> Status: **design / roadmap**. No Azure or GCP control implementation is
> committed by this document. It records how Stave's architecture already
> abstracts the cloud provider and what an Azure/GCP MVP would require, so the
> work can be scoped deliberately rather than bolted on.

24% of respondents in the Delinea 2026 Identity Security Report cite
*inconsistent controls across providers* as a top risk. Stave's evaluation core
is provider-agnostic; the gap is collectors and provider-specific control
coverage, not the engine.

## 1. How the snapshot contract abstracts the provider

Stave never talks to a cloud API. It evaluates an `obs.v0.1` snapshot: a list
of assets, each with a `type`, a `vendor`, and a normalized `properties` tree
(see `docs/contract/`). The evaluation core (CEL predicates, the Soufflé
reachability layer, the Z3 export) operates purely on those normalized
properties. Nothing in the core knows or cares whether the bytes came from AWS,
Azure, or GCP.

Two consequences:

- **A control is provider-agnostic to the extent its predicate reads normalized
  properties** (`properties.storage.encryption.at_rest_enabled`) rather than
  provider-specific shapes.
- **Adding a provider is, mechanically, adding a collector** that emits the same
  normalized `properties` for that provider's resources — plus controls for the
  provider-specific surfaces that have no AWS analog.

The `vendor` field (`aws`, `azure`, `gcp`) already exists on every asset and is
carried through findings, so multi-provider snapshots can be evaluated in one
run today. Azure and GCP controls already exist in small numbers
(`controls/azure/`, `controls/gcp/`), proving the path.

## 2. AWS-specific vs cloud-agnostic control logic

| Logic shape | Provider-agnostic? | Examples |
|---|---|---|
| Property assertion on a normalized field | **Agnostic** — same predicate works once a collector populates the field | encryption-at-rest, public-exposure, retention floor, classification-tag presence (`CTL.DATACLASS.*`) |
| Identity least-privilege / wildcard detection | **Mostly agnostic** — the *concept* ports; the policy grammar differs (IAM JSON vs Azure RBAC vs GCP IAM bindings), so the collector must normalize "effective permissions" | `CTL.IAM.POLICY.*` ↔ `CTL.AZURE.RBAC.*` ↔ `CTL.GCP.IAM.*` |
| Service-shaped checks keyed to an AWS API surface | **AWS-specific** — needs a provider analog control | CloudTrail data events, KMS key policy, Bedrock agent/KB, MicroVM |
| Compound reachability (Soufflé/Z3) | **Agnostic core, provider-specific facts** — the Datalog rules (`can_assume`, `can_reach`) are generic; the input facts come from the provider's trust/permission model | `CTL.IAM.FOOTHOLD.*` |

Rule of thumb: if a control reads `properties.<domain>.<thing>` and the domain
is a generic capability (storage, encryption, network exposure, classification),
it ports for free once the collector exists. If it reads a property that only
makes sense for an AWS service (`audit_trail.data_events.lambda.enabled`), it
needs an Azure/GCP sibling.

## 3. What an Azure/GCP collector must implement

A collector is an external program (not part of Stave core — see
`memory: extractors`) that produces `obs.v0.1`. For a new provider it must:

1. **Enumerate resources** for the in-scope services and emit one asset per
   resource with `type` (e.g. `azure_storage_account`, `gcp_gcs_bucket`),
   `vendor`, and a stable `id`.
2. **Normalize properties** into the existing namespaces wherever a generic
   analog exists: `storage.*`, `identity.*`, `network.*`, `database.*`,
   `governance.*` (classification/environment), `audit_trail.*`. This is the
   bulk of the work — mapping Azure/GCP shapes onto Stave's normalized tree.
3. **Compute the derived signals** the compound controls expect
   (`identity.reaches_sensitive`, `governance.is_data_bearing`) by running the
   same reachability reasoning over the provider's permission graph.
4. **Emit two snapshots** (two timestamps) where duration-based controls apply.

No engine change is required for steps that reuse existing namespaces.

## 4. AICM controls that benefit from multi-cloud coverage

From the AICM v1.1 mapping (`stave compliance --framework aicm-v1.1`), the
controls whose coverage is currently AWS-shaped and would gain the most from
Azure/GCP siblings:

- **I&S-01 … I&S-09** (Infrastructure Security): network segmentation, security
  groups/NSGs/firewall rules, OS hardening, env isolation — all generic
  concepts with per-provider grammar.
- **IAM-04, IAM-05, IAM-09, IAM-13, IAM-14, IAM-15** applied to **Azure
  Entra/RBAC** and **GCP IAM**: least privilege, privileged-role segregation,
  strong auth, credential management, authorization. The *invariants* are
  identical; only the policy model differs.
- **CEK-03, CEK-08, CEK-12** (encryption at rest / CMK / rotation) for Azure Key
  Vault and GCP KMS — partly covered already.
- **LOG-02, LOG-03, LOG-07, LOG-10** for Azure Monitor / Activity Log and GCP
  Cloud Audit Logs.

These are exactly the domains where "inconsistent controls across providers"
bites: an org enforces least privilege and encryption on AWS but cannot prove
the same invariants hold on Azure/GCP.

## 5. Estimated effort — Azure MVP

| Work item | Estimate |
|---|---|
| Azure snapshot collector (resource enumeration + property normalization for storage, identity/RBAC, network, key vault, monitor) | 3–4 weeks |
| Reachability fact extraction for Azure RBAC (feed the existing Soufflé layer) | 1–2 weeks |
| Top-20 Azure controls (port the agnostic invariants: encryption, public exposure, least privilege, classification, audit logging) | 2 weeks |
| Trap-triplet fixtures + golden tests for the 20 | 1 week |
| Contract docs (`docs/contract/azure.md`) | 2–3 days |

**MVP total: ~7–9 weeks** for a credible "same invariants, three providers"
story covering the highest-value I&S / IAM / CEK / LOG controls. GCP follows the
same shape and is cheaper once the Azure normalization patterns exist.

## Decision

Defer implementation. This document is the roadmap artifact; revisit when
multi-cloud parity is prioritized over deepening AWS + AI-agent coverage.

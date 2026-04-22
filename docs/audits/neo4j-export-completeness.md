# Neo4j GDS Export Completeness Audit

Assessment of Stave's graph export capabilities for Neo4j GDS
integration. Stave exports graph data; Neo4j GDS performs graph
analysis (centrality, effective permissions, path queries).

## Current Export Schema

### Export Commands

| Command | Formats | Purpose |
|---------|---------|---------|
| `stave path` | json, dot, csv-edges | Attack path graph from chain findings |
| `stave enforce graph export` | graph-json, stix, neo4j-cypher | Full assessment graph with Neo4j MERGE statements |

### Node Types (enforce graph export)

| Node Type | Properties | Status |
|-----------|-----------|--------|
| Finding | finding_id, control_id, severity, chain_membership | Exported |
| Resource | resource_arn, resource_class, provider, account_id | Exported |
| Control | control_id, control_name, severity | Exported |
| ComplianceRequirement | framework, requirement_id | Exported |
| ThreatChain | chain_id, narrative, compound_severity, stage_span | Exported |
| AttackerCapability | chain_id, compound_severity, stage_span_attck | Exported |
| RemediationAction | finding_id, action | Exported |
| TenantScope | account_id, provider | Exported |
| Identity | principal_arn | Referenced, populated when IAM data present |

### Edge Types (enforce graph export)

| Edge Type | From → To | Status |
|-----------|-----------|--------|
| TARGETS | Finding → Resource | Exported |
| MEMBER_OF | Finding → ThreatChain | Exported |
| VIOLATES | Finding → ComplianceRequirement | Exported |
| MAPS_TO | Control → ComplianceRequirement | Exported |
| BELONGS_TO_SCOPE | Resource → TenantScope | Exported |
| PRODUCES | ThreatChain → AttackerCapability | Exported |
| HAS_EFFECTIVE_ACCESS | Identity → Resource | Conditional on IAM data |
| CAN_IMPERSONATE | Identity → Identity | Conditional on IAM data |

## Export Gaps for IAM Reasoning

### IAM Entity Graph (not currently exported)

The graph export is **finding-centric and control-centric**. It
exports what Stave detected (findings on assets) and how those
findings relate (chains, compliance). It does NOT export the IAM
entity relationship graph that Neo4j GDS would need for effective
permission reasoning.

| Node Type | Status | Gap Type |
|-----------|--------|----------|
| IAM Users | Not exported as graph nodes | Export gap — data in observations |
| IAM Groups | Not exported | Observation gap — groups analyzed via escalation preconditions only |
| IAM Roles | Not exported as graph nodes | Export gap — data in observations |
| Managed Policies | Not exported | Observation gap — policies analyzed as boolean properties |
| Inline Policies | Not exported | Observation gap — same |
| Instance Profiles | Not exported | Export gap — data in observations |
| KMS Keys | Exported as Resource nodes | Partial — no key-encrypts-resource edges |

| Edge Type | Status | Gap Type |
|-----------|--------|----------|
| User MEMBER_OF Group | Not exported | Observation gap — group membership implicit in escalation |
| Policy ATTACHED_TO Principal | Not exported | Observation gap — attachment is boolean, not relational |
| Role TRUSTED_BY Principal | Not exported | Export gap — trust data in observations |
| Instance Profile HAS_ROLE Role | Not exported | Observation gap — profile analyzed as boolean |
| EC2 HAS_PROFILE InstanceProfile | Not exported | Export gap — profile attachment in observations |
| Policy GRANTS Action on Resource | Not exported | Schema gap — action-level grants not in observation model |
| KMS Key ENCRYPTS Resource | Not exported | Export gap — key ARN on resource, key as asset |
| Lambda USES_ROLE Role | Not exported | Export gap — execution_role data in observations |
| ECS Task USES_ROLE Role | Not exported | Export gap — task_role data in observations |

### Gap Classification

- **Export gap (5):** Data exists in observation snapshots but
  `stave enforce graph export` doesn't emit it as graph nodes/edges.
  Fix: add node/edge types to the graph builder.

- **Observation gap (4):** Data is analyzed as boolean properties
  (has_inline_policies, is_shared) but the underlying relationships
  aren't captured as relational data. The extractor produces
  booleans, not entity relationships.

- **Schema gap (1):** Action-level grant resolution (which actions
  on which resources) is not in the observation model. The extractor
  would need to resolve IAM policy statements into action-resource
  pairs.

## Critical Path Assessment

### Path 1: Effective User Permissions

```
User → MEMBER_OF → Group → ATTACHED → Policy → GRANTS → Resource
```

| Link | Status | Blocker |
|------|--------|---------|
| User node | Observation gap | Users in obs as identity entities, not exported as graph nodes |
| MEMBER_OF edge | Observation gap | Group membership implicit in escalation properties |
| Group node | Observation gap | No standalone group entity |
| ATTACHED edge | Observation gap | Policy attachment is boolean property |
| Policy node | Observation gap | Policies not captured as entities |
| GRANTS edge | Schema gap | Action→Resource grants not in observation model |
| Resource node | **Present** | Resources exported as Resource nodes |

**Verdict: BROKEN.** 6 of 7 links missing. The IAM entity graph is
not in the observation model — it's analyzed by the extractor and
reduced to boolean properties before reaching Stave. Neo4j GDS
cannot reconstruct the entity graph from booleans.

### Path 2: Role Assumption

```
Principal → CAN_ASSUME → Role → ATTACHED → Policy → GRANTS → Resource
```

| Link | Status | Blocker |
|------|--------|---------|
| Principal node | Export gap | Identity entities in observations |
| CAN_ASSUME edge | Export gap | Trust policy data in observations |
| Role node | Export gap | Role entities in observations |
| ATTACHED edge | Observation gap | Boolean property |
| Policy node | Observation gap | Not captured as entity |
| GRANTS edge | Schema gap | Not in observation model |
| Resource node | **Present** | Exported |

**Verdict: BROKEN.** 5 of 7 links missing. First 3 links are
export gaps (fixable); last 3 are observation/schema gaps.

### Path 3: Instance Credential Theft

```
EC2 → HAS_PROFILE → InstanceProfile → HAS_ROLE → Role → Policy → GRANTS → Resource
```

| Link | Status | Blocker |
|------|--------|---------|
| EC2 node | **Present** | Exported as Resource (instance class) |
| HAS_PROFILE edge | Export gap | Profile data in observations |
| InstanceProfile node | Observation gap | Not captured as entity |
| HAS_ROLE edge | Observation gap | Not captured |
| Role node | Export gap | Role entities in observations |
| Policy→GRANTS→Resource | Schema gap | Not in model |

**Verdict: BROKEN.** 4 of 7 links missing.

## Compound Chain Enrichment Assessment

| GDS Analysis | Required Data | Currently Exported | Feasible |
|-------------|---------------|-------------------|----------|
| Betweenness centrality (roles) | Full entity-policy-resource graph | No | Blocked by schema gap |
| Community detection (principals) | Policy attachment edges | No | Blocked by observation gap |
| Shortest path to admin | Full escalation graph | No | Blocked by schema gap |
| Attack chain centrality | Chain→Finding→Resource graph | **Yes** | Works today via MEMBER_OF + TARGETS edges |
| Compliance impact analysis | Finding→Control→Requirement graph | **Yes** | Works today via VIOLATES + MAPS_TO edges |
| Blast radius propagation | Resource→TenantScope + chain graph | **Yes** | Works today |

## Recommendations

### What works today (no changes needed)

1. **Attack chain analysis** — chain-level centrality, shortest
   path between chains, capability reachability
2. **Compliance impact** — which findings violate which frameworks,
   cascading impact analysis
3. **Blast radius** — resource-to-scope propagation, chain compound
   scoring

### Export gaps to close (Stave changes, no extractor changes)

Priority order:

1. **Identity nodes from observation snapshots** — emit IAM users
   and roles as Identity graph nodes when present in observations
2. **Trust edges** — emit CAN_ASSUME edges from trust policy data
   already in observations
3. **Resource-role edges** — emit Lambda USES_ROLE, ECS USES_ROLE,
   EC2 HAS_PROFILE edges from existing observation properties
4. **KMS ENCRYPTS edges** — emit key-to-resource relationships from
   kms_key_id properties on encrypted resources

These are export-only changes — the data exists in observations,
the graph builder just doesn't emit it.

### Observation model limitations (extractor changes needed)

These cannot be fixed in Stave alone:

1. **Group membership as entity relationships** — extractors produce
   `identity.escalation.add_user_to_group.target_group` (escalation
   analysis) but not a relational group membership graph
2. **Policy attachment as entity relationships** — extractors produce
   `identity.policies.has_inline_policies` (boolean) but not policy
   entities with attachment edges
3. **Action-level grant resolution** — extractors produce
   `identity.policies.has_admin_access` (boolean) but not per-action
   grants mapped to resources

### Design boundary

Stave's observation model is property-centric, not graph-centric.
Entities have properties that controls evaluate as boolean
predicates. The IAM entity graph (users → groups → policies →
actions → resources) is resolved by the extractor into per-entity
properties before reaching Stave.

For Neo4j GDS to perform full effective permission reasoning, the
extractor would need to emit the entity relationship graph as
structured observation data — not just boolean summaries. This is
a schema and extractor change, not a Stave catalog or export change.

### Translation layer requirements

For adopters building the Stave → Neo4j pipeline:

1. **Format conversion**: graph-json or neo4j-cypher output is
   directly importable. neo4j-cypher uses MERGE statements
   compatible with Neo4j 4.x+.
2. **Property mapping**: Stave property names map to Neo4j node
   properties. No transformation needed for neo4j-cypher format.
3. **Edge direction**: All edges are directed in Stave's graph
   model. Direction matches Neo4j convention.
4. **Schema creation**: Reference schema at
   `docs/integrations/neo4j/schema.cypher`. Import this before
   loading data.
5. **Incremental updates**: Use MERGE (not CREATE) for idempotent
   re-import. Stave's neo4j-cypher output already uses MERGE.

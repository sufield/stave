# Stave Data Ontology

Graph data model for Neo4j, SPARQL, or OWL integration.

---

## Node Types

### Asset
| Property | Type | Description |
|----------|------|-------------|
| asset_id | string | Unique identifier (ARN or equivalent) |
| asset_type | string | e.g., `s3_bucket`, `ec2_instance`, `eks_cluster` |
| vendor | string | `aws` \| `kubernetes` \| `vmware` \| `cisco` |
| captured_at | datetime | When the observation was taken |

### Control
| Property | Type | Description |
|----------|------|-------------|
| control_id | string | Unique, e.g., `CTL.S3.PUBLIC.001` |
| severity | string | `critical` \| `high` \| `medium` \| `low` |
| attack_stage | string | MITRE tactic Stave name |
| domain | string | e.g., `exposure`, `identity`, `encryption` |

### Finding
| Property | Type | Description |
|----------|------|-------------|
| finding_id | string | Unique per control+asset+time |
| verdict | string | `PASS` \| `VIOLATION` \| `INCONCLUSIVE` |
| dwell_hours | float | Hours the asset has been non-compliant |
| blast_radius | int | Count of downstream reachable assets |
| sla_breached | bool | Whether the SLA deadline is exceeded |
| captured_at | datetime | Assessment timestamp |

### Chain
| Property | Type | Description |
|----------|------|-------------|
| chain_id | string | Unique identifier |
| severity | string | Compound severity when activated |
| status | string | `active` \| `inactive` |

### Capability
| Property | Type | Description |
|----------|------|-------------|
| capability_id | string | From closed vocabulary (19 values) |
| label | string | Human-readable name |

### ComplianceFramework
| Property | Type | Description |
|----------|------|-------------|
| framework_id | string | e.g., `hipaa`, `fedramp_moderate` |
| version | string | Framework version |

### Team
| Property | Type | Description |
|----------|------|-------------|
| team_id | string | Unique identifier |
| name | string | Display name |
| contact | string | Email or Slack channel |

---

## Edge Types

| Edge | From | To | Cardinality | Description |
|------|------|----|-------------|-------------|
| EVALUATES | Control | Asset | 1:N | One control evaluates many assets |
| INSTANCE_OF | Finding | Control | N:1 | A finding is an instance of a control violation |
| ON | Finding | Asset | N:1 | A finding is on a specific asset |
| REQUIRES | Chain | Control | N:M | A chain requires member controls to fail |
| PRECONDITION | Chain | Capability | N:M | Chain requires this capability |
| POSTCONDITION | Chain | Capability | N:M | Chain grants this capability when active |
| ENABLES | Capability | Capability | N:M | Derived: postcondition of chain A matches precondition of chain B |
| SATISFIES | Control | ComplianceFramework | N:M | Control satisfies framework requirements |
| OWNED_BY | Asset | Team | N:1 | Asset attributed to team via manifest |

---

## Example Cypher Queries

```cypher
// All active chains
MATCH (c:Chain {status: "active"}) RETURN c

// Attack path from internet to RDS data access
MATCH path = (entry:Capability {capability_id: "internet_access"})
  -[:ENABLES*1..5]->
  (target:Capability {capability_id: "rds_data_access"})
RETURN path ORDER BY length(path) ASC LIMIT 5

// Findings attributed to a specific team
MATCH (f:Finding)-[:ATTRIBUTED_TO]->(t:Team {team_id: "identity"})
WHERE f.verdict = "VIOLATION"
RETURN f ORDER BY f.blast_radius DESC

// Controls with no findings (never triggered)
MATCH (ctrl:Control)
WHERE NOT (ctrl)<-[:INSTANCE_OF]-(:Finding)
RETURN ctrl.control_id

// Shared controls between two compliance frameworks
MATCH (ctrl:Control)-[:SATISFIES]->(f1:ComplianceFramework {framework_id: "hipaa"}),
      (ctrl)-[:SATISFIES]->(f2:ComplianceFramework {framework_id: "fedramp_moderate"})
RETURN ctrl.control_id, ctrl.severity
```

---

## Import from Stave

```bash
# Assessment graph
stave apply --snapshot snapshot.json --format graph-json \
  | python3 scripts/neo4j-import.py

# Capability graph (attack paths)
stave path --output findings.json --format json \
  | python3 scripts/neo4j-capability-import.py
```

See [integrations/neo4j.md](../integrations/neo4j.md) for complete import scripts.

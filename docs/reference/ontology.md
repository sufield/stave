# Stave Data Ontology

Graph data model exposed via JSON-LD and GraphML for SPARQL,
OWL, igraph, NetworkX, Neo4j GDS (via `n10s`), Gephi, and any
graph data science library.

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

## Example SPARQL Queries

The same questions, expressed against the JSON-LD export
(`stave graph export --format jsonld`). Load the file into any
SPARQL endpoint or RDF library; queries below assume the
`stave:` prefix bound to the ontology IRI in `ontology.ttl`.

```sparql
PREFIX stave: <urn:stave:ontology#>

# All active threat chains
SELECT ?chain WHERE {
  ?chain a stave:ThreatChain ;
         stave:active true .
}

# Findings attributed to a specific team, ordered by blast radius
SELECT ?finding ?blastRadius WHERE {
  ?finding a stave:Finding ;
           stave:attributedTo <urn:stave:team/identity> ;
           stave:verdict "VIOLATION" ;
           stave:blastRadius ?blastRadius .
} ORDER BY DESC(?blastRadius)

# Controls (invariants) with no associated findings
SELECT ?control WHERE {
  ?control a stave:Control .
  FILTER NOT EXISTS { ?finding stave:violatesInvariant ?control . }
}

# Controls satisfying both HIPAA and FedRAMP-moderate
SELECT ?control ?severity WHERE {
  ?control a stave:Control ;
           stave:mapsTo <urn:stave:framework/hipaa> ;
           stave:mapsTo <urn:stave:framework/fedramp_moderate> ;
           stave:severity ?severity .
}
```

---

## Import from Stave

```bash
# doctest:skip — requires assessment JSON from stave apply
# JSON-LD export — universal RDF format
stave graph export --output assessment.json --format jsonld --out graph.jsonld

# GraphML export — for igraph, NetworkX, Gephi, Cytoscape
stave graph export --output assessment.json --format graphml --out graph.graphml
```

See `docs/integrations/graph-libraries.md` for library-specific
load instructions (Neo4j GDS via `n10s`, igraph, NetworkX,
Spark GraphX).

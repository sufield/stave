# Neo4j Integration

Load Stave's standards-based security graph into Neo4j for graph
traversal, attack path analysis, and compliance intelligence queries.

## Prerequisites

```bash
# Neo4j (Docker)
docker run -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/stavepassword \
  neo4j:5

# Python driver
pip install neo4j
```

## Quick Start

```bash
# 1. Apply schema (run once)
cypher-shell -u neo4j -p stavepassword < docs/integrations/neo4j/schema.cypher

# 2. Export graph from assessment and load
stave graph export --output assessment.json \
  | python3 docs/integrations/neo4j/loader.py \
    --neo4j-pass stavepassword

# 3. Open Neo4j Browser at http://localhost:7474
# 4. Run queries from docs/integrations/neo4j/queries.cypher
```

## Loading from Multi-Account Consolidation

```bash
stave consolidate --snapshots ./org-snapshots/ --format json \
  | stave graph export --output /dev/stdin \
  | python3 docs/integrations/neo4j/loader.py --database stave
```

## Incremental Updates

The loader uses `MERGE` — safe to run repeatedly. New findings are
added, existing findings are updated, and the graph grows over time.

```bash
# Run on schedule (e.g. after each stave apply in CI)
stave graph export --output latest.json \
  | python3 docs/integrations/neo4j/loader.py
```

## Dry Run

Preview Cypher statements without connecting to Neo4j:

```bash
stave graph export --output assessment.json \
  | python3 docs/integrations/neo4j/loader.py --dry-run
```

## Loader Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | stdin | Path to graph-json file |
| `--neo4j-uri` | bolt://localhost:7687 | Neo4j Bolt URI |
| `--neo4j-user` | neo4j | Neo4j username |
| `--neo4j-pass` | neo4j | Neo4j password |
| `--database` | stave | Neo4j database name |
| `--clear` | false | Drop all Stave nodes before loading |
| `--dry-run` | false | Print Cypher without executing |
| `--batch-size` | 500 | Nodes/edges per transaction |

## Query Library

`queries.cypher` contains 15 documented Cypher queries organized by
use case:

| Section | Queries | Examples |
|---------|---------|----------|
| Attack Path Analysis | Q1-Q3 | Active chains, shortest path to PHI, cross-account paths |
| Identity Risk | Q4-Q6 | Identity reach ranking, storage access, minimum cut |
| Compliance Intelligence | Q7-Q9 | HIPAA violations, coverage gaps, framework coverage % |
| Risk Prioritization | Q10-Q12 | Chain finding concentration, SLA breaches, risk reduction |
| Graph Diagnostics | Q13-Q15 | Node/edge counts, orphaned nodes, edge distribution |

## Node Labels

Resource nodes carry dual labels for flexible querying:

```cypher
// Generic: all resources
MATCH (r:Resource) RETURN r;

// Specific: only storage resources
MATCH (r:StorageResource) RETURN r;

// Combined: storage resources in a specific account
MATCH (r:StorageResource)-[:BELONGS_TO_SCOPE]->(a:TenantScope)
WHERE a.account_id = '123456789012'
RETURN r;
```

## Air-Gapped Note

The loader connects to Neo4j only. No external API calls. Neo4j
can run locally on the same machine as Stave. No internet required.

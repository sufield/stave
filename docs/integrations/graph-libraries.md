# Loading Stave Graph Exports into Graph-Data-Science Libraries

Stave's `graph export` command produces vendor-neutral graph documents
in two formats. Pick whichever your tool of choice imports natively:

- **JSON-LD** (`--format jsonld`) — universal RDF format with an
  `@context` bound to the Stave ontology (`urn:stave:ontology#`).
  Every RDF-aware library can ingest it; OWL reasoners can apply the
  shipped ontology directly.
- **GraphML** (`--format graphml`) — XML graph exchange format with
  typed `<key>` attribute declarations. Native to igraph, NetworkX,
  Gephi, yEd, and Cytoscape; numeric severity weights and partition
  labels are decoded as numbers, not strings.

Both formats annotate **algorithm-shortcut edges** (`stave:violates`,
`stave:violatesRequirement`, `stave:hasEffectiveAccess`) with
`isAlgorithmShortcut: true`. Centrality, community detection, and
shortest-path workflows can ignore the multi-hop reasoning chain
(Resource → Finding → Control) and run directly over the materialized
shortcut subgraph.

## Neo4j Graph Data Science (GDS)

Neo4j accepts both formats — GraphML via APOC, JSON-LD via the
[neosemantics (n10s)](https://neo4j.com/labs/neosemantics/) plugin.

```bash
stave graph export --output assessment.json --format jsonld --out stave.jsonld
```

```cypher
// One-time: install n10s and bind the Stave ontology so resolved
// short names work in queries.
CALL n10s.graphconfig.init({handleVocabUris: 'SHORTEN'});
CALL n10s.nsprefixes.add('stave', 'urn:stave:ontology#');

// Import the JSON-LD document.
CALL n10s.rdf.import.fetch("file:///path/to/stave.jsonld", "JSON-LD");

// Run PageRank against the materialized shortcut subgraph.
MATCH (r:stave__Resource)-[v:stave__violates]->(c:stave__Control)
WITH gds.graph.project(
  'stave-violations',
  collect(distinct r) + collect(distinct c),
  collect({source: r, target: c, weight: v.severityWeight})
) AS g
CALL gds.pageRank.stream(g.graphName)
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).id AS resource, score
ORDER BY score DESC LIMIT 10;
```

GraphML imports work the same way via APOC:
`CALL apoc.import.graphml('stave.graphml', {readLabels: true})`.

## Python — igraph

igraph imports GraphML directly. Severity weights decode as numeric
attributes so they're usable as edge weights immediately.

```python
import igraph as ig

g = ig.Graph.Read_GraphML('stave.graphml')

# Filter to the algorithm-shortcut subgraph.
shortcut = g.subgraph_edges([
    e.index for e in g.es if e['isAlgorithmShortcut'] is True
])

# Centrality on the shortcut subgraph weighted by severity.
weights = shortcut.es['weight']
print(shortcut.betweenness(weights=weights))

# Community detection partitioned by invariant category.
clusters = shortcut.community_label_propagation(
    initial=shortcut.vs['category'],
    weights=weights,
)
print(clusters.summary())
```

For JSON-LD, igraph has no direct importer; round-trip via rdflib:

```python
import rdflib
from rdflib.extras.external_graph_libs import rdflib_to_networkx_multidigraph
import networkx as nx

g_rdf = rdflib.Graph().parse('stave.jsonld', format='json-ld')
g_nx = rdflib_to_networkx_multidigraph(g_rdf)
# convert nx -> igraph if needed:
g_ig = ig.Graph.from_networkx(g_nx)
```

## Python — NetworkX

GraphML loads natively; JSON-LD loads via rdflib's
`rdflib_to_networkx_multidigraph` helper.

```python
import networkx as nx

g = nx.read_graphml('stave.graphml')

# Severity-weighted shortest path.
path = nx.shortest_path(
    g,
    source='urn:stave:bucket/123456789012/secret-data',
    target='urn:stave:invariant/CTL.S3.PUBLIC.001',
    weight='weight',
)
print(path)

# Community detection on the shortcut subgraph.
shortcut = g.edge_subgraph(
    (u, v) for u, v, d in g.edges(data=True)
    if d.get('isAlgorithmShortcut') == 'true'
)
import networkx.algorithms.community as nxc
communities = nxc.louvain_communities(shortcut.to_undirected())
```

## Apache Spark — GraphX / GraphFrames

Spark accepts CSV exports of the GraphML attribute tables; for direct
GraphML loading use the [graphframes](https://graphframes.github.io/)
JSON-LD reader on top of `spark.read.format("rdf")` from the
`spark-rdf` connector.

```python
from graphframes import GraphFrame

# Read GraphML preprocessed to vertices.csv / edges.csv.
v = spark.read.csv('vertices.csv', header=True, inferSchema=True)
e = spark.read.csv('edges.csv', header=True, inferSchema=True)
g = GraphFrame(v, e)

# Influence propagation: Personalized PageRank seeded at critical
# resources, weighted by severity.
results = g.parallelPersonalizedPageRank(
    resetProbability=0.15,
    sourceIds=['urn:stave:bucket/123456789012/critical-bucket'],
    maxIter=10,
)
```

## Gephi / yEd / Cytoscape (visual exploration)

All three load GraphML directly via File → Import. Stave's GraphML
declares `severity_weight` as `xsd:double` and `category` as
`xsd:string`, so the visual tools render numeric edge widths and
categorical node colors out of the box.

## Verifying the export

The Stave repository ships a deterministic byte-comparison test
(`internal/graph/export_test.go`) and SPARQL ASK assertions
(`docs/graph-experiments.md` Experiment 6). Run

```bash
make test ./internal/graph/...
```

and load the resulting JSON-LD into your library of choice via the
recipes above. If the imports surface fewer triples than the export
contains, check that the consumer is reading `isAlgorithmShortcut` as
a bare key (the JSON-LD `@context` does not type-coerce it; some
strict parsers expand it as a string-typed literal).

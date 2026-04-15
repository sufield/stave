# GraphML Export

Convert Stave's graph-json to GraphML for desktop graph tools.

## Supported Tools

- **Gephi** — open-source graph visualization (https://gephi.org)
- **yEd** — diagram tool with auto-layout
- **Cytoscape desktop** — biological and network analysis
- **NetworkX** — Python graph library (`nx.read_graphml()`)
- **igraph** — R and Python graph library

No server, no database, no credentials required.

## Usage

```bash
# Basic conversion
stave graph export --output assessment.json \
  | python3 docs/integrations/graphml/to-graphml.py > graph.graphml

# Filter to chains and findings only
python3 to-graphml.py --input graph.json \
  --filter-type ThreatChain,Finding,Resource --output chains.graphml

# Active chain subgraph only
python3 to-graphml.py --input graph.json --active-only --output active.graphml
```

## Gephi Step-by-Step

1. Install Gephi from https://gephi.org
2. File > Open > select `graph.graphml`
3. Run Layout > ForceAtlas2 to spread the graph
4. Appearance > Nodes > Color > Partition > `type`
   - Finding = red, Resource = blue, ThreatChain = orange
5. Appearance > Nodes > Size > Ranking > degree
   - Larger nodes = more connections
6. Filter panel > Attributes > `type = ThreatChain` to isolate chains
7. Export > SVG/PDF/PNG for reports

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | stdin | Path to graph-json |
| `--output` | stdout | Path to GraphML output |
| `--filter-type` | all | Comma-separated node types to include |
| `--active-only` | false | Only chain-connected nodes |

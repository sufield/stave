# Cytoscape.js Graph Viewer

Self-contained HTML viewer for Stave's security graph.
No installation, no server, no dependencies. Open in any browser.

## Usage

```bash
# 1. Generate graph-json
stave graph export --output assessment.json > graph.json

# 2. Open viewer.html in browser

# 3. Drop graph.json onto the viewer or use the file picker
```

## Features

- **Drag-and-drop** or file picker for graph-json loading
- **Node coloring** by severity (critical=red, high=amber, medium=blue, low=gray)
- **Node shapes** by type (Finding=rectangle, ThreatChain=diamond, Control=ellipse, etc.)
- **Click** any node to see all properties in the detail panel
- **Click** any edge to see edge type and endpoints
- **Highlight Active Chains** button fades everything except chain-connected nodes
- **Filter** dropdown to show only specific node types
- **Search** box to find nodes by control ID or resource ARN
- **Reset View** to clear all filters and highlights

## Node Shapes

| Type | Shape |
|------|-------|
| Finding | Rectangle |
| Resource | Barrel |
| ThreatChain | Diamond |
| AttackerCapability | Star |
| Control | Ellipse |
| Identity | Triangle |
| ComplianceRequirement | Hexagon |
| TenantScope | Round Rectangle |

## Supersedes

This viewer supersedes the old DOT-based viewer (`docs/graph/cytoscape.html`), which was removed in Iteration 6.

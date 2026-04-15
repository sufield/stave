#!/usr/bin/env python3
"""Stave graph-json to Amazon Neptune (Gremlin) loader.

Two modes:
  Interactive: connects to Neptune via Gremlin WebSocket and loads
               graph-json directly. Requires network access.
  Bulk:        produces Neptune bulk load CSV files (vertices.csv,
               edges.csv) for S3 upload and Neptune Loader API.
               Air-gapped compatible.

Usage:
    # Interactive mode
    stave graph export --output assessment.json | \\
        python3 loader.py --neptune-endpoint wss://cluster.amazonaws.com:8182/gremlin

    # Bulk mode (air-gapped)
    stave graph export --output assessment.json | \\
        python3 loader.py --bulk --out ./neptune-bulk/

    # Dry run
    stave graph export --output assessment.json | \\
        python3 loader.py --dry-run
"""
import argparse
import csv
import json
import os
import sys


# Neptune type suffixes for CSV headers.
TYPE_SUFFIXES = {
    str: "String",
    bool: "Bool",
    int: "Int",
    float: "Double",
}


def load_graph(path):
    if path and path != "-":
        with open(path) as f:
            return json.load(f)
    return json.load(sys.stdin)


def python_type_suffix(value):
    for t, suffix in TYPE_SUFFIXES.items():
        if isinstance(value, t):
            return suffix
    return "String"


def flatten_properties(props):
    """Flatten nested dicts/lists into scalar values for CSV."""
    flat = {}
    for key, value in props.items():
        if isinstance(value, dict):
            for sub_key, sub_val in value.items():
                flat[f"{key}.{sub_key}"] = sub_val
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                flat[key] = json.dumps(value)
            else:
                flat[key] = ";".join(str(v) for v in value)
        else:
            flat[key] = value
    return flat


def write_bulk_csv(graph, out_dir):
    """Produce Neptune bulk load CSV files."""
    os.makedirs(out_dir, exist_ok=True)

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    # Collect all property keys across all nodes for CSV headers.
    all_keys = set()
    for node in nodes:
        flat = flatten_properties(node.get("properties", {}))
        for k, v in flat.items():
            all_keys.add((k, python_type_suffix(v)))

    sorted_keys = sorted(all_keys)

    # Write vertices.csv
    v_path = os.path.join(out_dir, "vertices.csv")
    with open(v_path, "w", newline="") as f:
        header = ["~id", "~label"] + [f"{k}:{s}" for k, s in sorted_keys]
        writer = csv.writer(f)
        writer.writerow(header)

        for node in nodes:
            flat = flatten_properties(node.get("properties", {}))
            row = [node["id"], node["type"]]
            for k, _ in sorted_keys:
                val = flat.get(k, "")
                if isinstance(val, bool):
                    val = str(val).lower()
                row.append(val)
            writer.writerow(row)

    print(f"Wrote {len(nodes)} vertices to {v_path}", file=sys.stderr)

    # Write edges.csv
    e_path = os.path.join(out_dir, "edges.csv")
    with open(e_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["~id", "~from", "~to", "~label"])

        for i, edge in enumerate(edges):
            edge_id = f"e{i}"
            writer.writerow([edge_id, edge["from"], edge["to"], edge["type"]])

    print(f"Wrote {len(edges)} edges to {e_path}", file=sys.stderr)


def run_dry(graph):
    """Print Gremlin traversals without executing."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    print("// --- Vertices ---")
    for node in nodes[:5]:
        flat = flatten_properties(node.get("properties", {}))
        props = ", ".join(f".property('{k}', {repr(v)})" for k, v in sorted(flat.items()))
        print(f"g.addV('{node['type']}').property('id', '{node['id']}'){props}")
    if len(nodes) > 5:
        print(f"// ... ({len(nodes) - 5} more vertices)")

    print("\n// --- Edges ---")
    for edge in edges[:5]:
        print(f"g.V('{edge['from']}').addE('{edge['type']}').to(g.V('{edge['to']}'))")
    if len(edges) > 5:
        print(f"// ... ({len(edges) - 5} more edges)")


def run_interactive(graph, endpoint, batch_size):
    """Load graph via Gremlin WebSocket."""
    try:
        from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
        from gremlin_python.process.anonymous_traversal import traversal
    except ImportError:
        print("Error: gremlinpython not installed. Run: pip install gremlinpython",
              file=sys.stderr)
        sys.exit(1)

    conn = DriverRemoteConnection(endpoint, "g")
    g = traversal().withRemote(conn)

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    # Load vertices.
    for i, node in enumerate(nodes):
        flat = flatten_properties(node.get("properties", {}))
        t = g.addV(node["type"]).property("id", node["id"])
        for k, v in flat.items():
            t = t.property(k, v)
        t.next()
        if (i + 1) % batch_size == 0:
            print(f"  vertices: {i + 1}/{len(nodes)}", file=sys.stderr)

    print(f"Loaded {len(nodes)} vertices", file=sys.stderr)

    # Load edges.
    for i, edge in enumerate(edges):
        g.V().has("id", edge["from"]).addE(edge["type"]).to(
            g.V().has("id", edge["to"])
        ).next()
        if (i + 1) % batch_size == 0:
            print(f"  edges: {i + 1}/{len(edges)}", file=sys.stderr)

    print(f"Loaded {len(edges)} edges", file=sys.stderr)
    conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Load Stave graph-json into Amazon Neptune"
    )
    parser.add_argument("--input", default="-",
                        help="Path to graph-json file (default: stdin)")
    parser.add_argument("--neptune-endpoint", default="",
                        help="Neptune Gremlin WebSocket URI (interactive mode)")
    parser.add_argument("--bulk", action="store_true",
                        help="Produce bulk load CSV files (air-gapped)")
    parser.add_argument("--out", default="",
                        help="Output directory for bulk CSV files")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print Gremlin traversals without executing")
    parser.add_argument("--batch-size", type=int, default=100,
                        help="Traversals per batch (interactive mode)")
    args = parser.parse_args()

    graph = load_graph(args.input if args.input != "-" else None)
    meta = graph.get("metadata", {})
    print(f"Graph: {meta.get('node_count', '?')} nodes, "
          f"{meta.get('edge_count', '?')} edges", file=sys.stderr)

    if args.dry_run:
        run_dry(graph)
    elif args.bulk:
        if not args.out:
            print("--out is required with --bulk", file=sys.stderr)
            sys.exit(2)
        write_bulk_csv(graph, args.out)
    elif args.neptune_endpoint:
        run_interactive(graph, args.neptune_endpoint, args.batch_size)
    else:
        print("Specify --neptune-endpoint, --bulk, or --dry-run", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

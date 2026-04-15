#!/usr/bin/env python3
"""Stave graph-json to GraphML converter.

Produces a GraphML file consumable by Gephi, yEd, Cytoscape desktop,
NetworkX, igraph, and any GraphML-aware tool.

Usage:
    stave graph export --output assessment.json | python3 to-graphml.py > graph.graphml
    python3 to-graphml.py --input graph.json --output graph.graphml
    python3 to-graphml.py --input graph.json --filter-type ThreatChain,Finding
"""
import argparse
import json
import sys
import xml.etree.ElementTree as ET


def load_graph(path):
    if path and path != "-":
        with open(path) as f:
            return json.load(f)
    return json.load(sys.stdin)


def flatten_properties(props):
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


def graphml_type(value):
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "double"
    return "string"


def to_graphml(graph, filter_types=None, active_only=False):
    """Convert graph-json to GraphML XML."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    # Apply filters.
    if filter_types:
        allowed = set(filter_types)
        nodes = [n for n in nodes if n["type"] in allowed]
        node_ids = {n["id"] for n in nodes}
        edges = [e for e in edges if e["from"] in node_ids and e["to"] in node_ids]

    if active_only:
        chain_ids = {n["id"] for n in nodes if n["type"] == "ThreatChain"
                     and n.get("properties", {}).get("active")}
        connected = set()
        for e in edges:
            if e["from"] in chain_ids or e["to"] in chain_ids:
                connected.add(e["from"])
                connected.add(e["to"])
        nodes = [n for n in nodes if n["id"] in connected]
        node_ids = {n["id"] for n in nodes}
        edges = [e for e in edges if e["from"] in node_ids and e["to"] in node_ids]

    # Collect all property keys and their types.
    node_keys = {}
    for node in nodes:
        flat = flatten_properties(node.get("properties", {}))
        for k, v in flat.items():
            if k not in node_keys:
                node_keys[k] = graphml_type(v)

    # Build XML.
    ns = "http://graphml.graphdrawing.org/graphml"
    graphml = ET.Element("graphml", xmlns=ns)

    # Node property keys.
    ET.SubElement(graphml, "key", id="node_type", attrib={
        "for": "node", "attr.name": "type", "attr.type": "string"})
    ET.SubElement(graphml, "key", id="node_standard", attrib={
        "for": "node", "attr.name": "standard", "attr.type": "string"})
    for key, ktype in sorted(node_keys.items()):
        ET.SubElement(graphml, "key", id=f"n_{key}", attrib={
            "for": "node", "attr.name": key, "attr.type": ktype})

    # Edge property key.
    ET.SubElement(graphml, "key", id="edge_type", attrib={
        "for": "edge", "attr.name": "type", "attr.type": "string"})

    graph_elem = ET.SubElement(graphml, "graph", id="stave", edgedefault="directed")

    # Nodes.
    for node in nodes:
        n_elem = ET.SubElement(graph_elem, "node", id=node["id"])
        d = ET.SubElement(n_elem, "data", key="node_type")
        d.text = node["type"]
        d = ET.SubElement(n_elem, "data", key="node_standard")
        d.text = node.get("standard", "")

        flat = flatten_properties(node.get("properties", {}))
        for key, value in sorted(flat.items()):
            d = ET.SubElement(n_elem, "data", key=f"n_{key}")
            if isinstance(value, bool):
                d.text = str(value).lower()
            else:
                d.text = str(value)

    # Edges.
    for i, edge in enumerate(edges):
        e_elem = ET.SubElement(graph_elem, "edge",
                               id=f"e{i}",
                               source=edge["from"],
                               target=edge["to"])
        d = ET.SubElement(e_elem, "data", key="edge_type")
        d.text = edge["type"]

    return graphml


def main():
    parser = argparse.ArgumentParser(
        description="Convert Stave graph-json to GraphML"
    )
    parser.add_argument("--input", default="-",
                        help="Path to graph-json file (default: stdin)")
    parser.add_argument("--output", default="-",
                        help="Path to GraphML output (default: stdout)")
    parser.add_argument("--filter-type", default="",
                        help="Comma-separated node types to include")
    parser.add_argument("--active-only", action="store_true",
                        help="Only include nodes connected to active chains")
    args = parser.parse_args()

    graph = load_graph(args.input if args.input != "-" else None)

    filter_types = [t.strip() for t in args.filter_type.split(",") if t.strip()] if args.filter_type else None

    graphml = to_graphml(graph, filter_types=filter_types, active_only=args.active_only)

    tree = ET.ElementTree(graphml)
    ET.indent(tree, space="  ")

    if args.output and args.output != "-":
        tree.write(args.output, encoding="unicode", xml_declaration=True)
        print(f"Wrote GraphML to {args.output}", file=sys.stderr)
    else:
        tree.write(sys.stdout, encoding="unicode", xml_declaration=True)


if __name__ == "__main__":
    main()

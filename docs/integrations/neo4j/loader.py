#!/usr/bin/env python3
"""Stave graph-json to Neo4j loader.

Reads graph-json from stdin or file and loads nodes and edges into
Neo4j using the Bolt protocol. Uses MERGE for idempotent loading —
safe to run repeatedly against the same database.

Usage:
    stave graph export --output assessment.json | python3 loader.py
    python3 loader.py --input graph.json
    python3 loader.py --input graph.json --neo4j-uri bolt://localhost:7687
    python3 loader.py --input graph.json --dry-run
"""
import argparse
import json
import sys


# Map graph-json node type to Neo4j labels.
# Resource nodes get an additional label based on resource_class.
NODE_LABELS = {
    "Finding":              ["Finding"],
    "Resource":             ["Resource"],
    "Control":              ["Control"],
    "ThreatChain":          ["ThreatChain"],
    "ChainFinding":         ["ChainFinding"],
    "ComplianceRequirement": ["ComplianceRequirement"],
    "AttackerCapability":   ["AttackerCapability"],
    "RemediationAction":    ["RemediationAction"],
    "TenantScope":          ["TenantScope"],
    "Identity":             ["Identity"],
    "AccessPolicy":         ["AccessPolicy"],
}

# Map resource_class to additional Neo4j label.
RESOURCE_CLASS_LABELS = {
    "storage":   "StorageResource",
    "database":  "DatabaseResource",
    "compute":   "ComputeResource",
    "instance":  "InstanceResource",
    "container": "ContainerResource",
    "network":   "NetworkResource",
    "identity":  "IdentityResource",
    "key":       "KeyResource",
    "secret":    "SecretResource",
    "cdn":       "CdnResource",
    "dns":       "DnsResource",
    "registry":  "RegistryResource",
    "queue":     "QueueResource",
    "log":       "LogResource",
}

# Map node type to its unique ID property name.
NODE_ID_FIELDS = {
    "Finding":              "finding_id",
    "Resource":             "resource_arn",
    "Control":              "control_id",
    "ThreatChain":          "chain_id",
    "ComplianceRequirement": "id",
    "AttackerCapability":   "chain_id",
    "RemediationAction":    "finding_id",
    "TenantScope":          "account_id",
    "Identity":             "principal_arn",
}


def load_graph(path):
    """Load graph-json from file or stdin."""
    if path and path != "-":
        with open(path) as f:
            return json.load(f)
    return json.load(sys.stdin)


def flatten_properties(props):
    """Flatten nested dicts into dot-separated keys for Neo4j properties.

    Neo4j properties must be scalar values or lists of scalars.
    Nested objects are flattened: {"a": {"b": 1}} -> {"a.b": 1}
    Lists of objects are stored as JSON strings.
    """
    flat = {}
    for key, value in props.items():
        if isinstance(value, dict):
            for sub_key, sub_val in value.items():
                flat[f"{key}.{sub_key}"] = sub_val
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            flat[key] = json.dumps(value)
        else:
            flat[key] = value
    return flat


def node_labels(node):
    """Determine Neo4j labels for a graph-json node."""
    node_type = node["type"]
    labels = list(NODE_LABELS.get(node_type, [node_type]))

    if node_type == "Resource":
        rc = node.get("properties", {}).get("resource_class", "")
        extra = RESOURCE_CLASS_LABELS.get(rc)
        if extra:
            labels.append(extra)

    return labels


def node_id_field(node_type):
    """Return the property name used as unique ID for a node type."""
    return NODE_ID_FIELDS.get(node_type, "id")


def build_merge_node_cypher(labels, id_field):
    """Build a MERGE Cypher statement for a batch of nodes."""
    label_str = ":".join(labels)
    return (
        f"UNWIND $batch AS row "
        f"MERGE (n:{label_str} {{{id_field}: row.id}}) "
        f"SET n += row.properties"
    )


def build_merge_edge_cypher(edge_type):
    """Build a MERGE Cypher statement for a batch of edges."""
    return (
        f"UNWIND $batch AS row "
        f"MATCH (a {{id: row.from_id}}) "
        f"MATCH (b {{id: row.to_id}}) "
        f"MERGE (a)-[r:{edge_type}]->(b) "
        f"SET r += row.properties"
    )


def group_nodes_by_label(nodes):
    """Group nodes by their label set for batch loading."""
    groups = {}
    for node in nodes:
        labels = tuple(node_labels(node))
        if labels not in groups:
            groups[labels] = []
        groups[labels].append(node)
    return groups


def group_edges_by_type(edges):
    """Group edges by type for batch loading."""
    groups = {}
    for edge in edges:
        etype = edge["type"]
        if etype not in groups:
            groups[etype] = []
        groups[etype].append(edge)
    return groups


def run_dry(graph):
    """Print Cypher statements without executing."""
    print("// --- Nodes ---")
    node_groups = group_nodes_by_label(graph.get("nodes", []))
    for labels, nodes in node_groups.items():
        id_field = node_id_field(nodes[0]["type"])
        cypher = build_merge_node_cypher(labels, id_field)
        print(f"\n// {len(nodes)} nodes with labels {':'.join(labels)}")
        print(f"// {cypher}")
        for n in nodes[:3]:
            print(f"//   id={n['id']}")
        if len(nodes) > 3:
            print(f"//   ... ({len(nodes) - 3} more)")

    print("\n// --- Edges ---")
    edge_groups = group_edges_by_type(graph.get("edges", []))
    for etype, edges in edge_groups.items():
        cypher = build_merge_edge_cypher(etype)
        print(f"\n// {len(edges)} edges of type {etype}")
        print(f"// {cypher}")
        for e in edges[:3]:
            print(f"//   {e['from']} -> {e['to']}")
        if len(edges) > 3:
            print(f"//   ... ({len(edges) - 3} more)")


def run_load(graph, uri, user, password, database, batch_size, clear):
    """Load graph into Neo4j."""
    try:
        import neo4j as neo4j_driver
    except ImportError:
        print("Error: neo4j Python driver not installed. Run: pip install neo4j",
              file=sys.stderr)
        sys.exit(1)

    driver = neo4j_driver.GraphDatabase.driver(uri, auth=(user, password))

    try:
        driver.verify_connectivity()
    except Exception as e:
        print(f"Error: cannot connect to Neo4j at {uri}: {e}", file=sys.stderr)
        sys.exit(1)

    with driver.session(database=database) as session:
        if clear:
            print("Clearing existing Stave nodes...", file=sys.stderr)
            for label in NODE_LABELS:
                session.run(f"MATCH (n:{label}) DETACH DELETE n")

        # Load nodes.
        node_groups = group_nodes_by_label(graph.get("nodes", []))
        total_nodes = 0
        for labels, nodes in node_groups.items():
            id_field = node_id_field(nodes[0]["type"])
            cypher = build_merge_node_cypher(labels, id_field)

            for i in range(0, len(nodes), batch_size):
                batch = []
                for n in nodes[i:i + batch_size]:
                    props = flatten_properties(n.get("properties", {}))
                    props["id"] = n["id"]
                    batch.append({"id": n["id"], "properties": props})

                session.run(cypher, batch=batch)
                total_nodes += len(batch)

        print(f"Loaded {total_nodes} nodes", file=sys.stderr)

        # Load edges.
        edge_groups = group_edges_by_type(graph.get("edges", []))
        total_edges = 0
        for etype, edges in edge_groups.items():
            cypher = build_merge_edge_cypher(etype)

            for i in range(0, len(edges), batch_size):
                batch = []
                for e in edges[i:i + batch_size]:
                    props = flatten_properties(e.get("properties", {}))
                    batch.append({
                        "from_id": e["from"],
                        "to_id": e["to"],
                        "properties": props,
                    })

                session.run(cypher, batch=batch)
                total_edges += len(batch)

        print(f"Loaded {total_edges} edges", file=sys.stderr)

    driver.close()
    print(f"Done: {total_nodes} nodes, {total_edges} edges loaded into {database}",
          file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Load Stave graph-json into Neo4j"
    )
    parser.add_argument("--input", default="-",
                        help="Path to graph-json file (default: stdin)")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687",
                        help="Neo4j Bolt URI")
    parser.add_argument("--neo4j-user", default="neo4j",
                        help="Neo4j username")
    parser.add_argument("--neo4j-pass", default="neo4j",
                        help="Neo4j password")
    parser.add_argument("--database", default="stave",
                        help="Neo4j database name")
    parser.add_argument("--clear", action="store_true",
                        help="Drop all Stave nodes before loading")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print Cypher statements without executing")
    parser.add_argument("--batch-size", type=int, default=500,
                        help="Nodes/edges per transaction batch")
    args = parser.parse_args()

    graph = load_graph(args.input if args.input != "-" else None)

    meta = graph.get("metadata", {})
    print(f"Graph: {meta.get('node_count', '?')} nodes, "
          f"{meta.get('edge_count', '?')} edges", file=sys.stderr)

    if args.dry_run:
        run_dry(graph)
        return

    run_load(graph, args.neo4j_uri, args.neo4j_user, args.neo4j_pass,
             args.database, args.batch_size, args.clear)


if __name__ == "__main__":
    main()

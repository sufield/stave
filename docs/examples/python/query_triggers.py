#!/usr/bin/env python3
"""
Query Stave findings for violations caused by a specific property change.

Usage:
    python query_triggers.py out.v0.1.json "identity.policies.attached"

Demonstrates downstream ergonomics of the reasoning + triggers fields.
"""
import json
import sys

def main():
    path, query_path = sys.argv[1], sys.argv[2]

    with open(path) as f:
        data = json.load(f)

    findings = data.get("findings", data if isinstance(data, list) else [])

    for f in findings:
        triggers = f.get("triggers")
        if not triggers:
            continue
        if query_path in (triggers.get("changed_paths") or []):
            print(f"[{f['verdict']}] {f['control_id']} on {f['asset_id']}")
            print(f"  Changed: {query_path}")
            print(f"  Before:  {triggers.get('prior_values', {}).get(query_path)}")
            print(f"  After:   {f.get('reasoning', {}).get('observed_values', {}).get(query_path)}")
            print(f"  Delta:   {triggers.get('verdict_delta')}")
            print()

if __name__ == "__main__":
    main()

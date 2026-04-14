#!/usr/bin/env python3
"""Generate Terraform resource patches from Stave structured remediation JSON.

Usage:
    stave rank --in output.json --format json | python3 to-terraform.py > patches.tf
"""
import json, sys

data = json.load(sys.stdin)
entries = data.get("entries", [])

for entry in entries:
    changes = entry.get("remediation", {}).get("changes", [])
    if not changes:
        continue

    asset_id = entry.get("asset_id", "unknown")
    print(f"# {entry.get('control_id', '')} on {asset_id}")

    for change in changes:
        path = change.get("property_path", "")
        required = change.get("required_value", "")
        safe = change.get("has_safe_default", False)

        if safe and required:
            # Convert property path to Terraform-style
            tf_field = path.replace("properties.", "").replace(".", "_")
            print(f'# resource "{change.get("resource_type", "unknown")}" "{asset_id}" {{')
            print(f"#   {tf_field} = {required}")
            print("#}")
        else:
            print(f"# TODO: {change.get('description', path)}")
            print(f"#   Property: {path}")
            print(f"#   Current:  {change.get('current_value', 'unknown')}")
            print(f"#   Required: (context-dependent)")
    print()

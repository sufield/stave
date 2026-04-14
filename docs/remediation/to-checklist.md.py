#!/usr/bin/env python3
"""Generate Markdown remediation checklist from Stave structured remediation JSON.

Usage:
    stave rank --in output.json --format json | python3 to-checklist.md.py > checklist.md
"""
import json, sys

data = json.load(sys.stdin)
entries = data.get("entries", [])

print("# Remediation Checklist")
print()

# Group by confidence tier
high_conf = []
low_conf = []

for entry in entries:
    changes = entry.get("remediation", {}).get("changes", [])
    confidence = entry.get("remediation", {}).get("confidence", 0.5)
    for change in changes:
        item = {
            "control": entry.get("control_id", ""),
            "asset": entry.get("asset_id", ""),
            "change": change,
            "confidence": confidence,
        }
        if change.get("has_safe_default"):
            high_conf.append(item)
        else:
            low_conf.append(item)

if high_conf:
    print("## Safe Defaults (automated)")
    print()
    for item in high_conf:
        c = item["change"]
        print(f"- [ ] **{item['control']}** on `{item['asset']}`")
        print(f"  - Set `{c['property_path']}` to `{c['required_value']}`")
        print(f"  - Confidence: {item['confidence']:.0%}")
    print()

if low_conf:
    print("## Context-Dependent (manual review)")
    print()
    for item in low_conf:
        c = item["change"]
        print(f"- [ ] **{item['control']}** on `{item['asset']}`")
        print(f"  - {c.get('description', c['property_path'])}")
        print(f"  - Current: `{c.get('current_value', 'unknown')}`")
    print()

print(f"---")
print(f"*{len(high_conf)} safe defaults, {len(low_conf)} manual reviews*")

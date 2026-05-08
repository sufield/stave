#!/usr/bin/env python3
"""Game-theoretic cost-to-compromise + security ROI ranking.

Every other engine in `examples/` answers "what is wrong";
this engine answers "how much does it cost the attacker to
exploit, and how much does each remediation increase that
cost?" The output turns security findings into a financial
decision: spend $50 here to add $3000 to the attacker's
bill, or spend $1000 there for an $800 increase. The CISO
gets ROI per remediation, not a flat list of vulnerabilities.

Pure stdlib; numbers are RELATIVE rankings — "$300 vs
$18,000" means "60x harder," not literal dollar costs. The
calibration constants live at the top of this file and are
intended to be overridden per organisation. The model's
value is in *ranking* remediations, not in predicting
absolute spend.

Model:
  Attacker = rational economic actor; chooses the cheapest
              path through the configuration's attack graph.
  Defender = picks the remediation that maximises the
              attacker's minimum cost (maximin); ties broken
              by defender cost.
  Output  = sorted ROI table (attacker_cost_increase /
              defender_cost), with INFINITE ROI for
              remediations that block a path entirely.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# =====================================================
# Calibration constants (RELATIVE values, not literal $).
# Override per organisation with internal threat intel.
# =====================================================

ATTACKER_STEP_COSTS = {
    # Discovery
    "discover_endpoint":             100,
    # Credential acquisition
    "unauthenticated_access":         50,
    "self_registration":             200,
    # Privilege manipulation
    "role_assumption":               500,
    "compute_trust_passrole":        200,
    "additional_hop":                800,
    # Exploitation primitives
    "broad_action_exploitation":     100,
    "scoped_action_exploitation":    300,
    "wildcard_resource":              50,
    "scoped_resource":               400,
    # Detection evasion (zero cost when no controls; high cost
    # when the env runs CloudTrail data events / SCPs)
    "evade_no_logging":                0,
    "evade_with_logging":           2000,
    "evade_no_scp":                    0,
    "evade_with_scp":               3000,
}

DEFENDER_REMEDIATIONS: dict = {
    "disable_unauth":           {"cost":   50, "blocks":   ["unauthenticated_access"]},
    "close_self_registration":  {"cost":   50, "blocks":   ["self_registration"]},
    "enable_mfa":               {"cost":  200, "increases":{"self_registration": 5000}},
    "scope_actions":            {"cost":  500, "replaces": {"broad_action_exploitation": "scoped_action_exploitation"}},
    "scope_resources":          {"cost":  500, "replaces": {"wildcard_resource": "scoped_resource"}},
    "enable_data_events":       {"cost": 1000, "replaces": {"evade_no_logging": "evade_with_logging"}},
    "apply_scp":                {"cost":  800, "replaces": {"evade_no_scp": "evade_with_scp"}},
    "remove_compute_trust":     {"cost":  300, "blocks":   ["compute_trust_passrole"]},
    "add_permissions_boundary": {"cost":  400, "increases":{"role_assumption": 2000}},
    "restrict_ip_range":        {"cost":  200, "increases":{"discover_endpoint": 3000}},
}


# =====================================================
# Attack-path extraction from JSONL.
# =====================================================
def load_facts(jsonl_path: Path) -> dict:
    facts: dict = {}
    for line in jsonl_path.read_text().splitlines():
        if not line.strip():
            continue
        t = json.loads(line)
        facts.setdefault(t["predicate"], []).append(t)
    return facts


def extract_attack_paths(facts: dict) -> list:
    """Build attack paths from the facts dict.

    Each shape is independent. A fixture may produce 0–4
    paths depending on which prerequisites are present.
    """
    paths: list = []

    # Helpers — pull commonly-needed flag values once.
    def has_pred(pred: str, value: str = "true") -> bool:
        return any(f["object"] == value for f in facts.get(pred, []))

    actions = [f["object"] for f in facts.get("has_action", [])]
    resources = [f["object"] for f in facts.get("has_resource", [])]
    has_broad_action = any(a == "*" or a.endswith(":*") for a in actions)
    has_wildcard_res = any(r == "*" for r in resources)

    # Shape 1: anonymous → S3 via unauthenticated identity pool.
    if has_pred("allows_unauthenticated"):
        steps = ["discover_endpoint", "unauthenticated_access"]
        steps.append("broad_action_exploitation" if has_broad_action else "scoped_action_exploitation")
        steps.append("wildcard_resource" if has_wildcard_res else "scoped_resource")
        steps.extend(["evade_no_logging", "evade_no_scp"])
        paths.append({"name": "Unauthenticated -> S3", "steps": steps})

    # Shape 2: self-register → authenticated role → S3.
    if has_pred("self_registration_unrestricted"):
        steps = ["discover_endpoint", "self_registration", "role_assumption"]
        steps.append("broad_action_exploitation" if has_broad_action else "scoped_action_exploitation")
        steps.append("wildcard_resource" if has_wildcard_res else "scoped_resource")
        steps.extend(["evade_no_logging", "evade_no_scp"])
        paths.append({"name": "Self-register -> auth role -> S3", "steps": steps})

    # Shape 3: multi-hop assume chain.
    edges = facts.get("can_assume", [])
    if edges:
        steps = ["discover_endpoint", "role_assumption"]
        # Each additional edge after the first hop adds an additional_hop step.
        for _ in range(max(0, len(edges) - 1)):
            steps.append("additional_hop")
        steps.append("broad_action_exploitation" if has_broad_action else "scoped_action_exploitation")
        steps.extend(["evade_no_logging", "evade_no_scp"])
        paths.append({"name": f"Multi-hop assume chain ({len(edges)} edges)", "steps": steps})

    # Shape 4: compute trust + PassRole.
    services = [f for f in facts.get("trusts_service", [])]
    contributed = facts.get("contributed_by", [])
    if services and contributed:
        steps = ["discover_endpoint", "compute_trust_passrole", "role_assumption"]
        steps.append("broad_action_exploitation" if has_broad_action else "scoped_action_exploitation")
        steps.extend(["evade_no_logging", "evade_no_scp"])
        paths.append({"name": "Compute PassRole escalation", "steps": steps})

    return paths


# =====================================================
# Cost computation.
# =====================================================
def path_cost(steps: list) -> int:
    return sum(ATTACKER_STEP_COSTS.get(s, 0) for s in steps)


INFINITY = float("inf")


def remediation_impact(steps: list, name: str) -> tuple:
    """Apply a remediation and return (new_attacker_cost, defender_cost).

    new_attacker_cost is INFINITY if the path is blocked
    (the remediation eliminates a step the path requires).
    """
    rem = DEFENDER_REMEDIATIONS[name]
    defender_cost: int = rem["cost"]

    # Blocking — if any step in this path matches a `blocks`
    # entry, the path no longer exists.
    if "blocks" in rem and any(s in steps for s in rem["blocks"]):
        return INFINITY, defender_cost

    new_steps = list(steps)
    if "replaces" in rem:
        new_steps = [rem["replaces"].get(s, s) for s in new_steps]

    base = path_cost(new_steps)
    if "increases" in rem:
        base += sum(rem["increases"].get(s, 0) for s in new_steps)
    return base, defender_cost


def evaluate_remediations(cheapest_path: dict) -> list:
    """For the attacker's cheapest path, score every remediation."""
    current = path_cost(cheapest_path["steps"])
    rows: list = []
    for name in DEFENDER_REMEDIATIONS:
        new_cost, def_cost = remediation_impact(cheapest_path["steps"], name)
        if new_cost == INFINITY:
            increase = INFINITY
            roi = INFINITY
        else:
            increase = new_cost - current
            roi = (increase / def_cost) if def_cost > 0 else INFINITY
        rows.append({
            "name": name,
            "defender_cost": def_cost,
            "attacker_before": current,
            "attacker_after": new_cost,
            "increase": increase,
            "roi": roi,
        })
    # Sort by ROI desc; INFINITY-ROI items first; ties → cheaper defender wins.
    def sort_key(r):
        roi = r["roi"]
        return (-(1e18 if roi == INFINITY else roi), r["defender_cost"])
    rows.sort(key=sort_key)
    return rows


# =====================================================
# Output rendering.
# =====================================================
def fmt_dollars(n) -> str:
    if n == INFINITY:
        return "BLOCKED"
    return f"${n:,}"


def fmt_roi(r) -> str:
    if r == INFINITY:
        return "INF"
    return f"{r:.0f}x"


def verdict(cheapest_cost) -> str:
    if cheapest_cost == INFINITY:
        return "MINIMAL — no viable attack path under modeled shapes"
    if cheapest_cost < 500:
        return "CRITICAL — trivially cheap to exploit"
    if cheapest_cost < 2000:
        return "HIGH — affordable for opportunistic attackers"
    if cheapest_cost < 10000:
        return "MEDIUM — requires motivated attacker"
    if cheapest_cost < 50000:
        return "LOW — requires well-resourced attacker"
    return "MINIMAL — prohibitively expensive"


def render(label: str, paths: list) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {label}")
    print(f"{'=' * 70}")
    if not paths:
        print("\n  no attack paths found under modeled shapes")
        print(f"  verdict: {verdict(INFINITY)}")
        return

    print("\n  attack paths (sorted by attacker cost):")
    sorted_paths = sorted(paths, key=lambda p: path_cost(p["steps"]))
    for p in sorted_paths:
        c = path_cost(p["steps"])
        print(f"    {fmt_dollars(c):>10s}  {p['name']}  ({len(p['steps'])} steps)")

    cheapest = sorted_paths[0]
    cheapest_cost = path_cost(cheapest["steps"])
    print(f"\n  attacker's optimal strategy:")
    print(f"    path: {cheapest['name']}")
    print(f"    cost: {fmt_dollars(cheapest_cost)}")
    print("    steps:")
    for step in cheapest["steps"]:
        sc = ATTACKER_STEP_COSTS.get(step, 0)
        print(f"      {fmt_dollars(sc):>8s}  {step}")

    rows = evaluate_remediations(cheapest)
    print("\n  remediation ROI ranking:")
    print(f"    {'remediation':<28s}  {'def $':>8s}  {'before':>10s}  {'after':>10s}  {'roi':>6s}")
    print(f"    {'-' * 28}  {'-' * 8}  {'-' * 10}  {'-' * 10}  {'-' * 6}")
    for r in rows:
        print(
            f"    {r['name']:<28s}  "
            f"{fmt_dollars(r['defender_cost']):>8s}  "
            f"{fmt_dollars(r['attacker_before']):>10s}  "
            f"{fmt_dollars(r['attacker_after']):>10s}  "
            f"{fmt_roi(r['roi']):>6s}"
        )

    best = rows[0]
    print(f"\n  recommended: {best['name']}")
    print(f"    defender cost: {fmt_dollars(best['defender_cost'])}")
    if best["roi"] == INFINITY:
        print("    impact: BLOCKS the cheapest path entirely")
    else:
        print(f"    attacker cost increase: {fmt_dollars(best['increase'])}  (ROI {fmt_roi(best['roi'])})")

    print(f"\n  verdict: {verdict(cheapest_cost)}")


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: cost_model.py <label> <facts.jsonl>", file=sys.stderr)
        return 2
    label, path = sys.argv[1], Path(sys.argv[2])
    facts = load_facts(path)
    paths = extract_attack_paths(facts)
    render(label, paths)
    return 0


if __name__ == "__main__":
    sys.exit(main())

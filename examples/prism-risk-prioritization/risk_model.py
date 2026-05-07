#!/usr/bin/env python3
"""Probabilistic attack-path prioritisation over Stave JSONL facts.

Z3 says "this path exists" (binary). This module assigns each
known attack shape a probability of exploitation conditioned
on attacker behaviour and the specific facts present in the
fixture.

Attack shapes covered:
  - cognito_unauth     anonymous identity-pool path to AWS
  - cognito_self_reg   self-register + authenticated mapping
  - multi_hop_chain    transitive can_assume edges (privesc)
  - overperm_compute   role with finding AND compute trust
  - wildcard_resource  s3:* + Resource:* (broad surface)

Each shape evaluates only when its prerequisites are present;
otherwise it scores 0. The fixture's overall P(exploitation)
is the MAX across applicable shapes — the worst-case attack
the configuration permits.

Probabilities are STARTING ESTIMATES, not actuarial values.
Their job is to *rank* paths against each other, not to
predict exploitation in absolute terms. Calibrate the
constants below with your own threat-intel before publishing
risk numbers as predictions.

Pure-stdlib by design — no pgmpy / no PRISM / no Java. The
multiplications are sequential-step independence; the
inference is closed-form, so a Bayesian-network library
would add ceremony without changing the numbers.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# =====================================================
# Calibration constants. Override per organisation.
# =====================================================

# Shape: cognito unauthenticated chain
P_DISCOVER_ENDPOINT = 0.80
P_UNAUTH_CREDS_GIVEN_ENABLED = 0.95
P_ROLE_ASSUMPTION = 0.95
P_RESOURCE_ACCESS_BROAD = 0.95
P_RESOURCE_ACCESS_NARROW = 0.80
P_EXFIL_NO_LOGGING = 0.95
P_EXFIL_WITH_LOGGING = 0.60
P_DETECT_NO_LOGGING = 0.05
P_DETECT_WITH_LOGGING = 0.40

# Shape: cognito self-register chain
P_SELF_REG_GIVEN_OPEN = 0.85

# Shape: multi-hop assume chain — per-hop success rate
P_PER_HOP = 0.90  # 90% chance the attacker succeeds at each AssumeRole
# Floor for chains of any length (attacker has SOMETHING to assume)
P_PRIVESC_FLOOR = 0.05

# Shape: overperm + compute trust (the iter-13 / iter-15 compound)
P_OVERPERM_COMPUTE = 0.65

# Shape: wildcard resource surface — broad-write
P_WILDCARD_BROAD = 0.40


# =====================================================
# Fact loading.
# =====================================================
def load_facts(jsonl_path: Path) -> dict:
    """Read JSONL triples and return a structured fact bag."""
    facts: dict = {
        "unauth_enabled": False,
        "self_reg_open": False,
        "has_sensitive_data": False,
        "has_logging": False,
        "actions": [],
        "resources": [],
        "tags": [],
        "can_assume_edges": [],
        "trusts_service": {},
        "contributed_by": {},
    }
    with jsonl_path.open() as f:
        for line in f:
            t = json.loads(line)
            pred, subj, obj = t["predicate"], t["subject"], t["object"]
            if pred == "allows_unauthenticated" and obj == "true":
                facts["unauth_enabled"] = True
            elif pred == "self_registration_unrestricted" and obj == "true":
                facts["self_reg_open"] = True
            elif pred == "has_tag":
                facts["tags"].append((subj, obj))
                if "data_classification" in obj or "phi" in obj.lower():
                    facts["has_sensitive_data"] = True
                if "production" in obj:
                    facts["has_sensitive_data"] = True  # production targets matter
            elif pred == "has_action":
                facts["actions"].append((subj, obj))
            elif pred == "has_resource":
                facts["resources"].append((subj, obj))
            elif pred == "can_assume":
                facts["can_assume_edges"].append((subj, obj))
            elif pred == "trusts_service":
                facts["trusts_service"].setdefault(subj, []).append(obj)
            elif pred == "contributed_by":
                facts["contributed_by"].setdefault(subj, []).append(obj)
            elif pred == "has_exposure_window":
                # Treat presence of any exposure_window as a signal that a
                # logging surface is active. Not perfect but a useful proxy
                # until a dedicated has_data_event_logging fact is projected.
                facts["has_logging"] = True
    return facts


# =====================================================
# Per-shape probability calculators. Each returns
# (probability, applicable, explanation_steps).
# =====================================================
def shape_cognito_unauth(facts: dict) -> tuple[float, bool, list]:
    if not facts["unauth_enabled"]:
        return 0.0, False, []
    p_creds = P_UNAUTH_CREDS_GIVEN_ENABLED
    p_access = (
        P_RESOURCE_ACCESS_BROAD
        if any(a == "s3:*" for _, a in facts["actions"])
        else P_RESOURCE_ACCESS_NARROW
    )
    p_exfil = P_EXFIL_WITH_LOGGING if facts["has_logging"] else P_EXFIL_NO_LOGGING
    p = P_DISCOVER_ENDPOINT * p_creds * P_ROLE_ASSUMPTION * p_access * p_exfil
    steps = [
        ("Discover endpoint", P_DISCOVER_ENDPOINT),
        ("Acquire unauth creds", p_creds),
        ("Assume role", P_ROLE_ASSUMPTION),
        ("Reach resource", p_access),
        ("Exfiltrate", p_exfil),
    ]
    return p, True, steps


def shape_cognito_self_reg(facts: dict) -> tuple[float, bool, list]:
    if not facts["self_reg_open"]:
        return 0.0, False, []
    p_creds = P_SELF_REG_GIVEN_OPEN
    p_access = (
        P_RESOURCE_ACCESS_BROAD
        if any(a == "s3:*" for _, a in facts["actions"])
        else P_RESOURCE_ACCESS_NARROW
    )
    p_exfil = P_EXFIL_WITH_LOGGING if facts["has_logging"] else P_EXFIL_NO_LOGGING
    p = P_DISCOVER_ENDPOINT * p_creds * P_ROLE_ASSUMPTION * p_access * p_exfil
    steps = [
        ("Discover endpoint", P_DISCOVER_ENDPOINT),
        ("Self-register, confirm email", p_creds),
        ("Assume role", P_ROLE_ASSUMPTION),
        ("Reach resource", p_access),
        ("Exfiltrate", p_exfil),
    ]
    return p, True, steps


def shape_multi_hop_chain(facts: dict) -> tuple[float, bool, list]:
    edges = facts["can_assume_edges"]
    if not edges:
        return 0.0, False, []
    # Find longest chain by walking forward greedily; bound at 8 hops.
    successors: dict = {}
    for a, b in edges:
        successors.setdefault(a, set()).add(b)
    longest = 1
    for start in {a for a, _ in edges}:
        seen = {start}
        depth = 0
        frontier = {start}
        while depth < 8:
            next_frontier = {
                nxt for cur in frontier for nxt in successors.get(cur, set())
                if nxt not in seen
            }
            if not next_frontier:
                break
            depth += 1
            frontier = next_frontier
            seen.update(frontier)
        longest = max(longest, depth)
    # A single 1-hop assume edge isn't a privesc chain — it's just
    # an assume. The shape only applies at depth >= 2, where the
    # transitive composition is the security property.
    if longest < 2:
        return 0.0, False, []
    # Per-hop independence: P(chain) = P_PER_HOP ** depth, floored.
    p = max(P_PRIVESC_FLOOR, P_PER_HOP ** longest)
    steps = [
        (f"Multi-hop privesc chain (depth {longest})", p),
    ]
    return p, True, steps


def shape_overperm_compute(facts: dict) -> tuple[float, bool, list]:
    overlapping = [
        role for role, _ in facts["contributed_by"].items()
        if role in facts["trusts_service"]
    ]
    if not overlapping:
        return 0.0, False, []
    p = P_OVERPERM_COMPUTE
    steps = [
        (f"Overpermissioned role + compute trust (×{len(overlapping)})", p),
    ]
    return p, True, steps


def shape_wildcard_resource(facts: dict) -> tuple[float, bool, list]:
    has_wildcard_action = any(a == "s3:*" or a == "*" for _, a in facts["actions"])
    has_wildcard_resource = any(r == "*" for _, r in facts["resources"])
    if not (has_wildcard_action and has_wildcard_resource):
        return 0.0, False, []
    p = P_WILDCARD_BROAD
    steps = [
        ("Wildcard action on wildcard resource", p),
    ]
    return p, True, steps


SHAPES = [
    ("cognito_unauth", shape_cognito_unauth),
    ("cognito_self_reg", shape_cognito_self_reg),
    ("multi_hop_chain", shape_multi_hop_chain),
    ("overperm_compute", shape_overperm_compute),
    ("wildcard_resource", shape_wildcard_resource),
]


# =====================================================
# Output formatting.
# =====================================================
def risk_rating(p: float) -> str:
    if p >= 0.40:
        return "CRITICAL — immediate remediation required"
    if p >= 0.20:
        return "HIGH — prioritize within current sprint"
    if p >= 0.05:
        return "MEDIUM — schedule for next review cycle"
    if p > 0:
        return "LOW — monitor, no immediate action"
    return "NONE — no modeled attack shape applies"


def render_bar(p: float, width: int = 20) -> str:
    filled = int(round(p * width))
    return "#" * filled + "-" * (width - filled)


def render_fixture(label: str, facts: dict, applied: list) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {label}")
    print(f"{'=' * 60}")
    print()
    print("  Configuration:")
    print(f"    unauthenticated access enabled : {'YES' if facts['unauth_enabled'] else 'no'}")
    print(f"    self-registration open         : {'YES' if facts['self_reg_open'] else 'no'}")
    print(f"    sensitive data tagged          : {'YES' if facts['has_sensitive_data'] else 'no'}")
    print(f"    can_assume edges               : {len(facts['can_assume_edges'])}")
    print(f"    overperm + compute-trust roles : {sum(1 for r in facts['contributed_by'] if r in facts['trusts_service'])}")
    print()
    if not applied:
        p_total = 0.0
        print("  No modeled attack shape applies to this fixture.")
        print()
    else:
        print("  Applicable attack shapes:")
        for name, prob, steps in applied:
            print(f"    {name:22s}  P = {prob:.1%}  [{render_bar(prob)}]")
            for desc, sp in steps:
                print(f"      step: {desc:48s}  {sp:.2f}")
        print()
        p_total = max(prob for _, prob, _ in applied)
    print(f"  P(exploitation) = {p_total:.1%}")
    print(f"  risk            : {risk_rating(p_total)}")


def evaluate(jsonl_path: Path) -> tuple[dict, list, float]:
    facts = load_facts(jsonl_path)
    applied: list = []
    for name, fn in SHAPES:
        prob, applicable, steps = fn(facts)
        if applicable:
            applied.append((name, prob, steps))
    p_total = max((p for _, p, _ in applied), default=0.0)
    return facts, applied, p_total


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: risk_model.py <label> <facts.jsonl>", file=sys.stderr)
        return 2
    label = sys.argv[1]
    path = Path(sys.argv[2])
    facts, applied, _ = evaluate(path)
    render_fixture(label, facts, applied)
    return 0


if __name__ == "__main__":
    sys.exit(main())

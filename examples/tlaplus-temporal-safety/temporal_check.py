#!/usr/bin/env python3
"""Temporal-safety state-space exploration — Python implementation.

Models cloud configuration as a state machine over a small set
of mutable boolean properties. Each state is one assignment of
those booleans; each transition is a single API call that flips
one boolean. BFS explores every reachable state and checks the
safety invariants at each.

The unique question this answers vs the other engines: "Even
if THIS snapshot is safe, how far is it from an unsafe state?"
The minimum-hop distance to a violating state is the
*drift margin* — the number of legitimate API calls a developer
is away from breaking the invariant.

Pure stdlib; no Java, no TLC. The TLA+/TLC counterparts in
this directory model the same state machine and give identical
verdicts but require a Java runtime and the tla2tools.jar
download. Switch to TLC when temporal logic over infinite or
parameterized state spaces becomes foundational.
"""
from __future__ import annotations

import json
import sys
from collections import deque
from pathlib import Path

# =====================================================
# State variables — mutable boolean configuration knobs.
# Adding a knob doubles the state space; keeping the
# vector at 7 yields 128 states — exhaustively
# searchable in milliseconds.
# =====================================================
VARIABLES = [
    "unauth_enabled",      # identity-pool: allows_unauthenticated=true
    "self_reg_open",       # user-pool: self_registration_unrestricted=true
    "auth_role_broad",     # auth role grants s3:* on Resource:*
    "unauth_role_broad",   # unauth role grants s3:* on Resource:*
    "data_logging",        # CloudTrail data event logging on
    "scp_applied",         # SCP restricting the account
    "mfa_required",        # user-pool requires MFA
]


# State encoded as an int bitmask over VARIABLES (bit i = VARIABLES[i] true).
def state_get(state: int, name: str) -> bool:
    return bool(state & (1 << VARIABLES.index(name)))


def state_set(state: int, name: str, value: bool) -> int:
    bit = 1 << VARIABLES.index(name)
    return (state | bit) if value else (state & ~bit)


def state_str(state: int) -> str:
    flags = [v for v in VARIABLES if state_get(state, v)]
    return "{" + ", ".join(flags) + "}" if flags else "{}"


def successors(state: int) -> list[int]:
    """One-step neighbours: states that differ by exactly one boolean flip."""
    return [state ^ (1 << i) for i in range(len(VARIABLES))]


# =====================================================
# Safety invariants. Each is True when the property
# HOLDS (safe). A False return is a violation.
# =====================================================
def inv_no_anon_broad(s: int) -> bool:
    """Anonymous users must not reach broad S3 access."""
    return not (state_get(s, "unauth_enabled") and state_get(s, "unauth_role_broad"))


def inv_no_self_reg_broad_without_mfa(s: int) -> bool:
    """Self-registered users must not reach broad access without MFA."""
    return not (
        state_get(s, "self_reg_open")
        and state_get(s, "auth_role_broad")
        and not state_get(s, "mfa_required")
    )


def inv_no_broad_without_logging(s: int) -> bool:
    """Broad access must coincide with data-event logging."""
    return not (state_get(s, "auth_role_broad") and not state_get(s, "data_logging"))


def inv_no_broad_without_scp(s: int) -> bool:
    """Broad access requires an SCP fence (defence-in-depth)."""
    return not (state_get(s, "auth_role_broad") and not state_get(s, "scp_applied"))


INVARIANTS = [
    ("NoAnonBroadAccess", inv_no_anon_broad),
    ("NoSelfRegBroadAccessWithoutMFA", inv_no_self_reg_broad_without_mfa),
    ("NoBroadAccessWithoutLogging", inv_no_broad_without_logging),
    ("NoBroadAccessWithoutSCP", inv_no_broad_without_scp),
]


def violations(s: int) -> list[str]:
    return [name for name, fn in INVARIANTS if not fn(s)]


# =====================================================
# Initial-state extraction from Stave JSONL.
# =====================================================
def load_initial_state(jsonl_path: Path) -> int:
    s = 0
    saw_unauth_role_broad = False
    saw_auth_role_broad = False
    actions_by_role: dict = {}
    resources_by_role: dict = {}
    for line in jsonl_path.read_text().splitlines():
        if not line.strip():
            continue
        t = json.loads(line)
        pred, subj, obj = t["predicate"], t["subject"], t["object"]
        if pred == "allows_unauthenticated" and obj == "true":
            s = state_set(s, "unauth_enabled", True)
        elif pred == "self_registration_unrestricted" and obj == "true":
            s = state_set(s, "self_reg_open", True)
        elif pred == "has_action":
            actions_by_role.setdefault(subj, set()).add(obj)
        elif pred == "has_resource":
            resources_by_role.setdefault(subj, set()).add(obj)
        # data_logging, scp_applied, mfa_required have no direct
        # SIR projection today; they default to False. The Stave
        # observation schema would need explicit facts for these
        # to flip — extending the SIR projection is a separate
        # exercise. The state-space search still produces a useful
        # drift-margin number under the conservative assumption
        # that those guards are absent.
    # auth/unauth role classification — match the cognito naming convention
    # but fall back to "any IAM role with broad grants" for fixtures that
    # don't follow the Cognito pattern.
    for role, acts in actions_by_role.items():
        broad = ("s3:*" in acts or "*" in acts) and "*" in resources_by_role.get(role, set())
        if not broad:
            continue
        if "Unauth" in role or "unauth" in role.lower():
            saw_unauth_role_broad = True
        else:
            saw_auth_role_broad = True
    if saw_unauth_role_broad:
        s = state_set(s, "unauth_role_broad", True)
    if saw_auth_role_broad:
        s = state_set(s, "auth_role_broad", True)
    return s


# =====================================================
# BFS exploration with drift-margin computation.
# =====================================================
def explore(initial: int, max_depth: int = 7) -> dict:
    """Compute reachable-state stats + min distance to violation."""
    # Distance from initial to every reachable state (BFS).
    distance: dict = {initial: 0}
    queue: deque = deque([initial])
    while queue:
        s = queue.popleft()
        if distance[s] >= max_depth:
            continue
        for nxt in successors(s):
            if nxt not in distance:
                distance[nxt] = distance[s] + 1
                queue.append(nxt)

    initial_violations = violations(initial)
    unsafe_states = sum(1 for s in distance if violations(s))
    safe_states = len(distance) - unsafe_states

    # Drift margin: minimum distance from initial to a state that
    # newly violates an invariant the initial state *does not*
    # violate. If initial already violates everything, drift = 0.
    initial_violation_set = set(initial_violations)
    nearest_new_violation: dict = {}  # invariant name → min hops
    for s, d in distance.items():
        if d == 0:
            continue
        for v in violations(s):
            if v in initial_violation_set:
                continue
            if v not in nearest_new_violation or d < nearest_new_violation[v]:
                nearest_new_violation[v] = d

    return {
        "initial": initial,
        "initial_violations": initial_violations,
        "states_reachable": len(distance),
        "states_unsafe": unsafe_states,
        "states_safe": safe_states,
        "nearest_new_violation": nearest_new_violation,
    }


# =====================================================
# Output rendering.
# =====================================================
def render(label: str, result: dict) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {label}")
    print(f"{'=' * 60}")
    initial = result["initial"]
    print(f"\n  initial state: {state_str(initial)}")
    iv = result["initial_violations"]
    if iv:
        print(f"  initial violations ({len(iv)}): {', '.join(iv)}")
    else:
        print("  initial violations: none — invariants hold today")
    print()
    print(f"  reachable states (depth <= 7): {result['states_reachable']}")
    print(f"  unsafe states                 : {result['states_unsafe']}")
    print(f"  safe states                   : {result['states_safe']}")
    print()
    nearest = result["nearest_new_violation"]
    if not iv and not nearest:
        print("  no reachable state violates any invariant within depth 7")
    elif nearest:
        print("  drift margin (min hops to a NEW invariant violation):")
        for inv_name, hops in sorted(nearest.items()):
            print(f"    {inv_name:36s}  {hops} hop(s)")
    else:
        print("  no NEW invariants reachable beyond initial violations")

    if iv:
        verdict = "UNSAFE — invariants violated in the current snapshot"
    elif nearest and min(nearest.values()) <= 2:
        verdict = "AT_RISK — drift margin <= 2 hops"
    else:
        verdict = "SAFE — no nearby unsafe state within depth 7"
    print(f"\n  verdict: {verdict}")


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: temporal_check.py <label> <facts.jsonl>", file=sys.stderr)
        return 2
    label, path = sys.argv[1], Path(sys.argv[2])
    initial = load_initial_state(path)
    result = explore(initial)
    render(label, result)
    return 0


if __name__ == "__main__":
    sys.exit(main())

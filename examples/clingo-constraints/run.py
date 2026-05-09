#!/usr/bin/env python3
"""Run Clingo constraints against a Stave JSONL fact set.

Reads JSONL triples on stdin, lifts each triple to a Clingo
binary fact `predicate("subject", "object").`, then loads the
sibling constraints.lp and prints every grounded violation/2,3
and latent_risk/2 atom.

ASP's stable-model semantics enumerates the complete set of
satisfying ground atoms — the natural shape for "list every
configuration triple that violates a policy." Z3 returns one
witness; ASP returns all of them.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import clingo

# Predicates we lift to Clingo facts. Anything not in this
# list is dropped — it's lifecycle / control metadata that
# the constraints don't reference.
LIFTED_PREDICATES = {
    "has_type", "has_action", "has_resource",
    "trusts_service", "contributed_by",
    "can_assume", "has_tag",
    "allows_unauthenticated", "maps_unauth_to", "maps_auth_to",
    "self_registration_unrestricted",
    # Per-asset boolean projectors (PRs 1, 4, 5). Each one is
    # anchored to a fact predicate that real fixtures already
    # emit. Adding a name here lifts the predicate into Clingo
    # facts; the matching rules live in constraints.lp.
    "has_public_read", "has_public_list",
    "has_public_access_blocked",
    "has_mfa_enforced", "has_advanced_security_enabled",
    "has_logging_enabled", "has_data_event_logging",
    "has_bucket_exists", "has_bucket_owned",
    "has_exposed_repo_artifacts",
    "has_webhook_config_access", "has_uses_access_key_id",
    "has_upload_key_mode",
    "resource_policy_principal", "resource_policy_action",
    "has_condition", "has_condition_value",
    "has_deny_action", "has_deny_resource",
}


def quote_atom(s: str) -> str:
    """Escape a string for use as a Clingo string-literal atom."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def load_facts(jsonl_path: Path) -> list[str]:
    """Convert JSONL triples to Clingo fact strings."""
    facts: list[str] = []
    with jsonl_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            triple = json.loads(line)
            pred = triple.get("predicate", "")
            if pred not in LIFTED_PREDICATES:
                continue
            subj = triple.get("subject", "")
            obj = triple.get("object", "")
            facts.append(f"{pred}({quote_atom(subj)}, {quote_atom(obj)}).")
    return sorted(set(facts))


def solve(facts: list[str], constraints_path: Path) -> tuple[list[clingo.Symbol], list[clingo.Symbol]]:
    """Run Clingo with the given facts + constraints. Return (violations, latents)."""
    ctl = clingo.Control(["--warn=none"])
    ctl.add("facts", [], "\n".join(facts))
    ctl.load(str(constraints_path))
    ctl.ground([("base", []), ("facts", [])])

    violations: list[clingo.Symbol] = []
    latents: list[clingo.Symbol] = []

    def on_model(model: clingo.Model) -> None:
        for atom in model.symbols(shown=True):
            if atom.name == "violation":
                violations.append(atom)
            elif atom.name == "latent_risk":
                latents.append(atom)

    ctl.solve(on_model=on_model)
    return violations, latents


def render(label: str, violations: list[clingo.Symbol], latents: list[clingo.Symbol]) -> None:
    print(f"=== {label} ===")
    if not violations and not latents:
        print("  (clean)")
        print()
        return

    by_kind: dict[str, list[tuple[str, str]]] = {}
    for atom in violations:
        if len(atom.arguments) != 3:
            continue
        subj = atom.arguments[0].string
        kind = atom.arguments[1].string
        obj = atom.arguments[2].string
        by_kind.setdefault(kind, []).append((subj, obj))

    for kind in sorted(by_kind):
        rows = sorted(set(by_kind[kind]))
        print(f"  violation: {kind}  ({len(rows)})")
        for subj, obj in rows:
            print(f"    {subj}  ->  {obj}")

    if latents:
        latent_rows = sorted(
            {(a.arguments[0].string, a.arguments[1].string) for a in latents if len(a.arguments) == 2}
        )
        print(f"  latent_risk  ({len(latent_rows)})")
        for subj, kind in latent_rows:
            print(f"    {subj}  ({kind})")
    print()


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: run.py <label> <facts.jsonl> <constraints.lp>", file=sys.stderr)
        return 2
    label = sys.argv[1]
    jsonl_path = Path(sys.argv[2])
    constraints_path = Path(sys.argv[3])
    facts = load_facts(jsonl_path)
    violations, latents = solve(facts, constraints_path)
    render(label, violations, latents)
    return 0


if __name__ == "__main__":
    sys.exit(main())

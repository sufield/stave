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
    # AI agent (Bedrock) — scalar booleans projected by the
    # propertyAllowlist extension; rules in ai-delegation-shadow.lp.
    "has_agent_guardrail", "has_agent_invocation_logging",
    "has_agent_lambda_scope_broad", "has_agent_s3_scope_broad",
    "has_agent_iac_managed", "has_agent_action_group_count",
    "has_kb_target_bucket", "has_kb_source_encrypted",
    # VPC peering — covers vpc_peering_exposure chain context.
    "has_peering_id", "has_peering_status", "has_peering_peer_in_org",
    "has_peering_dns_resolution", "has_peering_peer_account",
    "has_peering_peer_vpc", "has_peering_route_broad",
    "has_peering_route_target",
    # EC2 instance — covers shadow_ec2_lateral_movement chain.
    "has_instance_state", "has_instance_stopped_aged",
    "has_instance_stopped_age_days", "has_instance_dual_homed",
    "has_instance_profile_overprivileged",
    "has_instance_profile_arn", "has_instance_vpc",
    # IAM role drift / Shadow Admin — scalar + per-element facts.
    "has_role_age_days", "has_access_advisor_available",
    "has_intent_mismatch", "has_declared_role_type",
    "has_incompatible_categories",
    "has_permission_drift_threshold_exceeded",
    "has_unused_service_ratio", "has_total_services_accessible",
    "has_unused_service", "has_incompatible_pair",
    "has_forbidden_category",
    # S3 delegation — scalar + per-principal facts.
    "has_unknown_delegation", "has_delegation_scope_exceeded",
    "has_delegation_review_expired", "has_customer_can_revoke",
    "has_vendor_can_make_public",
    "has_delegation_external_principals",
    "has_vendor_put_bucket_policy",
    "has_delegated_principal", "has_unknown_delegated_principal",
    "has_delegation_scope_exceeded_for",
    # Identity purpose flags (PR 3.6 — purposeFlagFacts over
    # IdentityFact.Properties). Each semicolon-delimited key=value
    # pair on an identity's `purpose` becomes
    # has_purpose_flag(identity, "k=v"). Rule V18 in constraints.lp.
    "has_purpose_flag",
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


def solve(facts: list[str], constraints_paths: list[Path]) -> tuple[list[clingo.Symbol], list[clingo.Symbol]]:
    """Run Clingo with the given facts + constraints. Return (violations, latents).

    Accepts multiple constraint files so the catalog can keep
    domain-specific rule sets in separate .lp files
    (e.g. constraints.lp + ai-delegation-shadow.lp).
    """
    ctl = clingo.Control(["--warn=none"])
    ctl.add("facts", [], "\n".join(facts))
    for path in constraints_paths:
        ctl.load(str(path))
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
        args = atom.arguments
        # Support both violation/2 (subject + kind) and violation/3
        # (subject + kind + object). For arity-2 atoms the third
        # column is empty.
        if len(args) == 3:
            subj, kind, obj = args[0].string, args[1].string, args[2].string
        elif len(args) == 2:
            subj, kind, obj = args[0].string, args[1].string, ""
        else:
            continue
        by_kind.setdefault(kind, []).append((subj, obj))

    for kind in sorted(by_kind):
        rows = sorted(set(by_kind[kind]))
        print(f"  violation: {kind}  ({len(rows)})")
        for subj, obj in rows:
            if obj:
                print(f"    {subj}  ->  {obj}")
            else:
                print(f"    {subj}")

    if latents:
        latent_rows = sorted({
            tuple(a.string for a in atom.arguments)
            for atom in latents
            if len(atom.arguments) in (2, 3)
        })
        print(f"  latent_risk  ({len(latent_rows)})")
        for row in latent_rows:
            if len(row) == 3:
                print(f"    {row[0]}  ({row[1]}: {row[2]})")
            else:
                print(f"    {row[0]}  ({row[1]})")
    print()


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: run.py <label> <facts.jsonl> <constraints.lp> [<more.lp> ...]", file=sys.stderr)
        return 2
    label = sys.argv[1]
    jsonl_path = Path(sys.argv[2])
    constraints_paths = [Path(p) for p in sys.argv[3:]]
    facts = load_facts(jsonl_path)
    violations, latents = solve(facts, constraints_paths)
    render(label, violations, latents)
    return 0


if __name__ == "__main__":
    sys.exit(main())

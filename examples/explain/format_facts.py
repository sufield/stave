#!/usr/bin/env python3
"""
Render a SIR JSONL fact export as a human-readable encoding
report grouped by asset.

Reads the same JSONL `stave export-sir --format jsonl` produces.
Filters out control-catalog facts (has_severity / has_type on
controls themselves; useful for solver consumers, noise for a
human reading what the encoding extracted from observations).

Produces output in the cloud-security domain — predicate names
become human labels ("has_public_read" → "Public read access"),
boolean values become legible interpretations ("true" →
"ENABLED"). The reader can verify "did Stave understand my
configuration?" without reading SMT-LIB or Go.

Usage:
    stave export-sir --format jsonl --observations <obs-dir> 2>/dev/null \
        | python3 format_facts.py
or
    python3 format_facts.py <jsonl-file>

Set FMT_WIDTH or COLUMNS to control line wrapping (default 100).
NO_COLOR=1 disables colors; FORCE_COLOR=1 forces colors when
piping into less / capturing for documentation.
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from typing import Iterable

# Predicate name → human label. Predicates not in this map render
# under their predicate name unchanged so the output is still
# readable when a new projector ships before this table is updated.
PREDICATE_LABELS: dict[str, str] = {
    # Asset identity
    "has_type": "Asset type",
    "has_vendor": "Cloud vendor",
    "first_seen_at": "First seen",
    "last_seen_at": "Last seen",
    "is_provisioned": "Provisioned (declared in IaC)",
    "is_decommissioned": "Decommissioned",

    # Tags / classification
    "has_tag": "Tag",

    # S3 / bucket access surface
    "has_public_read": "Public read access",
    "has_public_list": "Public list access",
    "has_read_via_resource": "Read via resource policy",
    "has_list_via_resource": "List via resource policy",
    "has_public_access_blocked": "PublicAccessBlock fully enforced",
    "has_exposed_repo_artifacts": "Exposes git/repo artifacts",
    "has_bucket_exists": "Referenced bucket exists",
    "has_bucket_owned": "Referenced bucket owned by this account",
    "has_upload_key_mode": "Upload key scope",

    # IAM / policy
    "has_action": "IAM action allowed",
    "has_permission_action": "Granted action",
    "has_permission_resource": "Granted resource",
    "has_privilege_level": "Privilege level",
    "has_resource": "Resource scope",
    "has_deny_action": "Deny statement covers action",
    "has_deny_resource": "Deny statement covers resource",
    "has_condition": "Policy condition",
    "has_condition_value": "Policy condition value",
    "has_severity": "Severity",
    "resource_policy_principal": "Resource policy admits principal",
    "resource_policy_action": "Resource policy admits action",
    "trusts_service": "Trusts AWS service",
    "can_assume": "Can assume role",
    "cross_account_assumes": "Cross-account assume-role",

    # Cognito
    "allows_unauthenticated": "Unauthenticated (guest) access",
    "maps_unauth_to": "Maps unauthenticated users to",
    "maps_auth_to": "Maps authenticated users to",
    "has_mfa_enforced": "MFA enforcement",
    "has_advanced_security_enabled": "Advanced security mode",
    "self_registration_unrestricted": "Self-registration unrestricted",
    "has_ghost_trigger": "Ghost trigger reference (Lambda missing)",
    "has_trigger_type": "Trigger type",
    "has_trigger_lambda_exists": "Trigger Lambda exists",

    # CloudTrail / monitoring
    "has_logging_enabled": "Logging enabled",
    "has_data_event_logging": "Data-event logging covers",

    # EKS / Kubernetes
    "has_webhook_config_access": "Webhook can write configs",
    "has_uses_access_key_id": "Maps identities by access key id",

    # Chain / temporal
    "has_exposure_window": "Has open exposure window",
    "contributed_by": "Exposure contributed by control",
    "has_forbidden_state": "Carries forbidden_state invariant",
    "has_intent_rationale": "Has intent rationale",
}

# Object value → legible interpretation. Only common scalars here;
# everything else passes through as-is.
VALUE_LABELS: dict[str, str] = {
    "true": "ENABLED",
    "false": "DISABLED",
    "*": "* (ANY — unrestricted)",
    "AES256": "AES256 (SSE-S3 server-side keys)",
    "aws:kms": "aws:kms (KMS-managed keys)",
}

# Sources we render as the "encoding" — facts derived from
# observations, not from the catalog. Control-record facts
# (has_severity etc. with subject=control_id) describe the
# catalog itself and aren't what the human is verifying here.
ENCODING_SOURCES = {"asset", "tag", "lifecycle", "exposure", "provisioning", "policy"}


# ---- TTY-aware color helpers ----

def _color_enabled() -> bool:
    if os.environ.get("FORCE_COLOR") == "1":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


_COLOR = _color_enabled()
_BOLD = "\x1b[1m" if _COLOR else ""
_DIM = "\x1b[2m" if _COLOR else ""
_RED = "\x1b[31m" if _COLOR else ""
_GREEN = "\x1b[32m" if _COLOR else ""
_YELLOW = "\x1b[33m" if _COLOR else ""
_CYAN = "\x1b[36m" if _COLOR else ""
_RESET = "\x1b[0m" if _COLOR else ""


def _label_predicate(predicate: str) -> str:
    return PREDICATE_LABELS.get(predicate, predicate)


def _label_value(value: str) -> str:
    return VALUE_LABELS.get(value, value)


def _value_color(predicate: str, value: str) -> str:
    """Color the value by safety direction where it makes sense.

    Boolean predicates that name a permissive/unsafe shape — public
    read, unauthenticated access, ghost references — render their
    "true" red and "false" green. Predicates that name a *protective*
    state — PAB enforcement, MFA, encryption — invert.
    """
    if not _COLOR:
        return ""
    permissive_predicates = {
        "has_public_read", "has_public_list", "has_read_via_resource",
        "has_list_via_resource", "has_exposed_repo_artifacts",
        "allows_unauthenticated", "has_ghost_trigger",
        "is_decommissioned",
    }
    protective_predicates = {
        "has_public_access_blocked", "has_mfa_enforced",
        "has_logging_enabled", "has_advanced_security_enabled",
        "has_bucket_exists", "has_bucket_owned",
        "has_trigger_lambda_exists", "is_provisioned",
        "self_registration_unrestricted",  # name says unrestricted; true=permissive
    }
    if value == "true":
        if predicate in permissive_predicates:
            return _RED
        if predicate in protective_predicates:
            return _GREEN
    elif value == "false":
        if predicate in permissive_predicates:
            return _GREEN
        if predicate in protective_predicates:
            return _RED
    return ""


# ---- Rendering ----

def _load_jsonl(stream: Iterable[str]) -> list[dict]:
    out: list[dict] = []
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _is_encoding_fact(fact: dict) -> bool:
    return fact.get("source") in ENCODING_SOURCES


def _asset_type_label(facts: list[dict]) -> str:
    """Pick the asset type for the header line."""
    for f in facts:
        if f.get("predicate") == "has_type":
            t = f.get("object", "")
            return f" ({t})" if t else ""
    return ""


def _format_provenance(fact: dict) -> str:
    """Compose the source line: which observation property the fact came from."""
    prov = fact.get("provenance") or {}
    path = prov.get("property_path", "?")
    projector = prov.get("projector", "")
    evidence = fact.get("evidence", "")
    if evidence and evidence != path:
        return f"{evidence} (path: {path})"
    if projector and projector != "controlFacts":
        return f"{path} [projector: {projector}]"
    return path


def render(facts: list[dict]) -> str:
    encoding_facts = [f for f in facts if _is_encoding_fact(f)]
    by_subject: dict[str, list[dict]] = defaultdict(list)
    for f in encoding_facts:
        by_subject[f.get("subject", "")].append(f)
    asset_count = len(by_subject)
    fact_count = len(encoding_facts)

    lines: list[str] = []
    lines.append(
        f"{_BOLD}{_CYAN}Configuration Summary:{_RESET} "
        f"{asset_count} asset(s), {fact_count} encoded fact(s) "
        f"{_DIM}(non-control records from the SIR){_RESET}"
    )
    if not by_subject:
        lines.append(f"  {_DIM}No encoding facts in the JSONL — only catalog records present.{_RESET}")
        return "\n".join(lines) + "\n"

    # Stable subject order for golden-friendly output.
    for subject in sorted(by_subject):
        subject_facts = by_subject[subject]
        # Show identity facts first (has_type, has_vendor) so the
        # asset header reads like a sentence; the remaining facts
        # follow in stable predicate order.
        identity_preds = ("has_type", "has_vendor")
        identity = [f for f in subject_facts if f.get("predicate") in identity_preds]
        rest = [f for f in subject_facts if f.get("predicate") not in identity_preds]
        rest.sort(key=lambda f: (f.get("predicate", ""), f.get("object", "")))

        type_suffix = _asset_type_label(identity)
        lines.append("")
        lines.append(
            f"{_BOLD}Asset:{_RESET} {subject}{_DIM}{type_suffix}{_RESET}"
        )
        ordered = identity + rest
        for i, f in enumerate(ordered):
            is_last = i == len(ordered) - 1
            stem = "└──" if is_last else "├──"
            cont = "    " if is_last else "│   "
            label = _label_predicate(f.get("predicate", ""))
            value = f.get("object", "")
            display_value = _label_value(value)
            color = _value_color(f.get("predicate", ""), value)
            lines.append(
                f"  {stem} {_BOLD}{label}:{_RESET} "
                f"{color}{display_value}{_RESET}"
                f"  {_DIM}fact_id: {f.get('fact_id', '?')[:12]}{_RESET}"
            )
            source = _format_provenance(f)
            lines.append(f"  {cont}  {_DIM}Source: {source}{_RESET}")
    return "\n".join(lines) + "\n"


def main() -> int:
    if len(sys.argv) > 2:
        print("usage: format_facts.py [<jsonl-file>]", file=sys.stderr)
        return 2
    if len(sys.argv) == 2:
        with open(sys.argv[1]) as f:
            facts = _load_jsonl(f)
    else:
        facts = _load_jsonl(sys.stdin)
    sys.stdout.write(render(facts))
    return 0


if __name__ == "__main__":
    sys.exit(main())

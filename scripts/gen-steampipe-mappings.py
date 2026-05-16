#!/usr/bin/env python3
"""Generate Steampipe → Stave mapping YAMLs by joining the Steampipe
column catalog with each per-asset JSON Schema's property paths.

Inputs:
  - scripts/steampipe-columns.json
      Cached column catalog. Refresh with:
        steampipe query "select table_name, column_name, data_type
                         from information_schema.columns
                         where table_schema = 'aws'" --output json

  - schemas/observation/v1/asset-types/<type>.schema.json
      The per-asset target contract. Drives the candidate Stave
      property paths.

  - contracts/steampipe/<type>.yaml (optional, when --skip-existing)
      Hand-authored ground truth. Validated against, never overwritten.

Outputs:
  - One YAML per asset type under --output (default contracts/steampipe/)
  - Each output carries `_auto_generated: true` and
    `_review_required: N` so reviewers can sort by attention needed.

Matching strategy (best-effort, name-based only):
  1. Exact match on the column name vs the leaf segment of the path
     (case-insensitive, snake_case normalised)
  2. Compound-path match: column "block_public_acls" vs path ending in
     ".block_public_acls"
  3. Steampipe convention map: arn -> id, tags_src -> tags
  4. Anything unmatched is recorded in `_unmatched_columns` and
     `_unmatched_paths` so review work is bounded.

The output YAML uses the same operations-list shape the Iter 1 loader
already consumes. Field operations are emitted in alphabetical
column order — agents that need a specific output key ordering must
re-author.

Usage:
  python3 scripts/gen-steampipe-mappings.py --output contracts/steampipe/
  python3 scripts/gen-steampipe-mappings.py --validate-against contracts/steampipe/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

# Vendor / type-namespace metadata. Drives the static_kind value
# stamped on every emitted YAML so observations carry a stable
# `properties.<namespace>.kind` string the catalog reads.
NAMESPACE_BY_PREFIX = {
    "aws_s3_": "storage",
    "aws_iam_role": "identity",
    "aws_iam_user": "identity",
    "aws_iam_": "identity",
    "aws_cognito_": "identity",
    "aws_lambda_": "compute",
    "aws_ec2_instance": "compute",
    "aws_eks_": "compute",
    "aws_sfn_": "compute",
    "aws_stepfunctions_": "compute",
    "aws_kms_": "cryptography",
    "aws_cloudtrail_": "audit",
    "aws_cloudwatch_": "audit",
    "aws_guardduty_": "audit",
    "aws_securityhub_": "audit",
    "aws_sqs_": "messaging",
    "aws_sns_": "messaging",
    "aws_eventbridge_": "messaging",
    "aws_opensearch_": "search_service",
    "aws_vpc": "network",
    "aws_ec2_security_group": "network",
    "aws_rds_": "database",
    "aws_dynamodb_": "database",
    "aws_ebs_": "storage",
    "aws_dlm_": "storage",
    "aws_route53_": "dns_service",
    "aws_acm_": "cryptography",
}

# Steampipe table -> Stave asset_type. The plugin's table name and
# Stave's asset_type don't always match (Step Functions are the
# canonical example — aws_sfn_state_machine vs
# aws_stepfunctions_state_machine).
TABLE_OVERRIDES = {
    "aws_sfn_state_machine": "aws_stepfunctions_state_machine",
    "aws_vpc_security_group": "aws_ec2_security_group",
}

# Columns that exist on every Steampipe AWS table but are metadata
# rather than asset state. Skip them during matching.
NOISE_COLUMNS = {
    "_ctx", "sp_connection_name", "sp_ctx", "akas", "title", "partition",
    "account_id", "region",  # context, not state
    "tags",  # tags_src is the canonical column; "tags" is the formatted view
    "policy_std", "inline_policies_std", "assume_role_policy_std",  # *_std are convenience parses
}


def load_columns_catalog(path: Path) -> dict[str, list[str]]:
    """Load the cached column catalog. Returns map of table_name -> columns."""
    data = json.loads(path.read_text())
    out: dict[str, list[str]] = {}
    for table_name, table in data.get("tables", {}).items():
        out[table_name] = list(table.get("columns", []))
    return out


def load_schema_paths(schema_dir: Path, asset_type: str) -> list[str]:
    """Return the dotted property paths declared in the per-asset schema."""
    p = schema_dir / f"{asset_type}.schema.json"
    if not p.exists():
        return []
    schema = json.loads(p.read_text())
    return _walk_schema(schema)


def _walk_schema(node: Any, prefix: str = "") -> list[str]:
    out: list[str] = []
    if not isinstance(node, dict):
        return out
    props = node.get("properties")
    if not isinstance(props, dict):
        return out
    for k, v in props.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict) and isinstance(v.get("properties"), dict):
            out.extend(_walk_schema(v, path))
        else:
            out.append(path)
    return out


def namespace_for(asset_type: str) -> str:
    for prefix, ns in NAMESPACE_BY_PREFIX.items():
        if asset_type.startswith(prefix):
            return ns
    return "asset"


def kind_value_for(asset_type: str) -> str:
    """The static `kind` value the YAML stamps on properties.<ns>.kind."""
    return asset_type.removeprefix("aws_")


# Per-asset-type column → path overrides for fields the naming
# convention doesn't get right on its own. Each entry says "for
# this Steampipe column on this asset type, the canonical Stave
# property path is X." Populated empirically from the 11
# hand-authored mappings in contracts/steampipe/.
COLUMN_OVERRIDES: dict[str, dict[str, str]] = {
    "aws_iam_role": {
        "name": "properties.identity.role_name",
        "assume_role_policy_document": "properties.identity.trust_policy.raw",
    },
    "aws_iam_user": {
        "name": "properties.identity.user_name",
        "login_profile": "properties.identity.console_access.enabled",
    },
    "aws_cognito_user_pool": {
        "id": "properties.identity.cognito.id",
        "name": "properties.identity.cognito.name",
        "creation_date": "properties.identity.cognito.creation_date",
        "last_modified_date": "properties.identity.cognito.last_modified_date",
        "estimated_number_of_users": "properties.identity.cognito.estimated_number_of_users",
        "region": "properties.identity.cognito.region",
    },
    "aws_lambda_function": {
        "role": "properties.compute.execution_role.arn",
        "kms_key_arn": "properties.compute.env.kms_key_id",
        "code_signing_config_arn": "properties.compute.code_signing.config_arn_set",
    },
    "aws_cloudtrail_trail": {
        "is_multi_region_trail": "properties.audit.cloudtrail.is_multi_region",
        "is_logging": "properties.audit.cloudtrail.is_logging",
        "log_file_validation_enabled": "properties.audit.cloudtrail.log_file_validation_enabled",
        "include_global_service_events": "properties.audit.cloudtrail.include_global_events",
        "s3_bucket_name": "properties.audit.cloudtrail.s3_bucket_name",
        "kms_key_id": "properties.audit.cloudtrail.kms_key_id",
        "log_group_arn": "properties.audit.cloudtrail.cloud_watch_logs_log_group_arn",
        "cloud_watch_logs_role_arn": "properties.audit.cloudtrail.cloud_watch_logs_role_arn",
        "sns_topic_arn": "properties.audit.cloudtrail.sns_topic_arn",
    },
    "aws_kms_key": {
        "id": "properties.cryptography.key_id",
        "key_manager": "properties.cryptography.is_aws_managed",
        "enabled": "properties.cryptography.is_disabled",
        "key_rotation_enabled": "properties.cryptography.rotation.enabled",
        "creation_date": "properties.cryptography.creation_date",
        "deletion_date": "properties.cryptography.deletion_date",
        "key_state": "properties.cryptography.key_state",
        "policy": "properties.cryptography.policy.raw",
    },
    "aws_ec2_instance": {
        "instance_id": "properties.compute.instance.id",
        "instance_type": "properties.compute.instance.type",
        "instance_state": "properties.compute.instance.state",
        "launch_time": "properties.compute.instance.launch_time",
        "image_id": "properties.compute.ami.id",
        "key_name": "properties.compute.instance.has_key_pair",
        "iam_instance_profile_arn": "properties.compute.iam_instance_profile.arn",
    },
    "aws_sqs_queue": {
        "queue_arn": "properties.messaging.id",
        "queue_url": "properties.messaging.url",
        "kms_master_key_id": "properties.messaging.sqs.kms_key_id",
        "message_retention_seconds": "properties.messaging.sqs.message_retention_period",
        "visibility_timeout_seconds": "properties.messaging.sqs.visibility_timeout",
        "policy": "properties.messaging.policy.raw",
        "redrive_policy": "properties.messaging.sqs.redrive_policy_raw",
    },
    "aws_opensearch_domain": {
        "domain_name": "properties.search_service.name",
        "access_policies": "properties.search_service.access.policy.raw",
        "region": "properties.search_service.region",
    },
    "aws_stepfunctions_state_machine": {
        "definition": "properties.compute.asl.raw",
        "type": "properties.compute.asl.type",
        "role_arn": "properties.compute.execution_role.arn",
        "tracing_configuration": "properties.compute.tracing_config",
    },
    "aws_s3_bucket": {
        "tags": "properties.storage.tags",  # Iter 1 mapping uses `tags` not `tags_src`
    },
}


def _prefix(path: str) -> str:
    """Ensure every emitted path starts with `properties.`. Schema paths
    are stored without it; hand-authored YAMLs include it; the loader
    expects it. Normalise here so the generator's output matches what
    the loader (and the validation step) expects."""
    if not path:
        return path
    if path.startswith("properties."):
        return path
    return f"properties.{path}"


def _best_candidate_for_column(col_norm: str, paths: list[str]) -> str:
    """Score every schema path against the column's word tokens; return
    the path with the highest segment-overlap. Disambiguates leaf
    collisions like `enabled` (versioning.enabled vs logging.enabled)
    by preferring the path whose middle segments also share tokens
    with the column name."""
    col_tokens = set(col_norm.split("_"))
    best_path = ""
    best_score = -1
    for p in paths:
        path_tokens = set(p.lower().replace(".", "_").split("_"))
        score = len(col_tokens & path_tokens)
        # Tiebreak on shorter (more specific) path
        if score > best_score or (score == best_score and best_path and len(p) < len(best_path)):
            best_score = score
            best_path = p
    return best_path if best_score > 0 else ""


def match_columns(asset_type: str, columns: list[str], paths: list[str]
                  ) -> tuple[dict[str, str], list[str], list[str]]:
    """Return (column -> path map, unmatched columns, unmatched paths).

    Matching order, first hit wins:
      1. Per-asset-type override (COLUMN_OVERRIDES)
      2. Schema-path lookup via leaf / two-segment / flat normalisation
      3. Naming convention: column `foo_bar` -> `properties.<ns>.foo_bar`
         (covers identity/context fields the catalog doesn't read but
         every observation surfaces — name, region, create_date, etc.)
    """
    ns = namespace_for(asset_type)
    overrides = COLUMN_OVERRIDES.get(asset_type, {})

    # Build a lookup from normalised candidate keys -> the original
    # path.
    candidates: dict[str, str] = {}
    for path in paths:
        segs = path.split(".")
        leaf = segs[-1].lower()
        candidates.setdefault(leaf, path)
        if len(segs) >= 2:
            two = "_".join(segs[-2:]).lower()
            candidates.setdefault(two, path)
        flat = path.replace(".", "_").lower()
        candidates.setdefault(flat, path)

    field_map: dict[str, str] = {}
    unmatched_cols: list[str] = []
    for col in columns:
        norm = col.replace("-", "_").lower()
        # Overrides win over the NOISE filter so per-asset rewrites
        # (like s3's `tags` -> properties.storage.tags) take effect.
        if col in overrides:
            field_map[col] = _prefix(overrides[col])
            continue
        if col in NOISE_COLUMNS:
            continue
        if norm == "arn":
            continue  # asset id, set separately via asset_id_column
        if norm in candidates:
            # Prefer a candidate whose later segments contain the
            # column name (e.g. column "versioning_enabled" should
            # prefer "storage.versioning.enabled" over
            # "storage.logging.enabled" even though both have leaf
            # "enabled").
            field_map[col] = _prefix(_best_candidate_for_column(norm, paths) or candidates[norm])
            continue
        if norm == "tags_src":
            field_map[col] = f"properties.{ns}.tags"
            continue
        # Convention fallback: every column emits properties.<ns>.<col>
        # so identity/context fields land at predictable paths.
        field_map[col] = f"properties.{ns}.{norm}"

    matched_paths = set(field_map.values())
    unmatched_paths = [p for p in paths if p not in matched_paths]
    # No column went unmatched after the convention fallback — every
    # column lands somewhere. Keep the empty list as a stable shape.
    unmatched_cols = []
    return field_map, unmatched_cols, unmatched_paths


def pick_asset_id_column(columns: list[str]) -> str:
    """Choose the Steampipe column that names the asset's ARN.
    Prefer the plain `arn` column when present; fall back to any
    column ending in `_arn` (topic_arn, queue_arn, etc.)."""
    if "arn" in columns:
        return "arn"
    for c in columns:
        if c.endswith("_arn"):
            return c
    return "arn"  # last-ditch default


def emit_yaml(asset_type: str, table_name: str, field_map: dict[str, str],
              unmatched_cols: list[str], unmatched_paths: list[str],
              asset_id_column: str = "arn") -> str:
    """Render the YAML for one asset type. Uses the operations-list
    schema that the Iter 1 loader (examples/agents/stave_transform.py)
    already consumes."""
    ns = namespace_for(asset_type)
    kind = kind_value_for(asset_type)
    review_required = len(unmatched_cols) + len(unmatched_paths)

    lines: list[str] = []
    lines.append(f"# Auto-generated by scripts/gen-steampipe-mappings.py.")
    lines.append(f"# Review before promoting to ground truth: drop the")
    lines.append(f"# _auto_generated, _unmatched_* and _review_required keys")
    lines.append(f"# once a human has validated this file.")
    lines.append(f"asset_type: {asset_type}")
    lines.append(f"steampipe_table: {table_name}")
    lines.append(f"schema_version: obs.v0.1")
    lines.append("")
    lines.append(f"asset_id_column: {asset_id_column}")
    lines.append(f"vendor: aws")
    lines.append("")
    lines.append(f"_auto_generated: true")
    lines.append(f"_review_required: {review_required}")
    if unmatched_cols:
        lines.append("_unmatched_columns:")
        for c in sorted(unmatched_cols):
            lines.append(f"  - {c}")
    else:
        lines.append("_unmatched_columns: []")
    if unmatched_paths:
        lines.append("_unmatched_paths:")
        for p in sorted(unmatched_paths):
            lines.append(f"  - {p}")
    else:
        lines.append("_unmatched_paths: []")
    lines.append("")
    lines.append("operations:")
    lines.append(f"  - kind: static")
    lines.append(f"    path: properties.{ns}.kind")
    lines.append(f"    value: {kind}")
    lines.append("")
    lines.append(f"  - kind: field")
    lines.append(f"    path: properties.{ns}.id")
    lines.append(f"    column: {asset_id_column}")
    lines.append(f"    use_asset_id: true")

    # Emit field operations in alphabetical column order for stable
    # diffs.
    for col in sorted(field_map.keys()):
        path = field_map[col]
        lines.append("")
        lines.append(f"  - kind: field")
        lines.append(f"    path: {path}")
        lines.append(f"    column: {col}")

    lines.append("")
    return "\n".join(lines)


def parse_existing(yaml_path: Path) -> dict[str, str]:
    """Read a hand-authored or generated YAML, return its (column -> path)
    map across field + extract operations."""
    with yaml_path.open() as fh:
        data = yaml.safe_load(fh)
    out: dict[str, str] = {}
    for op in (data or {}).get("operations") or []:
        if op.get("kind") in ("field", "extract"):
            col = op.get("column")
            path = op.get("path")
            if col and path:
                # If a column appears twice (e.g. one field + one extract),
                # keep the first.
                out.setdefault(col, path)
    return out


def validate(generated: dict[str, str], hand: dict[str, str]) -> dict[str, float]:
    """Compare generated and hand-authored field maps. Returns accuracy stats."""
    g = set(generated.items())
    h = set(hand.items())
    correct = g & h
    only_g = g - h
    only_h = h - g
    accuracy = len(correct) / max(len(h), 1)
    return {
        "correct": len(correct),
        "auto_only": len(only_g),
        "manual_only": len(only_h),
        "manual_total": len(h),
        "accuracy": accuracy,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--columns", type=Path, default=Path("scripts/steampipe-columns.json"))
    ap.add_argument("--schemas", type=Path, default=Path("schemas/observation/v1/asset-types"))
    ap.add_argument("--output", type=Path, default=Path("contracts/steampipe"))
    ap.add_argument("--skip-existing", action="store_true",
                    help="Do not overwrite YAMLs that already exist under --output")
    ap.add_argument("--validate-against", type=Path,
                    help="Compare generator output against the hand-authored YAMLs in this directory; no files are written")
    ap.add_argument("--asset-type", help="Generate only this asset type")
    args = ap.parse_args()

    if not args.columns.exists():
        print(f"ERROR: column catalog not found at {args.columns}", file=sys.stderr)
        return 2
    columns_by_table = load_columns_catalog(args.columns)

    # Validation mode: do not write files.
    if args.validate_against:
        return run_validation(args, columns_by_table)

    args.output.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    for table_name, columns in sorted(columns_by_table.items()):
        asset_type = TABLE_OVERRIDES.get(table_name, table_name)
        if args.asset_type and asset_type != args.asset_type:
            continue
        out_path = args.output / f"{asset_type}.yaml"
        if out_path.exists() and args.skip_existing:
            skipped += 1
            continue
        paths = load_schema_paths(args.schemas, asset_type)
        if not paths:
            print(f"  skip {asset_type}: no per-asset schema at {args.schemas}/{asset_type}.schema.json",
                  file=sys.stderr)
            continue
        field_map, unmatched_cols, unmatched_paths = match_columns(asset_type, columns, paths)
        id_col = pick_asset_id_column(columns)
        # Drop the id column from field_map: it's the asset id, set via
        # asset_id_column, not a property field of its own. Without this
        # the column would also surface as `properties.<ns>.<id_col>`
        # via the convention fallback.
        field_map.pop(id_col, None)
        out_path.write_text(emit_yaml(asset_type, table_name, field_map,
                                       unmatched_cols, unmatched_paths,
                                       asset_id_column=id_col))
        written += 1
        print(f"  wrote {out_path} ({len(field_map)} fields, {len(unmatched_cols)} unmatched cols, {len(unmatched_paths)} unmatched paths)")

    print(f"\nGenerated: {written}, skipped existing: {skipped}")
    return 0


def run_validation(args: argparse.Namespace, columns_by_table: dict[str, list[str]]) -> int:
    """Compare auto-generated mappings against hand-authored ones."""
    overall_correct = 0
    overall_manual = 0
    per_type: list[dict[str, Any]] = []
    for ym in sorted(args.validate_against.glob("*.yaml")):
        hand = parse_existing(ym)
        with ym.open() as fh:
            doc = yaml.safe_load(fh) or {}
        asset_type = doc.get("asset_type")
        table_name = doc.get("steampipe_table")
        if not asset_type or not table_name or table_name not in columns_by_table:
            continue
        columns = columns_by_table[table_name]
        paths = load_schema_paths(args.schemas, asset_type)
        if not paths:
            continue
        generated, _, _ = match_columns(asset_type, columns, paths)
        stats = validate(generated, hand)
        per_type.append({"asset_type": asset_type, **stats})
        overall_correct += stats["correct"]
        overall_manual += stats["manual_total"]
        print(f"  {asset_type}: {stats['correct']}/{stats['manual_total']} "
              f"(accuracy {stats['accuracy']:.0%}, auto_only {stats['auto_only']}, "
              f"manual_only {stats['manual_only']})")
    if overall_manual == 0:
        print("\nNo hand-authored mappings to validate against.")
        return 0
    overall = overall_correct / overall_manual
    print(f"\nOverall: {overall_correct}/{overall_manual} = {overall:.0%} accuracy across {len(per_type)} type(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

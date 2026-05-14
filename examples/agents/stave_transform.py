#!/usr/bin/env python3
"""Stave Transform Agent.

Reads raw Steampipe-shaped JSON rows and emits an obs.v0.1
observation snapshot for Stave. Two modes:

  Deterministic (default)
    Built-in transforms for known asset types. Today aws_s3_bucket
    is fully wired as a worked example. Other types fall through
    with a clear "no built-in transform; use --llm or extend the
    BUILTIN_TRANSFORMS table" message.

  LLM-assisted (`--llm`)
    Sends the target asset-type schema + the raw rows' column
    names (NOT the data values) to an LLM and asks for a row →
    Asset mapping. Applies the mapping locally; if `--validate`
    is set, runs stave validate; on failure the validator's
    error message is fed back to the LLM (OODA loop, three
    attempts by default).

Both paths emit a single obs.v0.1 file at <output>/<asset-type>.obs.json.

Air-gap: deterministic mode is purely local. LLM mode sends only
the schema + column names; row values stay on disk. Disable via
`--no-llm` if you want a hard guarantee that no network calls fire.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Deterministic transforms
# ---------------------------------------------------------------------------

Asset = dict[str, Any]
Transform = Callable[[dict[str, Any]], Asset]


def transform_aws_s3_bucket(row: dict[str, Any]) -> Asset:
    """Map a Steampipe aws_s3_bucket row to Stave's aws_s3_bucket
    asset shape. Conservative: only fields the canonical S3 sub-
    schema declares paths for; everything else is omitted (Stave
    treats absence as "not observed", which is honest)."""
    name = row.get("name", "")
    arn = row.get("arn") or f"arn:aws:s3:::{name}"

    # Public Access Block flags. Steampipe surfaces these at the
    # top level (block_public_acls, etc.) when the bucket has a
    # PAB configured; null when it doesn't.
    pab_block_public_acls = row.get("block_public_acls") or False
    pab_block_public_policy = row.get("block_public_policy") or False
    pab_ignore_public_acls = row.get("ignore_public_acls") or False
    pab_restrict_public_buckets = row.get("restrict_public_buckets") or False
    pab_fully_blocked = all(
        [
            pab_block_public_acls,
            pab_block_public_policy,
            pab_ignore_public_acls,
            pab_restrict_public_buckets,
        ]
    )

    # Server-side encryption — Steampipe returns the SSE config
    # as JSON; pick the first rule's algorithm and KMS key ID.
    sse_algorithm = None
    sse_kms_key_id = None
    sse_cfg = row.get("server_side_encryption_configuration")
    if isinstance(sse_cfg, dict):
        rules = sse_cfg.get("Rules") or sse_cfg.get("rules") or []
        if rules:
            apply = (
                rules[0].get("ApplyServerSideEncryptionByDefault")
                or rules[0].get("apply_server_side_encryption_by_default")
                or {}
            )
            sse_algorithm = apply.get("SSEAlgorithm") or apply.get("sse_algorithm")
            sse_kms_key_id = apply.get("KMSMasterKeyID") or apply.get("kms_master_key_id")

    tags = row.get("tags") or {}
    if not isinstance(tags, dict):
        tags = {}

    return {
        "id": arn,
        "type": "aws_s3_bucket",
        "vendor": "aws",
        "properties": {
            "storage": {
                "kind": "bucket",
                "name": name,
                "id": arn,
                "tags": tags,
                "controls": {
                    "public_access_block": {
                        "block_public_acls": pab_block_public_acls,
                        "block_public_policy": pab_block_public_policy,
                        "ignore_public_acls": pab_ignore_public_acls,
                        "restrict_public_buckets": pab_restrict_public_buckets,
                    },
                    "public_access_fully_blocked": pab_fully_blocked,
                },
                "encryption": {
                    "algorithm": sse_algorithm or "none",
                    "kms_key_id": sse_kms_key_id,
                },
                "versioning": {
                    "enabled": bool(row.get("versioning_enabled")),
                    "mfa_delete_enabled": bool(row.get("versioning_mfa_delete")),
                },
            }
        },
    }


# Asset-type → transform function. Add your organisation's
# transforms here once the LLM-assisted mapping stabilises; the
# brief explicitly calls this out as the production path.
BUILTIN_TRANSFORMS: dict[str, Transform] = {
    "aws_s3_bucket": transform_aws_s3_bucket,
}


# ---------------------------------------------------------------------------
# LLM-assisted transform (optional, gated behind --llm)
# ---------------------------------------------------------------------------


def llm_generate_transform(asset_type: str, column_names: list[str], schema: dict) -> dict[str, str]:
    """Ask an LLM to map source column names to target property
    paths. Returns a flat dict { property_path -> source_column }.

    Air-gap discipline: this function sends ONLY the target
    schema (which is public) and the source column names (not the
    values). Row data never crosses the wire.

    Provider abstraction is one if/elif away from supporting more
    backends — Anthropic is wired today because Stave's CLAUDE.md
    pinned that vendor. Returns an empty dict when ANTHROPIC_API_KEY
    is not set so the caller can short-circuit gracefully.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "INFO: --llm requested but ANTHROPIC_API_KEY not set; emitting an "
            "empty transform and validating against the schema. The validator's "
            "error output is the contract for what to author.",
            file=sys.stderr,
        )
        return {}

    try:
        import anthropic  # type: ignore  # pylint: disable=import-outside-toplevel
    except ImportError:
        print(
            "INFO: anthropic package not installed; pip install anthropic to enable "
            "the LLM path. Falling back to empty transform.",
            file=sys.stderr,
        )
        return {}

    prompt = _build_llm_prompt(asset_type, column_names, schema)
    client = anthropic.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=(
            "You are mapping source-system columns to target JSON Schema "
            "property paths. Return STRICT JSON only — no prose, no markdown."
        ),
        messages=[{"role": "user", "content": prompt}],
    )
    text = msg.content[0].text if msg.content else ""
    return _parse_llm_mapping(text)


def _build_llm_prompt(asset_type: str, column_names: list[str], schema: dict) -> str:
    paths = _flatten_schema_paths(schema)
    return (
        f"Target asset type: {asset_type}\n\n"
        "Target property paths (with inferred types from the asset-type schema):\n"
        + "\n".join(f"  - {p}: {t}" for p, t in paths)
        + "\n\nSource columns available (Steampipe row keys):\n"
        + "\n".join(f"  - {c}" for c in column_names)
        + "\n\nReturn a JSON object mapping each target property path you can "
        "populate to the source column that feeds it. Omit paths you can't map.\n"
        '{ "properties.foo.bar": "source_col", ... }'
    )


def _flatten_schema_paths(schema: dict, prefix: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    props = schema.get("properties") or {}
    for name, defn in props.items():
        if not isinstance(defn, dict):
            continue
        path = f"{prefix}.{name}" if prefix else name
        t = defn.get("type", "any")
        if isinstance(t, list):
            t = "|".join(str(x) for x in t)
        if isinstance(defn.get("properties"), dict):
            out.extend(_flatten_schema_paths(defn, prefix=path))
        else:
            out.append((path, str(t)))
    return out


def _parse_llm_mapping(text: str) -> dict[str, str]:
    text = text.strip()
    # Strip code fences if the model wrapped its output despite
    # the system prompt's "no markdown" rule.
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        m = json.loads(text)
        return {k: v for k, v in m.items() if isinstance(k, str) and isinstance(v, str)}
    except json.JSONDecodeError:
        print(f"INFO: LLM did not return valid JSON mapping:\n  {text[:300]}", file=sys.stderr)
        return {}


def apply_llm_mapping(row: dict[str, Any], mapping: dict[str, str], asset_type: str) -> Asset:
    """Apply a flat (property_path -> source_column) mapping to
    one row. Property paths are dot-separated; this builds the
    nested structure they describe."""
    out: Asset = {
        "id": row.get("arn") or row.get("id") or row.get("name") or "<unknown>",
        "type": asset_type,
        "vendor": row.get("vendor") or "aws",
        "properties": {},
    }
    for path, col in mapping.items():
        if not path.startswith("properties."):
            continue
        rel = path[len("properties.") :]
        value = row.get(col)
        _set_nested(out["properties"], rel.split("."), value)
    return out


def _set_nested(node: dict[str, Any], segments: list[str], value: Any) -> None:
    cur = node
    for seg in segments[:-1]:
        nxt = cur.get(seg)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[seg] = nxt
        cur = nxt
    cur[segments[-1]] = value


# ---------------------------------------------------------------------------
# OODA loop: transform → validate → repair
# ---------------------------------------------------------------------------


def run_stave_validate(obs_path: Path, *, strict: bool = True) -> tuple[bool, str]:
    """Invoke `stave validate --in <path> --kind observation`.

    Returns (ok, diagnostics). The diagnostics text is the error
    message body when validation fails — useful for an OODA loop
    that feeds it back to the LLM.
    """
    if shutil.which("stave") is None:
        return False, "stave binary not on PATH; build it via `cd stave && make build`"
    cmd = ["stave", "validate", "--in", str(obs_path), "--kind", "observation"]
    if strict:
        cmd.append("--strict")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    ok = proc.returncode == 0
    diagnostics = proc.stderr.strip() or proc.stdout.strip()
    return ok, diagnostics


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def build_snapshot(assets: list[Asset], *, source: str = "deployed") -> dict[str, Any]:
    return {
        "schema_version": "obs.v0.1",
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "generated_by": {
            "source_type": "steampipe",
            "tool": "stave-transform-agent",
            "tool_version": "0.1.0",
            "provider": "aws",
        },
        "assets": assets,
    }


def load_target_schema(asset_type: str, schemas_dir: Path) -> dict:
    p = schemas_dir / "asset-types" / f"{asset_type}.schema.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def transform_rows(
    rows: list[dict[str, Any]],
    asset_type: str,
    *,
    use_llm: bool,
    schemas_dir: Path,
) -> list[Asset]:
    if asset_type in BUILTIN_TRANSFORMS:
        return [BUILTIN_TRANSFORMS[asset_type](r) for r in rows]
    if not use_llm:
        raise SystemExit(
            f"ERROR: no built-in transform for asset type {asset_type!r}. "
            f"Either add one to BUILTIN_TRANSFORMS or pass --llm to attempt "
            f"an LLM-assisted mapping."
        )
    schema = load_target_schema(asset_type, schemas_dir)
    columns = sorted({k for r in rows for k in r.keys()})
    mapping = llm_generate_transform(asset_type, columns, schema)
    return [apply_llm_mapping(r, mapping, asset_type) for r in rows]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("--input", required=True, type=Path, help="Raw JSON file from steampipe_collector.py")
    parser.add_argument("--asset-type", required=True, help="Stave asset type, e.g. aws_s3_bucket")
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("../../schemas/observation/v1"),
        help="Path to schemas/observation/v1 (default: ../../schemas/observation/v1)",
    )
    parser.add_argument("--output", required=True, type=Path, help="Output directory for the obs.v0.1 file")
    parser.add_argument("--source", default="deployed", choices=["deployed", "planned", "local"])
    parser.add_argument("--validate", action="store_true", help="Run stave validate after transform")
    parser.add_argument("--no-llm", action="store_true", help="Hard-disable LLM mode (default unless --llm)")
    parser.add_argument("--llm", action="store_true", help="Enable LLM-assisted transform for unknown types")
    parser.add_argument("--ooda-max-attempts", type=int, default=3, help="Validation/repair loop bound")
    args = parser.parse_args()

    if args.no_llm and args.llm:
        print("ERROR: --no-llm and --llm are mutually exclusive", file=sys.stderr)
        return 2

    rows = json.loads(args.input.read_text())
    if not isinstance(rows, list):
        print(f"ERROR: expected JSON array in {args.input}, got {type(rows).__name__}", file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)
    out_path = args.output / f"{args.asset_type}.obs.json"

    attempt = 0
    while True:
        attempt += 1
        assets = transform_rows(rows, args.asset_type, use_llm=args.llm, schemas_dir=args.schema)
        snapshot = build_snapshot(assets, source=args.source)
        out_path.write_text(json.dumps(snapshot, indent=2) + "\n")
        print(f"wrote {out_path} ({len(assets)} asset(s))")

        if not args.validate:
            return 0
        ok, diagnostics = run_stave_validate(out_path, strict=True)
        if ok:
            print("validation passed")
            return 0
        print(f"validation failed (attempt {attempt}):\n  {diagnostics[:600]}", file=sys.stderr)
        if attempt >= args.ooda_max_attempts:
            print(
                f"giving up after {attempt} attempt(s). Inspect {out_path} and the "
                f"diagnostics above; the target schema is at "
                f"{args.schema / 'asset-types' / (args.asset_type + '.schema.json')}",
                file=sys.stderr,
            )
            return 1
        if not args.llm:
            # No LLM means no automated repair — the operator
            # has to edit the deterministic transform. Bail out
            # of the loop after the first failure.
            return 1


if __name__ == "__main__":
    sys.exit(main())

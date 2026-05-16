#!/usr/bin/env python3
"""Stave Transform Agent.

Reads raw Steampipe-shaped JSON rows and emits an obs.v0.1
observation snapshot for Stave. Two modes:

  Deterministic (default)
    Declarative transforms loaded from YAML files at
    contracts/steampipe/<asset_type>.yaml. Each file maps
    Steampipe columns to Stave property paths. Today aws_s3_bucket
    ships as a worked example. To add a new type, drop a YAML file
    in the contracts directory — no Python code change required.
    Agents in any language can read the same YAML.

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
from typing import Any

# ---------------------------------------------------------------------------
# Declarative transforms loaded from YAML
# ---------------------------------------------------------------------------

Asset = dict[str, Any]
TransformSpec = dict[str, Any]


def _project_root() -> Path:
    """Resolve the stave repo root from this file's location.
    stave_transform.py lives at examples/agents/stave_transform.py.
    """
    return Path(__file__).resolve().parents[2]


def _default_contracts_dir() -> Path:
    return _project_root() / "contracts" / "steampipe"


def load_steampipe_mappings(contracts_dir: Path | None = None) -> dict[str, TransformSpec]:
    """Load every YAML mapping under contracts/steampipe/. Returns a
    mapping of asset_type -> raw spec dict, validated for required keys.

    Agents in other languages can perform the same load with their own
    YAML parser — the file shape is the contract, not this loader.
    """
    try:
        import yaml  # type: ignore  # pylint: disable=import-outside-toplevel
    except ImportError as exc:
        raise SystemExit(
            "PyYAML is required to load contracts/steampipe/*.yaml. "
            "Install with: pip install pyyaml"
        ) from exc

    base = contracts_dir or _default_contracts_dir()
    if not base.is_dir():
        return {}

    specs: dict[str, TransformSpec] = {}
    for yaml_path in sorted(base.glob("*.yaml")):
        with yaml_path.open() as fh:
            spec = yaml.safe_load(fh)
        if not isinstance(spec, dict):
            raise SystemExit(f"{yaml_path}: top-level must be a mapping")
        for required in ("asset_type", "asset_id_column", "vendor"):
            if required not in spec:
                raise SystemExit(f"{yaml_path}: missing required field {required!r}")
        specs[spec["asset_type"]] = spec
    return specs


# Loaded at import time; agents that want a different contracts directory
# can call load_steampipe_mappings(Path(...)) and pass the result to
# transform_rows() instead. Kept module-level for backwards-compatible
# discovery via `BUILTIN_TRANSFORMS`.
BUILTIN_TRANSFORMS: dict[str, TransformSpec] = load_steampipe_mappings()


# ---------------------------------------------------------------------------
# Spec interpreter — the loader for the contracts/steampipe/*.yaml format
# ---------------------------------------------------------------------------


def _coerce(value: Any, kind: str | None) -> Any:
    if kind is None:
        return value
    if kind == "bool":
        return bool(value)
    if kind == "str":
        return "" if value is None else str(value)
    if kind == "int":
        return 0 if value is None else int(value)
    if kind == "float":
        return 0.0 if value is None else float(value)
    raise SystemExit(f"unknown coerce kind: {kind!r}")


def _format_template(template: str, row: dict[str, Any]) -> str:
    """Fill {column} placeholders in template with row column values.
    Missing columns become empty strings — same behaviour as the
    previous imperative code path.
    """
    out = template
    # Use a simple ${col} replacement; format() would die on legitimate
    # braces inside a value.
    for key, value in row.items():
        placeholder = "{" + key + "}"
        if placeholder in out:
            out = out.replace(placeholder, "" if value is None else str(value))
    return out


def _compute_asset_id(spec: TransformSpec, row: dict[str, Any]) -> str:
    primary = row.get(spec["asset_id_column"])
    if primary:
        return str(primary)
    fallback = spec.get("asset_id_fallback_template")
    if fallback:
        return _format_template(fallback, row)
    return ""


def _set_path(node: dict[str, Any], path: str, value: Any) -> None:
    segments = path.split(".")
    if segments[0] == "properties":
        segments = segments[1:]
    cur = node
    for seg in segments[:-1]:
        nxt = cur.get(seg)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[seg] = nxt
        cur = nxt
    cur[segments[-1]] = value


def _get_path(node: dict[str, Any], path: str) -> Any:
    segments = path.split(".")
    if segments and segments[0] == "properties":
        segments = segments[1:]
    cur: Any = node
    for seg in segments:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(seg)
    return cur


def _walk_json_path(blob: Any, path: str, key_variants: dict[str, str]) -> Any:
    """Traverse a JSON blob along a dotted path. Numeric segments are
    treated as list indices. For each string segment, fall back to its
    key_variants alias if the primary key is absent.
    """
    if not path:
        # Empty json_path means "return the column value as-is."
        return blob
    cur = blob
    for seg in path.split("."):
        if cur is None:
            return None
        if seg.isdigit():
            idx = int(seg)
            if isinstance(cur, list) and 0 <= idx < len(cur):
                cur = cur[idx]
                continue
            return None
        if isinstance(cur, dict):
            if seg in cur:
                cur = cur[seg]
                continue
            alt = key_variants.get(seg)
            if alt and alt in cur:
                cur = cur[alt]
                continue
            return None
        return None
    return cur


def _apply_field(properties: dict[str, Any], op: dict[str, Any], row: dict[str, Any], asset_id: str) -> None:
    path = op["path"]
    if op.get("use_asset_id"):
        value: Any = asset_id
    else:
        value = row.get(op["column"])
        if value is None and "default" in op:
            value = op["default"]
        if op.get("type") == "dict" and not isinstance(value, dict):
            value = {}
        value = _coerce(value, op.get("coerce"))
    _set_path(properties, path, value)


def _apply_static(properties: dict[str, Any], op: dict[str, Any]) -> None:
    _set_path(properties, op["path"], op["value"])


def _apply_extract(properties: dict[str, Any], op: dict[str, Any], row: dict[str, Any]) -> None:
    blob = row.get(op["column"])
    variants = op.get("key_variants") or {}
    value = _walk_json_path(blob, op["json_path"], variants) if blob is not None else None
    if value is None:
        value = op.get("default")
    _set_path(properties, op["path"], value)


def _apply_computed(properties: dict[str, Any], op: dict[str, Any]) -> None:
    inputs = op.get("inputs") or []
    values = [_get_path(properties, p) for p in inputs]
    kind = op.get("op")
    if kind == "all":
        value: Any = all(values)
    elif kind == "any":
        value = any(values)
    else:
        raise SystemExit(f"unknown computed op: {kind!r}")
    _set_path(properties, op["path"], value)


_OP_DISPATCH: dict[str, Any] = {
    "field": _apply_field,
    "static": _apply_static,
    "extract": _apply_extract,
    "computed": _apply_computed,
}


def transform_with_spec(spec: TransformSpec, row: dict[str, Any]) -> Asset:
    """Apply a YAML-loaded mapping spec to a single Steampipe row.

    Operations are processed in declared YAML order. Each operation
    writes one property path. Later operations may read paths
    written by earlier ones — required for ``computed`` ops, optional
    for everything else. The YAML author controls insertion order
    (which preserves into JSON output order), so output bytes are
    a deterministic function of the YAML, not of the loader.
    """
    asset_id = _compute_asset_id(spec, row)
    properties: dict[str, Any] = {}
    for op in spec.get("operations") or []:
        kind = op.get("kind")
        handler = _OP_DISPATCH.get(kind)
        if handler is None:
            raise SystemExit(f"unknown operation kind: {kind!r}")
        if kind == "field":
            handler(properties, op, row, asset_id)
        elif kind == "extract":
            handler(properties, op, row)
        else:
            handler(properties, op)
    return {
        "id": asset_id,
        "type": spec["asset_type"],
        "vendor": spec["vendor"],
        "properties": properties,
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
    spec = BUILTIN_TRANSFORMS.get(asset_type)
    if spec is not None:
        return [transform_with_spec(spec, r) for r in rows]
    if not use_llm:
        raise SystemExit(
            f"ERROR: no built-in transform for asset type {asset_type!r}. "
            f"Either drop a mapping file at contracts/steampipe/{asset_type}.yaml "
            f"or pass --llm to attempt an LLM-assisted mapping."
        )
    schema = load_target_schema(asset_type, schemas_dir)
    columns = sorted({k for r in rows for k in r.keys()})
    mapping = llm_generate_transform(asset_type, columns, schema)
    return [apply_llm_mapping(r, mapping, asset_type) for r in rows]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("--list-transforms", action="store_true", help="Print available asset types from contracts/steampipe/ and exit")
    parser.add_argument("--input", type=Path, help="Raw JSON file from steampipe_collector.py")
    parser.add_argument("--asset-type", help="Stave asset type, e.g. aws_s3_bucket")
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("../../schemas/observation/v1"),
        help="Path to schemas/observation/v1 (default: ../../schemas/observation/v1)",
    )
    parser.add_argument("--output", type=Path, help="Output directory for the obs.v0.1 file (required unless --list-transforms)")
    parser.add_argument("--source", default="deployed", choices=["deployed", "planned", "local"])
    parser.add_argument("--validate", action="store_true", help="Run stave validate after transform")
    parser.add_argument("--no-llm", action="store_true", help="Hard-disable LLM mode (default unless --llm)")
    parser.add_argument("--llm", action="store_true", help="Enable LLM-assisted transform for unknown types")
    parser.add_argument("--ooda-max-attempts", type=int, default=3, help="Validation/repair loop bound")
    args = parser.parse_args()

    if args.list_transforms:
        for asset_type in sorted(BUILTIN_TRANSFORMS.keys()):
            print(asset_type)
        return 0

    if args.no_llm and args.llm:
        print("ERROR: --no-llm and --llm are mutually exclusive", file=sys.stderr)
        return 2

    if args.input is None or args.asset_type is None or args.output is None:
        print("ERROR: --input, --asset-type, and --output are required (unless --list-transforms)", file=sys.stderr)
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

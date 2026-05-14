#!/usr/bin/env python3
"""Steampipe Collector Agent.

Queries Steampipe tables via the `steampipe query` CLI and writes
each table's rows as raw JSON. Does NOT transform to Stave's
observation contract — that's the transform agent's job. Keeping
collection and transformation in two phases means the raw row
data is reviewable, replayable, and reusable (a single collection
run can feed multiple transform iterations).

Air-gap posture: every call is `steampipe query` on the local
Steampipe daemon. No network calls happen from this script
itself; the underlying Steampipe plugin handles cloud API calls
in its own process with the credentials the operator already
configured for it.

Usage:
    python3 steampipe_collector.py --tables aws_s3_bucket,aws_iam_role --output ./raw/
    python3 steampipe_collector.py --tables aws_s3_bucket --columns "name,arn,tags" --output ./raw/
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


def run_steampipe_query(query: str, *, timeout_seconds: int = 120) -> list[dict]:
    """Run a steampipe query and return the parsed JSON rows.

    Steampipe's --output json emits a JSON array of row objects
    where each row's keys are the column names. Errors flow
    through stderr; this function surfaces them with the query
    text so failures stay greppable.
    """
    if shutil.which("steampipe") is None:
        raise SystemExit(
            "ERROR: steampipe binary not found on PATH. Install it from "
            "https://steampipe.io/downloads and run `steampipe plugin install aws` "
            "(or the plugin you need) before running this script."
        )
    proc = subprocess.run(
        ["steampipe", "query", "--output", "json", query],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"steampipe query failed (exit {proc.returncode})\n"
            f"  query:  {query}\n"
            f"  stderr: {proc.stderr.strip()[:600]}"
        )
    if not proc.stdout.strip():
        return []
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"steampipe returned non-JSON output for {query!r}: {exc}\n"
            f"  stdout (first 400 chars): {proc.stdout[:400]!r}"
        ) from exc


def collect_table(table: str, columns: str | None, output_dir: Path) -> int:
    """Query one table and write its rows to <output_dir>/<table>.json."""
    select = columns if columns else "*"
    query = f"SELECT {select} FROM {table}"
    rows = run_steampipe_query(query)
    out_path = output_dir / f"{table}.json"
    out_path.write_text(json.dumps(rows, indent=2, default=str) + "\n")
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument(
        "--tables",
        required=True,
        help="Comma-separated Steampipe table names (e.g. aws_s3_bucket,aws_iam_role)",
    )
    parser.add_argument(
        "--columns",
        default=None,
        help="Optional comma-separated columns; default is SELECT *",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Directory to write <table>.json files into",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Per-query timeout in seconds (default 120)",
    )
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    tables = [t.strip() for t in args.tables.split(",") if t.strip()]
    if not tables:
        print("ERROR: no tables given", file=sys.stderr)
        return 2

    total_rows = 0
    for table in tables:
        try:
            n = collect_table(table, args.columns, args.output)
        except RuntimeError as exc:
            print(f"FAIL: {table}: {exc}", file=sys.stderr)
            return 1
        total_rows += n
        print(f"  {table}: {n} rows → {args.output / f'{table}.json'}")
    print(f"\ndone: {len(tables)} tables, {total_rows} rows total")
    return 0


if __name__ == "__main__":
    sys.exit(main())

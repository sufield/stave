"""H1 fixture × reasoning engine matrix harness.

Iterates every example fixture pair, runs each engine, captures verdict
per cell. Writes matrix.json next to this script. Subsequent rendering
step (`render.py`) reads matrix.json and writes the catalog.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
STAVE = HERE.parent.parent          # …/stave/
REPO = STAVE.parent                  # …/bizacademy/
EXAMPLES = STAVE / "examples"
STAVE_BIN = STAVE / "stave"
NOW = "2026-01-09T00:00:00Z"
OUT_PATH = HERE / "matrix.json"

# Map fixture-bearing example dirs -> known z3-* runner that has
# query.smt2 + uses these fixtures.
Z3_RUNNERS = {
    "cognito-self-register-to-aws-creds": [
        ("z3-cognito-unauth-chain", "query.smt2"),
        ("z3-cognito-auth-chain", "query-auth-chain.smt2"),
        ("z3-cognito-auth-chain", "query-self-register-chain.smt2"),
    ],
    "iam-overpermission-wildcard": [
        ("z3-overpermission-fixture", "query.smt2"),
        ("z3-bybit-tag-aware-compound", "query.smt2"),
        ("z3-compound-overperm-assumable", "query.smt2"),
    ],
    "iam-multi-hop-trust": [
        ("z3-multi-hop-can-assume", "query.smt2"),
    ],
    "iam-21-privesc-5-patterns": [
        ("z3-rhino-pattern1-self-mutation", "query.smt2"),
        ("z3-rhino-pattern2-credential-creation", "query.smt2"),
        ("z3-rhino-pattern3-passrole-compute", "query.smt2"),
        ("z3-rhino-pattern4-indirect-invoke", "query.smt2"),
        ("z3-rhino-pattern5-trust-modification", "query.smt2"),
    ],
    # In-example queries (no z3-* runner directory; the query lives
    # alongside the example's main.go).
    "iam-attach-user-policy-self": [
        ("iam-attach-user-policy-self", "query.smt2"),
    ],
    "sns-secrets-compound-chain": [
        ("sns-secrets-compound-chain", "query.smt2"),
    ],
    "iam-autoscaling-privesc-bypass": [
        ("iam-autoscaling-privesc-bypass", "query.smt2"),
    ],
    "cloudtrail-stop-logging": [
        ("cloudtrail-stop-logging", "query-data-events.smt2"),
        ("cloudtrail-stop-logging", "query-mgmt.smt2"),
    ],
    # PR 1 — generic per-property projector unblocked these.
    "cognito-no-mfa-advanced-security": [
        ("cognito-no-mfa-advanced-security", "query.smt2"),
    ],
    "eks-aws-auth-template-injection": [
        ("eks-aws-auth-template-injection", "query.smt2"),
    ],
    "eks-rbac-webhook-config-access": [
        ("eks-rbac-webhook-config-access", "query.smt2"),
    ],
    "s3-broad-write-scope": [
        ("s3-broad-write-scope", "query.smt2"),
    ],
    "s3-bucket-name-dangling": [
        ("s3-bucket-name-dangling", "query.smt2"),
    ],
    "s3-dotgit-readable": [
        ("s3-dotgit-readable", "query.smt2"),
    ],
    "s3-public-list-policy": [
        ("s3-public-list-policy", "query.smt2"),
    ],
    "s3-public-read-policy": [
        ("s3-public-read-policy", "query.smt2"),
    ],
    # PR 4 — stringified-policy Condition parser unblocked apigw
    # (the aws:sourceVpc → aws:sourceVpce discriminator lives
    # inside the resource_policy_json string field).
    "apigw-private-api-scoped-deny": [
        ("apigw-private-api-scoped-deny", "query.smt2"),
    ],
    # PR 5 — resource-policy Principal/Action projection
    # unblocked cross-account-replication. The bucket policy
    # has no Conditions; the writeup → remediated diff is
    # principal scope (:root → :role/specific) and an extra
    # AllowRead statement. The query disjuncts on either shape.
    "s3-cross-account-replication-overperm": [
        ("s3-cross-account-replication-overperm", "query.smt2"),
    ],
}


def find_fixtures() -> list[dict]:
    """Discover (example_dir, fixture_name, controls_dir, observations_dir)."""
    out = []
    for example in sorted((EXAMPLES).iterdir()):
        fx_root = example / "fixtures"
        if not fx_root.is_dir():
            continue
        # Each subdirectory holds an observations/ + maybe extras
        for fix in sorted(fx_root.iterdir()):
            obs = fix / "observations"
            if not obs.is_dir():
                continue
            # Find a controls dir — usually example/controls but some
            # have per-fixture controls.
            controls = example / "controls"
            if not controls.is_dir():
                # Skip the fixture if there's no control set; we can't
                # eval CEL without controls.
                continue
            out.append({
                "example": example.name,
                "fixture": fix.name,
                "label": f"{example.name}/{fix.name}",
                "obs": str(obs),
                "controls": str(controls),
            })
    return out


def run(cmd: list[str], stdin: str = "", timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, input=stdin, capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "(timeout)"
    except FileNotFoundError as e:
        return 127, "", f"(not found: {e})"


def cell_cel(fix: dict) -> dict:
    rc, out, err = run([str(STAVE_BIN), "apply",
                        "--controls", fix["controls"],
                        "--observations", fix["obs"],
                        "--now", NOW,
                        "--format", "json",
                        "--allow-unknown-input"])
    if rc not in (0, 3) or not out:
        return {"verdict": "error", "detail": err.strip()[:120] or f"rc={rc}"}
    try:
        d = json.loads(out)
    except Exception:
        return {"verdict": "error", "detail": "bad-json"}
    findings = d.get("findings") or []
    return {
        "verdict": d.get("status", "?"),
        "findings": len(findings),
        "controls": sorted({f["control_id"] for f in findings}),
    }


def cell_export(fix: dict, fmt: str, dest: pathlib.Path) -> dict:
    rc, out, err = run([str(STAVE_BIN), "export-sir",
                        "--controls", fix["controls"],
                        "--observations", fix["obs"],
                        "--now", NOW,
                        "--format", fmt])
    if rc != 0 or not out:
        return {"verdict": "error", "lines": 0, "detail": err.strip()[:120]}
    dest.write_text(out)
    return {"verdict": "ok", "lines": len(out.splitlines())}


def cell_smt(facts_smt2: pathlib.Path, query: pathlib.Path, solver: str) -> dict:
    if not query.is_file():
        return {"verdict": "n/a", "detail": "no query.smt2 paired"}
    if not shutil.which(solver):
        return {"verdict": "n/a", "detail": f"{solver} not on PATH"}
    payload = facts_smt2.read_text() + query.read_text()
    if solver == "z3":
        cmd = ["z3", "-in"]
    elif solver == "cvc5":
        cmd = ["cvc5", "--lang", "smt2", "--finite-model-find", "--produce-models"]
    elif solver == "yices-smt2":
        cmd = ["yices-smt2"]
    else:
        return {"verdict": "n/a"}
    rc, out, err = run(cmd, stdin=payload, timeout=30)
    first = (out.splitlines() or [""])[0].strip().lower()
    if "sat" in first and "unsat" not in first:
        return {"verdict": "sat"}
    if "unsat" in first:
        return {"verdict": "unsat"}
    return {"verdict": "error", "detail": (first or err.strip()[:80] or "?")}


def cell_souffle(facts_jsonl: pathlib.Path) -> dict:
    if not shutil.which("souffle"):
        return {"verdict": "n/a", "detail": "souffle not on PATH"}
    transform = EXAMPLES / "souffle-reachability" / "transform.sh"
    dl = EXAMPLES / "souffle-reachability" / "reachability.dl"
    facts_dir = pathlib.Path(tempfile.mkdtemp(prefix="souffle-facts-"))
    out_dir = pathlib.Path(tempfile.mkdtemp(prefix="souffle-out-"))
    try:
        rc, _, err = run(["bash", str(transform), str(facts_jsonl), str(facts_dir)])
        if rc != 0:
            return {"verdict": "error", "detail": "transform failed"}
        rc, _, err = run(["souffle", "-F", str(facts_dir), "-D", str(out_dir), str(dl)])
        if rc != 0:
            return {"verdict": "error", "detail": err.strip()[:120]}
        rels = {}
        for csv in sorted(out_dir.glob("*.csv")):
            n = sum(1 for _ in csv.open())
            rels[csv.stem] = n
        return {"verdict": "ok", "rels": rels}
    finally:
        shutil.rmtree(facts_dir, ignore_errors=True)
        shutil.rmtree(out_dir, ignore_errors=True)


def venv_python() -> str:
    venv = REPO / ".tools-venv" / "bin" / "python3"
    return str(venv) if venv.is_file() else "python3"


def cell_clingo(fixture_label: str, facts_jsonl: pathlib.Path) -> dict:
    constraints = EXAMPLES / "clingo-constraints" / "constraints.lp"
    runner = EXAMPLES / "clingo-constraints" / "run.py"
    if not runner.is_file():
        return {"verdict": "n/a"}
    rc, out, err = run([venv_python(), str(runner), fixture_label,
                        str(facts_jsonl), str(constraints)])
    if rc != 0:
        return {"verdict": "error", "detail": (err.strip() or out.strip())[:160]}
    # Count violation kinds reported.
    kinds = sorted(set(re.findall(r"violation:\s+(\w+)", out)))
    return {"verdict": "ok" if kinds else "empty",
            "violations": kinds, "count": len(kinds)}


def cell_prolog(facts_jsonl: pathlib.Path) -> dict:
    if not shutil.which("swipl"):
        return {"verdict": "n/a", "detail": "swipl not on PATH"}
    transform = EXAMPLES / "prolog-proof-trees" / "transform-to-pl.sh"
    reasoning = EXAMPLES / "prolog-proof-trees" / "reasoning.pl"
    if not transform.is_file() or not reasoning.is_file():
        return {"verdict": "n/a"}
    pl_file = pathlib.Path(tempfile.mkstemp(suffix=".pl")[1])
    try:
        rc, _, err = run(["bash", str(transform), str(facts_jsonl), str(pl_file)])
        if rc != 0:
            return {"verdict": "error", "detail": "transform failed"}
        rc, out, err = run(
            ["swipl", "-q", "-g",
             f"consult('{pl_file}'), consult('{reasoning}'), run_queries, halt.",
             "-t", "halt"], timeout=60)
        # Each step in the proof tree starts with `--[`.
        steps = out.count("--[")
        if rc != 0 and steps == 0:
            return {"verdict": "error", "detail": (err.strip() or out.strip())[:120]}
        return {"verdict": "ok" if steps else "empty", "proof_steps": steps}
    finally:
        pl_file.unlink(missing_ok=True)


def cell_pysat(fixture_label: str, facts_jsonl: pathlib.Path) -> dict:
    runner = EXAMPLES / "sat-control-regression" / "run.py"
    if not runner.is_file():
        return {"verdict": "n/a"}
    rc, out, err = run([venv_python(), str(runner), fixture_label, str(facts_jsonl)])
    if rc != 0 and not out:
        return {"verdict": "error", "detail": (err.strip())[:120]}
    if "UNSAFE" in out:
        return {"verdict": "UNSAFE",
                "compounds": sorted(set(re.findall(r"compound:\s+(\S+)", out)))}
    if "SAFE" in out:
        return {"verdict": "SAFE"}
    return {"verdict": "empty", "detail": (out.strip().splitlines() or [""])[0][:120]}


def cell_risk(fixture_label: str, facts_jsonl: pathlib.Path) -> dict:
    runner = EXAMPLES / "prism-risk-prioritization" / "risk_model.py"
    rc, out, err = run(["python3", str(runner), fixture_label, str(facts_jsonl)])
    if rc != 0 and not out:
        return {"verdict": "error", "detail": err.strip()[:120]}
    m = re.search(r"P\(exploitation\)\s*=\s*([\d.]+)%", out)
    if m:
        pct = float(m.group(1))
        v = "MINIMAL" if pct < 1 else ("CRITICAL" if pct >= 30 else
                                       "HIGH" if pct >= 10 else "MEDIUM")
        return {"verdict": v, "p_exploit_pct": pct}
    return {"verdict": "empty"}


def cell_tla(fixture_label: str, facts_jsonl: pathlib.Path) -> dict:
    runner = EXAMPLES / "tlaplus-temporal-safety" / "temporal_check.py"
    rc, out, err = run(["python3", str(runner), fixture_label, str(facts_jsonl)])
    if rc != 0 and not out:
        return {"verdict": "error", "detail": err.strip()[:120]}
    for marker in ("UNSAFE", "AT_RISK", "SAFE"):
        if marker in out:
            m = re.search(r"drift margin[:\s]+([\d]+)", out)
            return {"verdict": marker, "drift_margin": int(m.group(1)) if m else None}
    return {"verdict": "empty"}


def cell_game(fixture_label: str, facts_jsonl: pathlib.Path) -> dict:
    runner = EXAMPLES / "game-theory-cost" / "cost_model.py"
    rc, out, err = run(["python3", str(runner), fixture_label, str(facts_jsonl)])
    if rc != 0 and not out:
        return {"verdict": "error", "detail": err.strip()[:120]}
    m = re.search(r"cost:\s*\$([\d,]+)", out)
    cost = int(m.group(1).replace(",", "")) if m else None
    if cost is None:
        # Look for "no viable path" / verdict line
        if re.search(r"(no viable path|MINIMAL)", out):
            return {"verdict": "no-path"}
        return {"verdict": "empty"}
    return {"verdict": f"${cost}", "cost": cost}


def all_z3_queries_for(example_name: str) -> list[tuple[str, pathlib.Path]]:
    """Return [(query_label, query_path)] paired with this example."""
    out = []
    for runner_name, q_name in Z3_RUNNERS.get(example_name, []):
        q = EXAMPLES / runner_name / q_name
        if q.is_file():
            label = f"{runner_name}/{q_name.replace('.smt2','')}"
            out.append((label, q))
    return out


def main() -> int:
    if not STAVE_BIN.is_file():
        print(f"stave binary missing at {STAVE_BIN}; build first", file=sys.stderr)
        return 2
    fixtures = find_fixtures()
    print(f"discovered {len(fixtures)} fixture pairs", file=sys.stderr)

    matrix = {"fixtures": [], "z3_runners": Z3_RUNNERS}
    work = pathlib.Path(tempfile.mkdtemp(prefix="h1-matrix-"))

    for i, fix in enumerate(fixtures, 1):
        print(f"[{i}/{len(fixtures)}] {fix['label']}", file=sys.stderr, flush=True)
        t0 = time.monotonic()

        cell = {"label": fix["label"], "example": fix["example"], "fixture": fix["fixture"]}
        cell["cel"] = cell_cel(fix)

        smt2 = work / f"{i}.smt2"
        jsonl = work / f"{i}.jsonl"
        cell["export_smt2"] = cell_export(fix, "smt2", smt2)
        cell["export_jsonl"] = cell_export(fix, "jsonl", jsonl)

        # SMT solvers (Z3, cvc5, yices) — if there's a paired query
        smt_results = []
        for q_label, q_path in all_z3_queries_for(fix["example"]):
            qres = {"query": q_label,
                    "z3":    cell_smt(smt2, q_path, "z3"),
                    "cvc5":  cell_smt(smt2, q_path, "cvc5"),
                    "yices": cell_smt(smt2, q_path, "yices-smt2")}
            smt_results.append(qres)
        cell["smt_queries"] = smt_results

        # Datalog / ASP / Prolog / SAT / Risk / TLA+ / Game theory
        # Only meaningful when JSONL export succeeded.
        if cell["export_jsonl"]["verdict"] == "ok":
            cell["souffle"] = cell_souffle(jsonl)
            cell["clingo"]  = cell_clingo(fix["label"], jsonl)
            cell["prolog"]  = cell_prolog(jsonl)
            cell["pysat"]   = cell_pysat(fix["label"], jsonl)
            cell["risk"]    = cell_risk(fix["label"], jsonl)
            cell["tla"]     = cell_tla(fix["label"], jsonl)
            cell["game"]    = cell_game(fix["label"], jsonl)
        else:
            for k in ("souffle", "clingo", "prolog", "pysat", "risk", "tla", "game"):
                cell[k] = {"verdict": "skipped", "detail": "no jsonl export"}

        cell["elapsed_s"] = round(time.monotonic() - t0, 2)
        matrix["fixtures"].append(cell)

    OUT_PATH.write_text(json.dumps(matrix, indent=2, default=str))
    print(f"wrote {OUT_PATH} ({len(matrix['fixtures'])} fixtures)", file=sys.stderr)

    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

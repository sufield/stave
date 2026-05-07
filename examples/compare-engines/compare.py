#!/usr/bin/env python3
"""Multi-engine comparison harness.

Runs every available reasoning engine on the same fixture set
and reports per-fixture consensus. Agreement → high confidence;
disagreement → blind spot in one of the engines.

Each engine answers a different KIND of question (CEL: rule
violation; Z3: satisfiability; Clingo: violation atoms; SAT:
boolean compound; Soufflé: reach count). The harness normalizes
to {SAFE, UNSAFE, INCONCLUSIVE} per fixture; raw output stays
available when investigation is needed.

Usage:
    python3 compare.py             # run every fixture
    python3 compare.py --json      # machine-readable output
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
EXAMPLES_DIR = SCRIPT_DIR.parent
STAVE_ROOT = EXAMPLES_DIR.parent
REPO_ROOT = STAVE_ROOT.parent

# Canonical fixture set. Each fixture's `engine_labels` maps
# engine names to either (script_path, label) tuples (for batch
# engines whose run.sh emits a section/row by that label) or
# strings (for engines whose batch emits one section per
# fixture). Adding a new fixture = add an entry here + ensure
# every engine's run.sh covers it under the listed label.
FIXTURES = [
    {
        "id": "cognito-writeup",
        "label": "Cognito self-register (writeup)",
        "expected": "UNSAFE",
        "observations": EXAMPLES_DIR / "cognito-self-register-to-aws-creds/fixtures/writeup-config/observations",
        "narrow_controls": EXAMPLES_DIR / "cognito-self-register-to-aws-creds/controls",
        "engine_labels": {
            "z3": ("z3-cognito-unauth-chain", "writeup-config"),
            "clingo": "cognito-writeup",
            "pysat": "cognito-writeup",
            "souffle": "Cognito writeup-config",
            "prolog": "Cognito writeup-config",
        },
    },
    {
        "id": "cognito-remediated",
        "label": "Cognito self-register (remediated)",
        "expected": "SAFE",
        "observations": EXAMPLES_DIR / "cognito-self-register-to-aws-creds/fixtures/remediated-config/observations",
        "narrow_controls": EXAMPLES_DIR / "cognito-self-register-to-aws-creds/controls",
        "engine_labels": {
            "z3": ("z3-cognito-unauth-chain", "remediated-config"),
            "clingo": "cognito-remediated",
            "pysat": "cognito-remediated",
            "souffle": "Cognito remediated",
            "prolog": "Cognito remediated",
        },
    },
    {
        "id": "multi-hop-vulnerable",
        "label": "Multi-hop can_assume (vulnerable)",
        "expected": "UNSAFE",
        "observations": EXAMPLES_DIR / "iam-multi-hop-trust/fixtures/vulnerable/observations",
        "narrow_controls": EXAMPLES_DIR / "iam-multi-hop-trust/controls",
        "engine_labels": {
            "z3": ("z3-multi-hop-can-assume", "vulnerable"),
            "clingo": "multi-hop-vulnerable",
            "pysat": None,
            "souffle": "Multi-hop vulnerable",
            "prolog": "Multi-hop vulnerable",
        },
    },
    {
        "id": "multi-hop-remediated",
        "label": "Multi-hop can_assume (remediated)",
        "expected": "SAFE",
        "observations": EXAMPLES_DIR / "iam-multi-hop-trust/fixtures/remediated/observations",
        "narrow_controls": EXAMPLES_DIR / "iam-multi-hop-trust/controls",
        "engine_labels": {
            "z3": ("z3-multi-hop-can-assume", "remediated"),
            "clingo": "multi-hop-remediated",
            "pysat": None,
            "souffle": "Multi-hop remediated",
            "prolog": "Multi-hop remediated",
        },
    },
    {
        "id": "rhino-vulnerable",
        "label": "Rhino privesc (vulnerable)",
        "expected": "UNSAFE",
        "observations": EXAMPLES_DIR / "iam-21-privesc-5-patterns/fixtures/rhino-vulnerable/observations",
        "narrow_controls": EXAMPLES_DIR / "iam-21-privesc-5-patterns/controls",
        "engine_labels": {
            "z3": ("z3-rhino-pattern1-self-mutation", "rhino-vulnerable"),
            "clingo": "rhino-vulnerable",
            "pysat": "rhino-vulnerable",
            "souffle": "Rhino vulnerable",
            "prolog": "Rhino vulnerable",
        },
    },
    {
        "id": "rhino-remediated",
        "label": "Rhino privesc (remediated)",
        "expected": "SAFE",
        "observations": EXAMPLES_DIR / "iam-21-privesc-5-patterns/fixtures/remediated/observations",
        "narrow_controls": EXAMPLES_DIR / "iam-21-privesc-5-patterns/controls",
        "engine_labels": {
            "z3": ("z3-rhino-pattern1-self-mutation", "remediated"),
            "clingo": "rhino-remediated",
            "pysat": "rhino-remediated",
            "souffle": "Rhino remediated",
            "prolog": None,
        },
    },
    {
        "id": "bybit-before",
        "label": "Bybit wildcard (before)",
        "expected": "UNSAFE",
        "observations": EXAMPLES_DIR / "iam-overpermission-wildcard/fixtures/bybit-pattern-before/observations",
        "narrow_controls": EXAMPLES_DIR / "iam-overpermission-wildcard/controls",
        "engine_labels": {
            "z3": ("z3-bybit-tag-aware-compound", "bybit-pattern-before"),
            "clingo": "bybit-before",
            "pysat": None,
            "souffle": "Bybit before",
            "prolog": None,
        },
    },
    {
        "id": "bybit-after",
        "label": "Bybit wildcard (after)",
        "expected": "SAFE",
        "observations": EXAMPLES_DIR / "iam-overpermission-wildcard/fixtures/bybit-pattern-after/observations",
        "narrow_controls": EXAMPLES_DIR / "iam-overpermission-wildcard/controls",
        "engine_labels": {
            "z3": ("z3-bybit-tag-aware-compound", "bybit-pattern-after"),
            "clingo": "bybit-after",
            "pysat": None,
            "souffle": "Bybit after",
            "prolog": None,
        },
    },
]


def load_engines() -> list[dict]:
    with (SCRIPT_DIR / "engines.json").open() as f:
        return json.load(f)["engines"]


def venv_python() -> str:
    return str(REPO_ROOT / ".tools-venv" / "bin" / "python3")


def stave_bin() -> str:
    return str(STAVE_ROOT / "stave")


def check_available(engine: dict) -> bool:
    cmd = engine["available_check"].replace("${REPO_ROOT}", str(REPO_ROOT))
    try:
        result = subprocess.run(
            cmd, shell=True, cwd=STAVE_ROOT,
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def time_call(fn):
    start = time.time()
    out = fn()
    return out, int((time.time() - start) * 1000)


# =====================================================
# Per-engine batch runners. Each returns the raw stdout
# of running the engine's run.sh once across every
# fixture it covers. Cached per engine to avoid
# re-running.
# =====================================================
class BatchCache:
    def __init__(self):
        self.cache: dict[str, str] = {}
        self.timings: dict[str, int] = {}

    def get(self, key: str, builder) -> str:
        if key not in self.cache:
            out, ms = time_call(builder)
            self.cache[key] = out
            self.timings[key] = ms
        return self.cache[key]

    def time(self, key: str) -> int:
        return self.timings.get(key, 0)


def run_z3_example(example_name: str) -> str:
    """Run a z3-* run.sh and return stdout+stderr."""
    script = EXAMPLES_DIR / example_name / "run.sh"
    result = subprocess.run(
        ["bash", str(script)],
        cwd=STAVE_ROOT,
        capture_output=True, text=True, timeout=180,
    )
    return result.stdout + result.stderr


def run_clingo() -> str:
    script = EXAMPLES_DIR / "clingo-constraints" / "run.sh"
    result = subprocess.run(
        ["bash", str(script)],
        cwd=STAVE_ROOT,
        capture_output=True, text=True, timeout=180,
        env={**os.environ, "CLINGO_VENV": str(REPO_ROOT / ".tools-venv")},
    )
    return result.stdout


def run_pysat() -> str:
    script = EXAMPLES_DIR / "sat-control-regression" / "run.sh"
    result = subprocess.run(
        ["bash", str(script)],
        cwd=STAVE_ROOT,
        capture_output=True, text=True, timeout=180,
        env={**os.environ, "PYSAT_VENV": str(REPO_ROOT / ".tools-venv")},
    )
    return result.stdout


def run_prolog() -> str:
    script = EXAMPLES_DIR / "prolog-proof-trees" / "run.sh"
    result = subprocess.run(
        ["bash", str(script)],
        cwd=STAVE_ROOT,
        capture_output=True, text=True, timeout=180,
    )
    return result.stdout


def run_souffle() -> str:
    script = EXAMPLES_DIR / "souffle-reachability" / "run.sh"
    env = {**os.environ}
    env["PATH"] = f"{Path.home()}/.local/bin:{env.get('PATH', '')}"
    result = subprocess.run(
        ["bash", str(script)],
        cwd=STAVE_ROOT,
        capture_output=True, text=True, timeout=300,
        env=env,
    )
    return result.stdout


# =====================================================
# Per-engine output parsers. Each returns
# {SAFE, UNSAFE, INCONCLUSIVE} for the fixture, given
# the cached batch output and the fixture's engine_label.
# =====================================================
def parse_z3_row(output: str, label: str) -> str:
    """Z3 example tables emit `<label>   ... z3=sat|unsat ...`."""
    pat = re.compile(rf"^\s*{re.escape(label)}\b.*?z3=(\S+)", re.MULTILINE)
    m = pat.search(output)
    if not m:
        return "INCONCLUSIVE"
    verdict = m.group(1)
    if verdict == "sat":
        return "UNSAFE"
    if verdict == "unsat":
        return "SAFE"
    return "INCONCLUSIVE"


def parse_cvc5_row(output: str, label: str) -> str:
    pat = re.compile(rf"^\s*{re.escape(label)}\b.*?cvc5=(\S+)", re.MULTILINE)
    m = pat.search(output)
    if not m:
        return "INCONCLUSIVE"
    verdict = m.group(1)
    if verdict == "sat":
        return "UNSAFE"
    if verdict == "unsat":
        return "SAFE"
    if verdict in ("(timeout)", "(skipped)", "unknown"):
        return "INCONCLUSIVE"
    return "INCONCLUSIVE"


def split_sections(output: str) -> dict[str, str]:
    """Split `=== label ===` sectioned output into a dict."""
    sections: dict[str, str] = {}
    current = None
    buf: list[str] = []
    for line in output.splitlines():
        m = re.match(r"^===\s+(.+?)\s+===\s*$", line)
        if m:
            if current is not None:
                sections[current] = "\n".join(buf)
            current = m.group(1)
            buf = []
        else:
            buf.append(line)
    if current is not None:
        sections[current] = "\n".join(buf)
    return sections


def parse_clingo(output: str, label: str) -> str:
    sections = split_sections(output)
    body = sections.get(label)
    if body is None:
        return "INCONCLUSIVE"
    # UNSAFE iff at least one `violation:` line. latent_risk
    # alone is not UNSAFE (it's a risk signal, not a violation).
    if "violation:" in body:
        return "UNSAFE"
    if "(clean)" in body or "latent_risk" in body:
        return "SAFE"
    return "INCONCLUSIVE"


def parse_pysat(output: str, label: str) -> str:
    sections = split_sections(output)
    body = sections.get(label)
    if body is None:
        return "INCONCLUSIVE"
    if "UNSAFE" in body and "compound(s) fire" in body:
        return "UNSAFE"
    if "SAFE" in body:
        return "SAFE"
    return "INCONCLUSIVE"


def split_prolog_fixtures(output: str) -> dict[str, str]:
    """Split Prolog batch output into per-fixture bodies.

    The Prolog runner prints fixture headers as
    `============================================================`
    above and below the label, distinct from the `=== ... ===`
    convention the other engines use.
    """
    sections: dict[str, str] = {}
    lines = output.splitlines()
    i = 0
    sep = "============================================================"
    while i < len(lines):
        if lines[i].rstrip() == sep and i + 1 < len(lines):
            header = lines[i + 1].strip()
            j = i + 3  # skip the closing separator
            buf: list[str] = []
            while j < len(lines) and lines[j].rstrip() != sep:
                buf.append(lines[j])
                j += 1
            sections[header] = "\n".join(buf)
            i = j
        else:
            i += 1
    return sections


def parse_prolog(output: str, label: str) -> str:
    """UNSAFE iff any of the four sub-sections has a proof tree.

    A proof tree is rendered as `subject --[verb]--> object`
    lines under one of the section headers. An empty section
    prints `(none)` instead. The fixture is SAFE only when
    every section is `(none)`.
    """
    fixtures = split_prolog_fixtures(output)
    body = fixtures.get(label)
    if body is None:
        return "INCONCLUSIVE"
    if "--[" in body:
        return "UNSAFE"
    if "(none)" in body:
        return "SAFE"
    return "INCONCLUSIVE"


def parse_souffle(output: str, label: str) -> str:
    """UNSAFE iff any unsafe-pattern relation has rows > 0.

    `reachable` alone is too coarse — legitimate access shows
    up there too. The unsafe pattern is "anonymous or
    self-register or exploitable_overperm or privesc_chain
    has at least one row."
    """
    sections = split_sections(output)
    body = sections.get(label)
    if body is None:
        return "INCONCLUSIVE"
    unsafe_relations = [
        "anonymous_reachable",
        "self_register_reachable",
        "exploitable_overperm",
        "privesc_chain",
    ]
    for rel in unsafe_relations:
        m = re.search(rf"{rel}:\s*(\d+)", body)
        if m and int(m.group(1)) > 0:
            return "UNSAFE"
    # No unsafe-pattern relation hits → SAFE.
    return "SAFE"


def run_stave_cel(fixture: dict) -> str:
    """Run `stave apply` on a single fixture, return verdict."""
    cmd = [
        stave_bin(), "apply",
        "--controls", str(fixture["narrow_controls"]),
        "--observations", str(fixture["observations"]),
        "--now", "2026-01-09T00:00:00Z",
        "--format", "json",
        "--allow-unknown-input",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        # exit 0 = compliant, 3 = violations, 2 = input error
        if result.returncode in (0, 3) and result.stdout.strip():
            doc = json.loads(result.stdout)
            status = doc.get("status", "")
            if status == "COMPLIANT":
                return "SAFE"
            if status == "NON_COMPLIANT":
                return "UNSAFE"
            if status == "AT_RISK":
                return "INCONCLUSIVE"
        return "INCONCLUSIVE"
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return "INCONCLUSIVE"


# =====================================================
# Orchestration.
# =====================================================
def evaluate_fixture(fixture: dict, engines: list[dict],
                     availability: dict[str, bool],
                     batch: BatchCache) -> dict:
    """Return per-engine verdict + timing for one fixture."""
    results: list[dict] = []
    for engine in engines:
        name = engine["name"]
        if not availability.get(name, False):
            results.append({"engine": name, "status": "not_available"})
            continue

        if name == "stave-cel":
            verdict, ms = time_call(lambda: run_stave_cel(fixture))
            results.append({"engine": name, "status": "ok",
                            "verdict": verdict, "time_ms": ms})
            continue

        # cvc5 reuses z3's engine_label and z3's batch run.sh —
        # both verdicts are emitted in the same table.
        lookup_key = "z3" if name == "cvc5" else name
        engine_label = fixture["engine_labels"].get(lookup_key)
        if engine_label is None:
            results.append({"engine": name, "status": "no_coverage"})
            continue

        if name == "z3":
            example, label = engine_label
            output = batch.get(f"z3:{example}", lambda: run_z3_example(example))
            results.append({"engine": name, "status": "ok",
                            "verdict": parse_z3_row(output, label),
                            "time_ms": batch.time(f"z3:{example}")})
        elif name == "cvc5":
            example, label = engine_label
            output = batch.get(f"z3:{example}", lambda: run_z3_example(example))
            results.append({"engine": name, "status": "ok",
                            "verdict": parse_cvc5_row(output, label),
                            "time_ms": batch.time(f"z3:{example}")})
        elif name == "clingo":
            output = batch.get("clingo", run_clingo)
            results.append({"engine": name, "status": "ok",
                            "verdict": parse_clingo(output, engine_label),
                            "time_ms": batch.time("clingo")})
        elif name == "pysat":
            output = batch.get("pysat", run_pysat)
            results.append({"engine": name, "status": "ok",
                            "verdict": parse_pysat(output, engine_label),
                            "time_ms": batch.time("pysat")})
        elif name == "souffle":
            output = batch.get("souffle", run_souffle)
            results.append({"engine": name, "status": "ok",
                            "verdict": parse_souffle(output, engine_label),
                            "time_ms": batch.time("souffle")})
        elif name == "prolog":
            output = batch.get("prolog", run_prolog)
            results.append({"engine": name, "status": "ok",
                            "verdict": parse_prolog(output, engine_label),
                            "time_ms": batch.time("prolog")})
    return {"fixture": fixture, "engines": results}


def consensus(engine_results: list[dict]) -> tuple[str, str]:
    decided = {r["engine"]: r["verdict"]
               for r in engine_results
               if r.get("status") == "ok"
               and r.get("verdict") in ("SAFE", "UNSAFE")}
    if not decided:
        return "INCONCLUSIVE", "no engine produced a definitive verdict"
    unique = set(decided.values())
    if len(unique) == 1:
        v = unique.pop()
        return "CONSENSUS", f"{v} ({len(decided)} engine(s))"
    parts = sorted(f"{e}={v}" for e, v in decided.items())
    return "DISAGREEMENT", "; ".join(parts)


def render(results: list[dict]) -> int:
    print()
    overall = {"CONSENSUS": 0, "DISAGREEMENT": 0, "INCONCLUSIVE": 0}
    expected_match = 0
    show_timing = "--no-timing" not in sys.argv
    for entry in results:
        fixture = entry["fixture"]
        engines = entry["engines"]
        status, detail = consensus(engines)
        overall[status] += 1

        # Did consensus match the expected verdict?
        expected = fixture["expected"]
        if status == "CONSENSUS" and expected in detail:
            expected_match += 1

        print(f"=== {fixture['label']}  (expected {expected}) ===")
        for r in engines:
            name = r["engine"]
            st = r.get("status")
            if st == "ok":
                v = r["verdict"]
                ms = r.get("time_ms", 0)
                marker = "[ok]" if v in ("SAFE", "UNSAFE") else "[??]"
                tail = f"  ({ms} ms)" if show_timing else ""
                print(f"  {marker}  {name:12s}  {v:13s}{tail}")
            elif st == "not_available":
                print(f"  [--]  {name:12s}  not available")
            elif st == "no_coverage":
                print(f"  [--]  {name:12s}  no example covers this fixture")
            else:
                print(f"  [ER]  {name:12s}  {st}")
        marker = "==" if status == "CONSENSUS" else "!="
        print(f"  {marker} {status}: {detail}")
        print()

    total = len(results)
    print("=" * 60)
    print(f"  Total fixtures:    {total}")
    print(f"  Consensus:         {overall['CONSENSUS']}")
    print(f"  Disagreements:     {overall['DISAGREEMENT']}")
    print(f"  Inconclusive:      {overall['INCONCLUSIVE']}")
    print(f"  Matching expected: {expected_match}/{total}")
    print()
    if overall["DISAGREEMENT"] > 0:
        print(f"  {overall['DISAGREEMENT']} disagreement(s) — see README for blind-spot interpretation.")
    else:
        print("  All available engines agree on every fixture.")
    # Harness is informational: exit 0 on successful end-to-end
    # run regardless of disagreements. Disagreements are the
    # value, not the failure. Use --strict to gate on consensus.
    if "--strict" in sys.argv and overall["DISAGREEMENT"] > 0:
        return 1
    return 0


def main() -> int:
    engines = load_engines()
    availability = {e["name"]: check_available(e) for e in engines}
    print("Engine availability:")
    for e in engines:
        ok = availability[e["name"]]
        print(f"  {e['name']:12s}  {'available' if ok else 'NOT available'}")
    print()

    if not (STAVE_ROOT / "stave").exists():
        print(f"warning: stave binary not found at {STAVE_ROOT}/stave")
        print("build with: cd stave && make build")
        return 2

    batch = BatchCache()
    results = []
    for fixture in FIXTURES:
        results.append(evaluate_fixture(fixture, engines, availability, batch))
    if "--json" in sys.argv:
        sys.stdout.write(json.dumps(
            [_serialize(r) for r in results], indent=2,
        ))
        return 0
    return render(results)


def _serialize(entry: dict) -> dict:
    return {
        "fixture": {
            "id": entry["fixture"]["id"],
            "label": entry["fixture"]["label"],
            "expected": entry["fixture"]["expected"],
        },
        "engines": entry["engines"],
    }


if __name__ == "__main__":
    sys.exit(main())

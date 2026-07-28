"""Tests for the framework-agnostic Stave verify core."""
import os
import sys

import stave_verify_core as c

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))   # bizacademy root
STAVE_BIN = os.path.join(REPO, "stave", "stave")
SNAP = os.path.join(REPO, "ctf", "bishopfox", "observations")
NOW = "2026-05-30T12:00:00Z"


def _verify(**kw):
    return c.verify(SNAP, stave_bin=STAVE_BIN, now=NOW, **kw)


def test_full_catalog_finds_violations():
    r = _verify()
    assert r["status"] == "fail"
    assert r["finding_count"] == 31           # matches the Bishop Fox scorecard
    assert r["error"] is None


def test_finding_shape_is_agent_friendly():
    f = _verify()["findings"][0]
    for k in ("control_id", "resource", "severity", "description", "evidence", "engine", "remediation_hint"):
        assert k in f, k
    assert f["control_id"].startswith("CTL.")
    assert f["engine"] in ("cel", "souffle")
    assert f["remediation_hint"]  # populated from the control's remediation


def test_quick_pack_scopes_down():
    # 'quick' excludes the IAM-escalation controls -> 0 here (documented gotcha).
    r = _verify(pack="quick")
    assert r["status"] == "pass" and r["finding_count"] == 0


def test_verify_text_surfaces():
    assert c.verify_text(SNAP, stave_bin=STAVE_BIN, now=NOW).startswith("FAIL")
    assert "PASS" in c.verify_text(SNAP, stave_bin=STAVE_BIN, now=NOW, pack="quick")


def test_error_path_is_explicit():
    r = c.verify("/nonexistent/snapshot/dir", stave_bin=STAVE_BIN)
    assert r["status"] == "error" and r["error"]


def test_framework_shims_import_without_frameworks():
    import crewai_tool
    import langchain_tool
    # modules import even without langchain/crewai; tools raise a clear error if used
    for fn in (langchain_tool.StaveVerifyTool, crewai_tool.stave_verify_tool):
        try:
            fn(); assert False, "expected ImportError"
        except ImportError:
            pass


if __name__ == "__main__":
    if not os.path.exists(STAVE_BIN):
        print(f"SKIP: stave binary not built at {STAVE_BIN}")
        sys.exit(0)
    fails = 0
    for n, fn in sorted(globals().items()):
        if n.startswith("test_") and callable(fn):
            try:
                fn(); print(f"PASS {n}")
            except AssertionError as e:
                fails += 1; print(f"FAIL {n}: {e}")
    sys.exit(1 if fails else 0)

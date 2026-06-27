"""Tests for the PR comment formatter."""
import stave_pr_report as r


def test_zero_findings_is_pass():
    body, n = r.render({"findings": [], "run": {"tool_version": "x", "snapshots": 2}})
    assert n == 0
    assert "no findings" in body and "✅" in body
    assert r._MARK in body  # marker for comment de-dup


def test_findings_table_and_severity_order():
    doc = {"run": {"tool_version": "x", "snapshots": 1}, "findings": [
        {"control_id": "CTL.A", "control_severity": "low", "asset_id": "arn:aws:s3:::b", "control_name": "Low one"},
        {"control_id": "CTL.B", "control_severity": "critical", "asset_id": "arn:aws:iam::1:role/r", "control_name": "Crit one"},
    ]}
    body, n = r.render(doc)
    assert n == 2
    # critical sorts before low
    assert body.index("CTL.B") < body.index("CTL.A")
    # ARNs are shortened to the last segment
    assert "`role/r`" in body and "`b`" in body
    assert "deterministic violations, not suggestions" in body


def test_short_arn():
    assert r._short_arn("arn:aws:iam::123:role/admin") == "role/admin"
    assert r._short_arn("plain-id") == "plain-id"


if __name__ == "__main__":
    import sys
    fails = 0
    for n, fn in sorted(globals().items()):
        if n.startswith("test_") and callable(fn):
            try:
                fn(); print(f"PASS {n}")
            except AssertionError as e:
                fails += 1; print(f"FAIL {n}: {e}")
    sys.exit(1 if fails else 0)

"""Iter 3.1.1 harness tests.

Verify that the stdin->stdout pipe is correct before adding any
Z3 logic in 3.1.2:
  - SIR JSON round-trips through ``sir.Document.from_json``.
  - ``main.py`` invoked as a subprocess with valid SIR on stdin
    produces an empty JSON array on stdout and exits 0.
  - Malformed input produces an error object on stderr and
    exits 2.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from stave_solver import sir


SAMPLE_SIR = {
    "controls": [
        {
            "id": "CTL.S3.PUBLIC.001",
            "type": "unsafe_state",
            "severity": "high",
            "predicate": {"logic": "any", "rules": []},
            "source": {"kind": "control", "id": "CTL.S3.PUBLIC.001"},
        }
    ],
    "assets": [
        {
            "id": "arn:aws:s3:::demo",
            "type": "aws_s3_bucket",
            "vendor": "aws",
            "properties": {},
            "source": {"kind": "asset", "id": "arn:aws:s3:::demo"},
        }
    ],
    "identities": [],
    "effective_permissions": [],
    "temporal": {"observations": [], "windows": []},
    "evaluated_at": "2026-05-05T12:00:00Z",
}


def test_document_from_json_roundtrips_known_keys() -> None:
    doc = sir.Document.from_json(json.dumps(SAMPLE_SIR))
    assert len(doc.controls) == 1
    assert doc.controls[0].id == "CTL.S3.PUBLIC.001"
    assert len(doc.assets) == 1
    assert doc.assets[0].id == "arn:aws:s3:::demo"
    assert doc.evaluated_at == "2026-05-05T12:00:00Z"


def test_document_from_json_unknown_key_warns_does_not_error(capsys: pytest.CaptureFixture[str]) -> None:
    payload = dict(SAMPLE_SIR)
    payload["x_future_field"] = ["whatever"]
    sir.Document.from_json(json.dumps(payload))
    err = capsys.readouterr().err
    assert "x_future_field" in err


def test_document_from_json_rejects_non_object() -> None:
    with pytest.raises(ValueError):
        sir.Document.from_json("[]")


def test_main_subprocess_empty_findings_array(tmp_path: Path) -> None:
    fixture = tmp_path / "sir.json"
    fixture.write_text(json.dumps(SAMPLE_SIR))
    result = subprocess.run(
        [sys.executable, "-m", "stave_solver.main"],
        input=fixture.read_bytes(),
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, f"stderr: {result.stderr.decode(errors='replace')}"
    parsed = json.loads(result.stdout)
    assert parsed == [], f"expected empty array, got {parsed}"


def test_main_subprocess_malformed_input_errors() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "stave_solver.main"],
        input=b"{not json",
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 2, f"stdout: {result.stdout.decode(errors='replace')}"
    err = result.stderr.decode(errors="replace")
    assert '"error"' in err, f"missing error key in stderr: {err}"


def test_main_subprocess_empty_input_produces_empty_array() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "stave_solver.main"],
        input=b"",
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout) == []

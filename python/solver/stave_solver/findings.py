"""Stave Finding output dataclass.

Mirrors the wire-format produced by Stave's Go side
(``internal/adapters/output/dto/types_finding.go``). The fields
listed here are the SUBSET the solver populates today; the Go
unmarshal is tolerant of missing fields, so absent keys read as
zero-values on the Stave side.

When ``SuggestedFix`` is added in 3.1.3, this file gains the
matching dataclass; until then the optional field is None and
omits cleanly from the JSON via ``omit_none``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SourceRef:
    kind: str = ""
    id: str = ""
    path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "id": self.id}
        if self.path:
            out["path"] = list(self.path)
        return out


@dataclass
class FixChange:
    """One element of a SuggestedFix.changes list. Populated in
    Iter 3.1.3; the v1 vocabulary covers ``remove`` /
    ``constrain`` / ``add_deny`` operations.
    """

    target: SourceRef = field(default_factory=SourceRef)
    operation: str = ""
    parameter: str = ""
    proves_unsat: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "operation": self.operation,
            "parameter": self.parameter,
            "proves_unsat": self.proves_unsat,
        }


@dataclass
class SuggestedFix:
    description: str = ""
    changes: list[FixChange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "changes": [c.to_dict() for c in self.changes],
        }


@dataclass
class Finding:
    """Stave Finding wire format.

    Field names match ``FindingDTO`` exactly; a mismatch here
    causes unmarshal failures in the Go bridge that look like
    solver bugs and are hard to debug. Keep this list in sync
    with the Go-side DTO.
    """

    control_id: str = ""
    asset_id: str = ""
    verdict: str = ""
    control_severity: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    contributing_sources: list[SourceRef] = field(default_factory=list)
    suggested_fix: Optional[SuggestedFix] = None
    logical_proof: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "control_id": self.control_id,
            "asset_id": self.asset_id,
            "verdict": self.verdict,
            "evidence": dict(self.evidence) if self.evidence else {},
        }
        if self.control_severity:
            out["control_severity"] = self.control_severity
        if self.contributing_sources:
            out["contributing_sources"] = [s.to_dict() for s in self.contributing_sources]
        if self.suggested_fix is not None:
            out["suggested_fix"] = self.suggested_fix.to_dict()
        if self.logical_proof:
            out["logical_proof"] = self.logical_proof
        return out

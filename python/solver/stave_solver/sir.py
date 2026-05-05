"""Python dataclasses mirroring the Go SIR types.

Source-of-truth for field names and JSON shape:
``internal/core/sir/types.go``. When the Go side adds a field,
this module gains the same field; an absent field on the wire
uses the dataclass default (None or empty).

``Document.from_json`` is the entry point. It logs unknown
top-level keys to stderr so a Go-side schema change that this
side hasn't yet absorbed is visible at the seam rather than
silently dropped.
"""
from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class SourceRef:
    kind: str = ""
    id: str = ""
    path: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SourceRef":
        return cls(
            kind=data.get("kind", ""),
            id=data.get("id", ""),
            path=list(data.get("path", []) or []),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "id": self.id}
        if self.path:
            out["path"] = list(self.path)
        return out


@dataclass
class ConditionFact:
    operator: str = ""
    key: str = ""
    values: list[str] = field(default_factory=list)


@dataclass
class PermissionFact:
    action: str = ""
    resource: str = ""
    conditions: list[ConditionFact] = field(default_factory=list)
    source: Optional[SourceRef] = None


@dataclass
class ValidityWindow:
    from_time: str = ""
    until: str = ""
    principal_scope: str = ""
    network_scope: str = ""
    trust_boundary: str = ""
    permissions: list[PermissionFact] = field(default_factory=list)
    source: Optional[SourceRef] = None


@dataclass
class IdentityFact:
    principal_id: str = ""
    validity: list[ValidityWindow] = field(default_factory=list)
    role_chains: list[Any] = field(default_factory=list)
    source: Optional[SourceRef] = None


@dataclass
class AssetLifecycleFact:
    provisioned: bool = False
    decommissioned: bool = False
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class AssetFact:
    id: str = ""
    type: str = ""
    vendor: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    lifecycle: Optional[AssetLifecycleFact] = None
    source: Optional[SourceRef] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AssetFact":
        lc_raw = data.get("lifecycle")
        lifecycle = None
        if lc_raw is not None:
            lifecycle = AssetLifecycleFact(
                provisioned=lc_raw.get("provisioned", False),
                decommissioned=lc_raw.get("decommissioned", False),
                first_seen=lc_raw.get("first_seen", ""),
                last_seen=lc_raw.get("last_seen", ""),
            )
        return cls(
            id=data.get("id", ""),
            type=data.get("type", ""),
            vendor=data.get("vendor", ""),
            properties=dict(data.get("properties", {}) or {}),
            lifecycle=lifecycle,
            source=SourceRef.from_dict(data["source"]) if data.get("source") else None,
        )


@dataclass
class TypedPrincipal:
    """One typed principal in a bucket-policy or IAM statement."""

    kind: str = ""
    value: str = ""
    is_public: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TypedPrincipal":
        return cls(
            kind=data.get("kind", ""),
            value=data.get("value", ""),
            is_public=data.get("is_public", False),
        )


@dataclass
class ConditionFact:
    operator: str = ""
    key: str = ""
    values: list[str] = field(default_factory=list)
    source: Optional[SourceRef] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConditionFact":
        return cls(
            operator=data.get("operator", ""),
            key=data.get("key", ""),
            values=list(data.get("values", []) or []),
            source=SourceRef.from_dict(data["source"]) if data.get("source") else None,
        )


@dataclass
class BucketPolicyStatementFact:
    statement_index: int = 0
    sid: str = ""
    effect: str = ""
    principals: list[TypedPrincipal] = field(default_factory=list)
    not_principals: list[TypedPrincipal] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    conditions: list[ConditionFact] = field(default_factory=list)
    source: Optional[SourceRef] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BucketPolicyStatementFact":
        return cls(
            statement_index=int(data.get("statement_index", 0) or 0),
            sid=data.get("sid", ""),
            effect=data.get("effect", ""),
            principals=[TypedPrincipal.from_dict(p) for p in (data.get("principals") or [])],
            not_principals=[TypedPrincipal.from_dict(p) for p in (data.get("not_principals") or [])],
            actions=list(data.get("actions", []) or []),
            not_actions=list(data.get("not_actions", []) or []),
            resources=list(data.get("resources", []) or []),
            not_resources=list(data.get("not_resources", []) or []),
            conditions=[ConditionFact.from_dict(c) for c in (data.get("conditions") or [])],
            source=SourceRef.from_dict(data["source"]) if data.get("source") else None,
        )


@dataclass
class ACLGrantFact:
    grantee_kind: str = ""
    grantee_uri: str = ""
    grantee_id: str = ""
    grantee_email: str = ""
    permission: str = ""
    is_public: bool = False
    is_any_auth: bool = False
    source: Optional[SourceRef] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ACLGrantFact":
        return cls(
            grantee_kind=data.get("grantee_kind", ""),
            grantee_uri=data.get("grantee_uri", ""),
            grantee_id=data.get("grantee_id", ""),
            grantee_email=data.get("grantee_email", ""),
            permission=data.get("permission", ""),
            is_public=data.get("is_public", False),
            is_any_auth=data.get("is_any_auth", False),
            source=SourceRef.from_dict(data["source"]) if data.get("source") else None,
        )


@dataclass
class PublicAccessBlockFact:
    block_public_acls: bool = False
    ignore_public_acls: bool = False
    block_public_policy: bool = False
    restrict_public_buckets: bool = False
    source: Optional[SourceRef] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PublicAccessBlockFact":
        return cls(
            block_public_acls=data.get("block_public_acls", False),
            ignore_public_acls=data.get("ignore_public_acls", False),
            block_public_policy=data.get("block_public_policy", False),
            restrict_public_buckets=data.get("restrict_public_buckets", False),
            source=SourceRef.from_dict(data["source"]) if data.get("source") else None,
        )


@dataclass
class IAMPolicyStatementFact:
    statement_index: int = 0
    sid: str = ""
    effect: str = ""
    principals: list[TypedPrincipal] = field(default_factory=list)
    not_principals: list[TypedPrincipal] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    conditions: list[ConditionFact] = field(default_factory=list)
    attached_to: Optional[TypedPrincipal] = None
    policy_arn: str = ""
    source: Optional[SourceRef] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IAMPolicyStatementFact":
        return cls(
            statement_index=int(data.get("statement_index", 0) or 0),
            sid=data.get("sid", ""),
            effect=data.get("effect", ""),
            principals=[TypedPrincipal.from_dict(p) for p in (data.get("principals") or [])],
            not_principals=[TypedPrincipal.from_dict(p) for p in (data.get("not_principals") or [])],
            actions=list(data.get("actions", []) or []),
            not_actions=list(data.get("not_actions", []) or []),
            resources=list(data.get("resources", []) or []),
            not_resources=list(data.get("not_resources", []) or []),
            conditions=[ConditionFact.from_dict(c) for c in (data.get("conditions") or [])],
            attached_to=TypedPrincipal.from_dict(data["attached_to"]) if data.get("attached_to") else None,
            policy_arn=data.get("policy_arn", ""),
            source=SourceRef.from_dict(data["source"]) if data.get("source") else None,
        )


@dataclass
class ResourceFactGroup:
    """Per-resource bundle of raw vector facts. The Z3 solver
    composes Policy ∪ ACL ∪ AttachedIAM minus PAB suppression
    from the inputs in this group."""

    asset_id: str = ""
    vendor: str = ""
    service_area: str = ""
    bucket_policy: list[BucketPolicyStatementFact] = field(default_factory=list)
    acl_grants: list[ACLGrantFact] = field(default_factory=list)
    pab: list[PublicAccessBlockFact] = field(default_factory=list)
    attached_iam: list[IAMPolicyStatementFact] = field(default_factory=list)
    source: Optional[SourceRef] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResourceFactGroup":
        return cls(
            asset_id=data.get("asset_id", ""),
            vendor=data.get("vendor", ""),
            service_area=data.get("service_area", ""),
            bucket_policy=[BucketPolicyStatementFact.from_dict(s) for s in (data.get("bucket_policy") or [])],
            acl_grants=[ACLGrantFact.from_dict(g) for g in (data.get("acl_grants") or [])],
            pab=[PublicAccessBlockFact.from_dict(p) for p in (data.get("pab") or [])],
            attached_iam=[IAMPolicyStatementFact.from_dict(i) for i in (data.get("attached_iam") or [])],
            source=SourceRef.from_dict(data["source"]) if data.get("source") else None,
        )


@dataclass
class RuleFact:
    field_path: str = ""
    operator: str = ""
    value: Any = None
    nested: Optional["PredicateFact"] = None
    source: Optional[SourceRef] = None


@dataclass
class PredicateFact:
    logic: str = ""
    rules: list[RuleFact] = field(default_factory=list)


@dataclass
class ControlFact:
    id: str = ""
    type: str = ""
    severity: str = ""
    predicate: PredicateFact = field(default_factory=PredicateFact)
    threshold_hours: Optional[float] = None
    intent_rationale: str = ""
    forbidden_state: Optional[PredicateFact] = None
    source: Optional[SourceRef] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ControlFact":
        return cls(
            id=data.get("id", ""),
            type=data.get("type", ""),
            severity=data.get("severity", ""),
            threshold_hours=data.get("threshold_hours"),
            intent_rationale=data.get("intent_rationale", ""),
            source=SourceRef.from_dict(data["source"]) if data.get("source") else None,
        )


@dataclass
class TemporalFacts:
    observations: list[str] = field(default_factory=list)
    windows: list[Any] = field(default_factory=list)


@dataclass
class Document:
    controls: list[ControlFact] = field(default_factory=list)
    assets: list[AssetFact] = field(default_factory=list)
    identities: list[IdentityFact] = field(default_factory=list)
    resource_groups: list[ResourceFactGroup] = field(default_factory=list)
    temporal: TemporalFacts = field(default_factory=TemporalFacts)
    evaluated_at: str = ""

    @classmethod
    def from_json(cls, payload: str) -> "Document":
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError(f"SIR document must be a JSON object; got {type(data).__name__}")

        known = {
            "controls",
            "assets",
            "identities",
            "resource_groups",
            "temporal",
            "evaluated_at",
        }
        for key in data.keys():
            if key not in known:
                logger.warning("sir: unknown top-level key %r (ignored)", key)
                print(f"sir: unknown top-level key {key!r}", file=sys.stderr)

        return cls(
            controls=[ControlFact.from_dict(c) for c in (data.get("controls") or [])],
            assets=[AssetFact.from_dict(a) for a in (data.get("assets") or [])],
            identities=[
                IdentityFact(
                    principal_id=i.get("principal_id", ""),
                    role_chains=list(i.get("role_chains", []) or []),
                    source=SourceRef.from_dict(i["source"]) if i.get("source") else None,
                )
                for i in (data.get("identities") or [])
            ],
            resource_groups=[
                ResourceFactGroup.from_dict(g)
                for g in (data.get("resource_groups") or [])
            ],
            evaluated_at=data.get("evaluated_at", ""),
        )

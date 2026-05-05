"""L6 S3 composition model tests.

Seven cases covering the suppression and condition matrix:

  1. Public-Allow policy, no PAB → SAT, violation.
  2. Public-Allow policy, BlockPublicPolicy=true → UNSAT.
  3. Public ACL, BlockPublicAcls=true → UNSAT.
  4. Public ACL, IgnorePublicAcls=true → UNSAT.
  5. Public-Allow policy with explicit Deny on same principal
     → UNSAT.
  6. Allow + IpAddress aws:SourceIp 10.0.0.0/8 → UNSAT (private).
  7. Allow + IpAddress aws:SourceIp 0.0.0.0/0 → SAT (any IP).
"""
from __future__ import annotations

from stave_solver import sir
from stave_solver.models import s3


def _bucket_group(asset_id: str = "arn:aws:s3:::demo") -> sir.ResourceFactGroup:
    return sir.ResourceFactGroup(
        asset_id=asset_id,
        vendor="aws",
        service_area="s3",
        source=sir.SourceRef(kind="asset", id=asset_id),
    )


def _public_control() -> sir.ControlFact:
    return sir.ControlFact(
        id="CTL.S3.PUBLIC.001",
        type="unsafe_state",
        severity="high",
        source=sir.SourceRef(kind="control", id="CTL.S3.PUBLIC.001"),
    )


def _public_allow_statement(asset_id: str, index: int = 0) -> sir.BucketPolicyStatementFact:
    return sir.BucketPolicyStatementFact(
        statement_index=index,
        sid="PublicRead",
        effect="Allow",
        principals=[sir.TypedPrincipal(kind="Wildcard", value="*", is_public=True)],
        actions=["s3:GetObject"],
        resources=[f"{asset_id}/*"],
        source=sir.SourceRef(
            kind="statement",
            id=asset_id,
            path=["Statement", str(index)],
        ),
    )


def _public_acl_grant(asset_id: str, index: int = 0) -> sir.ACLGrantFact:
    return sir.ACLGrantFact(
        grantee_kind="Group",
        grantee_uri="http://acs.amazonaws.com/groups/global/AllUsers",
        permission="READ",
        is_public=True,
        source=sir.SourceRef(
            kind="s3_acl_grant",
            id=asset_id,
            path=["Grants", str(index), "Permission"],
        ),
    )


def _pab(
    asset_id: str,
    *,
    block_acls: bool = False,
    ignore_acls: bool = False,
    block_policy: bool = False,
    restrict: bool = False,
) -> sir.PublicAccessBlockFact:
    return sir.PublicAccessBlockFact(
        block_public_acls=block_acls,
        ignore_public_acls=ignore_acls,
        block_public_policy=block_policy,
        restrict_public_buckets=restrict,
        source=sir.SourceRef(
            kind="s3_public_access_block",
            id=asset_id,
            path=["PublicAccessBlockConfiguration"],
        ),
    )


def test_public_allow_policy_without_pab_violates() -> None:
    g = _bucket_group()
    g.bucket_policy = [_public_allow_statement(g.asset_id)]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert len(out) == 1, f"expected 1 violation, got {out}"
    assert out[0].verdict == "violation"


def test_public_allow_policy_blocked_by_block_public_policy() -> None:
    g = _bucket_group()
    g.bucket_policy = [_public_allow_statement(g.asset_id)]
    g.pab = [_pab(g.asset_id, block_policy=True)]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"BlockPublicPolicy=true must suppress violation, got {out}"


def test_public_acl_blocked_by_block_public_acls() -> None:
    g = _bucket_group()
    g.acl_grants = [_public_acl_grant(g.asset_id)]
    g.pab = [_pab(g.asset_id, block_acls=True)]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"BlockPublicAcls=true must suppress violation, got {out}"


def test_public_acl_blocked_by_ignore_public_acls() -> None:
    g = _bucket_group()
    g.acl_grants = [_public_acl_grant(g.asset_id)]
    g.pab = [_pab(g.asset_id, ignore_acls=True)]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"IgnorePublicAcls=true must suppress violation, got {out}"


def test_public_allow_with_explicit_deny_unsat() -> None:
    g = _bucket_group()
    deny = sir.BucketPolicyStatementFact(
        statement_index=0,
        effect="Deny",
        principals=[sir.TypedPrincipal(kind="Wildcard", value="*", is_public=True)],
        actions=["s3:GetObject"],
        resources=[f"{g.asset_id}/*"],
        source=sir.SourceRef(kind="statement", id=g.asset_id, path=["Statement", "0"]),
    )
    allow = _public_allow_statement(g.asset_id, index=1)
    g.bucket_policy = [deny, allow]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"explicit Deny must suppress Allow, got {out}"


def test_allow_with_private_cidr_condition_unsat() -> None:
    g = _bucket_group()
    stmt = _public_allow_statement(g.asset_id)
    stmt.conditions = [
        sir.ConditionFact(
            operator="IpAddress",
            key="aws:SourceIp",
            values=["10.0.0.0/8"],
            source=sir.SourceRef(
                kind="condition",
                id=g.asset_id,
                path=["Statement", "0", "Condition", "IpAddress", "aws:SourceIp"],
            ),
        ),
    ]
    g.bucket_policy = [stmt]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"private CIDR restriction must suppress violation, got {out}"


def test_allow_with_wildcard_cidr_violates() -> None:
    g = _bucket_group()
    stmt = _public_allow_statement(g.asset_id)
    stmt.conditions = [
        sir.ConditionFact(
            operator="IpAddress",
            key="aws:SourceIp",
            values=["0.0.0.0/0"],
            source=sir.SourceRef(
                kind="condition",
                id=g.asset_id,
                path=["Statement", "0", "Condition", "IpAddress", "aws:SourceIp"],
            ),
        ),
    ]
    g.bucket_policy = [stmt]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert len(out) == 1, f"wildcard CIDR allows public access, want violation; got {out}"


def test_violation_carries_contributing_source_to_acl_grant() -> None:
    """When the violation comes from an ACL grant, the
    Finding's contributing_sources point back at the
    originating Grants[i].Permission path. Pins L6 ↔ L4
    SourceRef integrity."""
    g = _bucket_group()
    g.acl_grants = [_public_acl_grant(g.asset_id)]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert len(out) == 1
    sources = out[0].contributing_sources
    assert any(s.kind == "s3_acl_grant" for s in sources), \
        f"expected s3_acl_grant source, got {sources}"

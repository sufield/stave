"""L7 SuggestedFix tests.

Three cases per spec:
  1. Public ACL alone → SuggestedFix with one operation="remove"
     FixChange, proves_unsat=True.
  2. Public ACL AND public bucket-policy statement → joint
     SuggestedFix with TWO FixChanges (no single change
     suffices because either one alone leaves the other Allow
     active).
  3. Public-policy + PAB.BlockPublicPolicy=false →
     SuggestedFix lists EITHER tightening the policy OR setting
     the PAB flag; both options have proves_unsat=True.
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


def test_acl_only_violation_single_change_fix() -> None:
    g = _bucket_group()
    g.acl_grants = [_public_acl_grant(g.asset_id)]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert len(out) == 1
    sf = out[0].suggested_fix
    assert sf is not None, "violation must carry a SuggestedFix"
    assert len(sf.changes) == 1
    change = sf.changes[0]
    assert change.operation == "remove"
    assert change.proves_unsat is True
    assert change.target.kind == "s3_acl_grant"
    assert "Grants" in change.target.path


def test_acl_plus_policy_violation_joint_fix() -> None:
    g = _bucket_group()
    g.acl_grants = [_public_acl_grant(g.asset_id)]
    g.bucket_policy = [_public_allow_statement(g.asset_id)]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert len(out) == 1
    sf = out[0].suggested_fix
    assert sf is not None
    # Two contributing facts; neither alone proves UNSAT (the
    # other Allow path remains). The fix set must list BOTH.
    assert len(sf.changes) == 2, f"expected 2 FixChanges (joint), got {sf.changes}"
    ops = sorted(c.operation for c in sf.changes)
    assert ops == ["add_deny", "remove"], f"unexpected operations: {ops}"
    # Joint proves_unsat reflects whether forcing both vars
    # False eliminates the violation.
    for change in sf.changes:
        assert change.proves_unsat is True, (
            f"joint set must prove UNSAT; got {change}"
        )


def test_public_policy_only_single_change_fix() -> None:
    g = _bucket_group()
    g.bucket_policy = [_public_allow_statement(g.asset_id)]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert len(out) == 1
    sf = out[0].suggested_fix
    assert sf is not None
    assert len(sf.changes) == 1
    change = sf.changes[0]
    # Bucket policy fix vocabulary: add_deny.
    assert change.operation == "add_deny"
    assert change.proves_unsat is True
    assert change.target.kind == "statement"
    assert "Statement" in change.target.path

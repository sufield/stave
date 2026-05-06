"""Iter 1 — condition encoder tests.

False-positive regression coverage: every (operator, key) pair
that the old IPv4-only handler silently dropped is now
explicitly modeled. Unhandled combinations fail closed.

Test groups:

  Priority 1 — org / VPCE / transport conditions that prevent
              false positives on org-restricted buckets.

  Priority 2 — ARN-pattern + date-range conditions that
              restrict access in ways the old encoder ignored.

  Priority 3 — fail-closed default for unknown
              (operator, key) pairs.

  Confused-deputy guards — aws:SourceArn / aws:SourceAccount
              shape used heavily in SNS / SQS production
              policies (107 / 93 / 79 hits in the catalog).
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


def _public_allow_with_condition(
    asset_id: str,
    operator: str,
    key: str,
    values: list[str],
    index: int = 0,
) -> sir.BucketPolicyStatementFact:
    """Helper: a public-Allow statement with one condition
    block. Tests inject (operator, key, values) to drive the
    handler dispatch."""
    return sir.BucketPolicyStatementFact(
        statement_index=index,
        sid="PublicWithCond",
        effect="Allow",
        principals=[sir.TypedPrincipal(kind="Wildcard", value="*", is_public=True)],
        actions=["s3:GetObject"],
        resources=[f"{asset_id}/*"],
        conditions=[
            sir.ConditionFact(
                operator=operator,
                key=key,
                values=list(values),
                source=sir.SourceRef(
                    kind="condition",
                    id=asset_id,
                    path=["Statement", str(index), "Condition", operator, key],
                ),
            ),
        ],
        source=sir.SourceRef(kind="statement", id=asset_id, path=["Statement", str(index)]),
    )


# ---------- Priority 1: PrincipalOrgID / SourceVpce / SecureTransport ----------

def test_org_restricted_bucket_no_longer_false_positive() -> None:
    """The load-bearing fix. Before Iter 1 a public-Allow
    statement with `StringEquals aws:PrincipalOrgID o-abc123`
    was reported as a public violation because the IPv4-only
    encoder silently dropped the org condition. After Iter 1
    the condition is recognized: a public principal carries no
    org membership, so the statement does not contribute to
    public access."""
    g = _bucket_group()
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "StringEquals", "aws:PrincipalOrgID", ["o-abc123"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"org-restricted bucket must NOT report public access; got {out}"


def test_string_not_equals_principal_org_id_still_violates() -> None:
    """`StringNotEquals aws:PrincipalOrgID o-abc123` permits
    any principal not in the named org — including the public
    wildcard. Solver must still surface this as a violation."""
    g = _bucket_group()
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "StringNotEquals", "aws:PrincipalOrgID", ["o-abc123"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert len(out) == 1, f"NotEquals on org id permits public principal; expected violation, got {out}"


def test_source_vpce_restricted_bucket_no_longer_false_positive() -> None:
    """`StringEquals aws:SourceVpce vpce-abc123`: public
    internet doesn't carry a SourceVpce, so the statement
    cannot contribute to a public violation."""
    g = _bucket_group()
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "StringEquals", "aws:SourceVpce", ["vpce-0123456789abcdef0"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"SourceVpce-restricted bucket must NOT report public access; got {out}"


def test_secure_transport_does_not_gate_access() -> None:
    """`Bool aws:SecureTransport true` enforces HTTPS but
    doesn't restrict WHO can access. A public-Allow with this
    condition is still a public violation — both HTTPS and
    HTTP are achievable from the public internet."""
    g = _bucket_group()
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "Bool", "aws:SecureTransport", ["true"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert len(out) == 1, f"SecureTransport=true does not gate access; expected violation, got {out}"


# ---------- Priority 2: PrincipalArn patterns + date conditions ----------

def test_principal_arn_specific_pattern_blocks_public() -> None:
    """`StringLike aws:PrincipalArn arn:aws:iam::111122223333:*`
    restricts access to a single account. A public principal
    matches no specific account pattern → no violation."""
    g = _bucket_group()
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "StringLike", "aws:PrincipalArn",
        ["arn:aws:iam::111122223333:*"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"PrincipalArn-restricted bucket must NOT report public access; got {out}"


def test_principal_arn_wildcard_pattern_still_violates() -> None:
    """`StringLike aws:PrincipalArn *` is functionally
    unconditioned. Public principal trivially matches → still
    a violation."""
    g = _bucket_group()
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "StringLike", "aws:PrincipalArn", ["*"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert len(out) == 1, f"wildcard PrincipalArn doesn't restrict; expected violation, got {out}"


def test_date_condition_treated_as_restricted() -> None:
    """`DateGreaterThan aws:CurrentTime ...` is a time gate.
    For the public-access query we conservatively model it as
    restricting — public-access reasoning isn't a temporal
    audit. Matches the spec's Priority 2 guidance."""
    g = _bucket_group()
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "DateGreaterThan", "aws:CurrentTime", ["2030-01-01T00:00:00Z"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"date-conditioned statement should not produce public violation; got {out}"


# ---------- Confused-deputy guards: SourceArn / SourceAccount ----------

def test_source_arn_guard_blocks_public() -> None:
    """`StringEquals aws:SourceArn arn:aws:sns:...`: an SNS
    topic invoking the bucket has a SourceArn; a public
    requester does not. Standard SNS-confused-deputy guard
    pattern, present 93× in the catalog."""
    g = _bucket_group()
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "StringEquals", "aws:SourceArn",
        ["arn:aws:sns:us-east-1:111122223333:topic"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"SourceArn-guarded statement must NOT produce public violation; got {out}"


def test_source_account_guard_blocks_public() -> None:
    """`StringEquals aws:SourceAccount 111122223333`: same
    confused-deputy pattern keyed on account ID instead of
    ARN. Public principal carries no source account."""
    g = _bucket_group()
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "StringEquals", "aws:SourceAccount", ["111122223333"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"SourceAccount-guarded statement must NOT produce public violation; got {out}"


# ---------- Priority 3: fail-closed default ----------

def test_unknown_condition_key_fails_closed() -> None:
    """Per the load-bearing rule: any (operator, key) pair the
    handler doesn't recognize defaults to FALSE — the
    statement does not contribute to public access. This
    prevents false positives from new AWS condition keys
    Stave hasn't yet absorbed."""
    g = _bucket_group()
    # Hypothetical future condition key Stave doesn't model.
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "StringEquals", "aws:SomeFutureCondition", ["restricted"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"unknown condition must fail closed; got {out}"


def test_unknown_operator_fails_closed() -> None:
    """Same fail-closed rule for unknown operators on known
    keys. A future AWS operator we haven't modeled defaults to
    restricting access."""
    g = _bucket_group()
    g.bucket_policy = [_public_allow_with_condition(
        g.asset_id, "FutureFancyOperator", "aws:PrincipalOrgID", ["o-abc123"],
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"unknown operator on known key must fail closed; got {out}"


# ---------- Multiple-conditions composition ----------

def test_multiple_conditions_conjoined() -> None:
    """A statement with multiple condition blocks must satisfy
    ALL of them (AWS evaluation rule). If any condition blocks
    public access, the statement does not contribute to a
    public violation."""
    asset_id = "arn:aws:s3:::demo"
    stmt = sir.BucketPolicyStatementFact(
        statement_index=0,
        sid="MultiCond",
        effect="Allow",
        principals=[sir.TypedPrincipal(kind="Wildcard", value="*", is_public=True)],
        actions=["s3:GetObject"],
        resources=[f"{asset_id}/*"],
        conditions=[
            # Permits public (HTTPS doesn't gate access).
            sir.ConditionFact(
                operator="Bool", key="aws:SecureTransport", values=["true"],
                source=sir.SourceRef(kind="condition", id=asset_id, path=["Statement", "0", "Condition", "Bool", "aws:SecureTransport"]),
            ),
            # Blocks public (org-restricted).
            sir.ConditionFact(
                operator="StringEquals", key="aws:PrincipalOrgID", values=["o-abc123"],
                source=sir.SourceRef(kind="condition", id=asset_id, path=["Statement", "0", "Condition", "StringEquals", "aws:PrincipalOrgID"]),
            ),
        ],
        source=sir.SourceRef(kind="statement", id=asset_id, path=["Statement", "0"]),
    )
    g = _bucket_group(asset_id)
    g.bucket_policy = [stmt]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert out == [], f"AND-composition: org-restriction blocks public even with permissive transport; got {out}"


def test_genuinely_public_no_conditions_still_violates() -> None:
    """Regression check: a statement with NO conditions still
    produces a public violation. This is the baseline case
    Iter 1 must not break."""
    g = _bucket_group()
    g.bucket_policy = [sir.BucketPolicyStatementFact(
        statement_index=0,
        sid="UnconditionalPublic",
        effect="Allow",
        principals=[sir.TypedPrincipal(kind="Wildcard", value="*", is_public=True)],
        actions=["s3:GetObject"],
        resources=[f"{g.asset_id}/*"],
        source=sir.SourceRef(kind="statement", id=g.asset_id, path=["Statement", "0"]),
    )]
    out = s3.S3SafetyModel(g).evaluate(_public_control())
    assert len(out) == 1, f"unconditional public-Allow must still violate; got {out}"

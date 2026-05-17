"""Compound-rule definitions for the SAT control-regression example.

Each rule names a set of control IDs whose simultaneous firing
constitutes an unsafe configuration. When all conjuncts hold,
the configuration violates the rule; otherwise it does not.

These mirror a subset of the Clingo `constraints.lp` patterns
but at the *control-verdict* layer (boolean: did finding fire?)
rather than the *atom* layer (relations between principals,
resources, actions). The point: SAT scales the boolean check
across the full control catalog at near-zero per-rule cost,
making this the right layer for compound-of-finding regression.

Format: name → list of control IDs that must all fire.
Negation (a control that must NOT fire) is encoded as the
string "!CTL.ID" — a control whose absence is required.
"""

COMPOUND_RULES: list[dict[str, object]] = [
    {
        "name": "rhino_passrole_with_role_hygiene_gap",
        "description": (
            "AutoScaling-PassRole primitive fires AND a role-hygiene "
            "finding fires on the same fixture. The privesc primitive "
            "alone is exploitable; combined with role-tagging gaps "
            "(unattributed roles), the attacker's lateral targets "
            "lack the intent-tag controls would otherwise enable."
        ),
        "controls": [
            "CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001",
            "CTL.IAM.ROLE.INTENTTAG.001",
        ],
    },
    {
        "name": "cognito_anon_to_aws_2of3",
        "description": (
            "Cognito self-registration enabled AND MFA disabled. "
            "Either gate alone is bad; together they hand AWS-"
            "credential issuance to anyone who completes the public "
            "sign-up flow without a second factor — the cognito-self-register "
            "choke-point shape."
        ),
        "controls": [
            "CTL.COGNITO.SELFREG.001",
            "CTL.COGNITO.MFA.001",
        ],
    },
    {
        "name": "cognito_full_id_bypass_3of3",
        "description": (
            "All three Cognito identity-bypass primitives fire: "
            "self-registration unrestricted, MFA off, advanced "
            "security off. The complete identity-bypass cascade — "
            "no rate-limit, no second factor, no anomaly detection. "
            "Stricter than the 2-of-3 compound above."
        ),
        "controls": [
            "CTL.COGNITO.SELFREG.001",
            "CTL.COGNITO.MFA.001",
            "CTL.COGNITO.ADVANCED.SECURITY.001",
        ],
    },

    # =====================================================
    # Expansion: IAM, S3, and cross-service compounds.
    #
    # Each rule references control IDs that real fixtures
    # actually emit (verified against the in-tree examples'
    # contributed_by edges). Compound semantics: every
    # conjunct must fire on the same fixture's facts; the SAT
    # encoding is unchanged from the existing rules above.
    #
    # Matrix-coverage caveat: scripts/h1-matrix/run.py loads
    # each fixture with its example's local controls/ directory
    # rather than the full catalog. Most in-tree examples ship
    # a single control, so multi-control compounds only fire
    # when PySAT is invoked against the FULL catalog (this
    # example's run.sh path) or against a fixture whose
    # example carries multiple controls (the demos/nodes-2026
    # capital-one fixture, which fires five controls
    # simultaneously, is the primary demonstration target for
    # these new rules).
    # =====================================================
    {
        "name": "cognito_anon_then_self_register",
        "description": (
            "Identity-pool unauthenticated access AND user-pool "
            "self-registration both fire on the same fixture. "
            "Either gate alone admits abuse; together the attacker "
            "has the full credential-issuance surface — anonymous "
            "S3 read PLUS cheap-to-create authenticated identities."
        ),
        "controls": [
            "CTL.COGNITO.IDPOOL.UNAUTH.S3.001",
            "CTL.COGNITO.SELFREG.001",
        ],
    },
    {
        "name": "weak_encryption_no_data_event_audit",
        "description": (
            "S3 server-side encryption is not customer-managed AND "
            "CloudTrail is not configured for data-event logging on "
            "the same bucket. The S3 control flags the cryptographic "
            "weakness; the CloudTrail control flags the lack of an "
            "audit trail. Together they're the post-breach scenario "
            "from the Capital One reconstruction: weak crypto, no "
            "tamper-evident log of who read what."
        ),
        "controls": [
            "CTL.S3.ENCRYPT.003",
            "CTL.CLOUDTRAIL.DATAEVENTS.S3.001",
        ],
    },
    {
        "name": "anonymous_compute_trust_no_audit",
        "description": (
            "Three controls fire simultaneously: the identity pool "
            "admits anonymous users, an IAM role mounts a dual "
            "compute-and-iam trust, and CloudTrail data-event "
            "coverage is missing. The full Capital One "
            "reconstruction in three-control form."
        ),
        "controls": [
            "CTL.COGNITO.IDPOOL.UNAUTH.S3.001",
            "CTL.IAM.TRUST.DUAL.001",
            "CTL.CLOUDTRAIL.DATAEVENTS.S3.001",
        ],
    },
    {
        "name": "iam_overperm_with_compute_trust",
        "description": (
            "Policy resource-wildcard finding fires on the same "
            "role that the autoscaling-PassRole privesc primitive "
            "flags. Wildcard = breadth, PassRole-bypass = vector. "
            "Combined: any compute service the role trusts becomes "
            "a privesc launcher. Mirrors the overperm-plus-compute-trust article."
        ),
        "controls": [
            "CTL.IAM.POLICY.RESOURCE.WILDCARD.001",
            "CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001",
        ],
    },
    {
        "name": "iam_overperm_and_iam_self_attach",
        "description": (
            "A wildcard-resource finding AND the "
            "iam:AttachUserPolicy self-mutation primitive on the "
            "same fixture. Wildcard hands broad current authority; "
            "self-attach hands future authority — any user in the "
            "principal set can grant themselves arbitrary policy "
            "attachments without ever asking IAM."
        ),
        "controls": [
            "CTL.IAM.POLICY.RESOURCE.WILDCARD.001",
            "CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001",
        ],
    },
]

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
            "sign-up flow without a second factor — the iter-16 "
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
]

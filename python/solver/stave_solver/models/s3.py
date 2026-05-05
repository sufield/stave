"""S3 effective-access composition model in Z3.

Reads a ResourceFactGroup (raw vectors: bucket policy, ACL
grants, PAB layers, attached IAM statements) and asks Z3:
"Is there a satisfying assignment where a public principal can
perform a sensitive action?".

This is the LIBRARIAN ↔ JUDGE split materialized: Stave emits
inputs, the solver composes them. No re-aggregation, no string
matching on policy text — every decision uses typed fields
already in the SIR.

Composition formula:
    policy_allow      = OR over Allow bucket-policy statements
                        matching (principal, action) with no
                        Deny statement overriding
    acl_allow         = OR over ACL grants matching
                        (principal, action) — READ → GetObject
                        + ListBucket, etc.
    iam_allow         = OR over Allow IAM statements matching
                        (principal, action)
    pab_blocks_acl    = (BlockPublicAcls OR IgnorePublicAcls)
                        AND principal is public
    pab_blocks_policy = BlockPublicPolicy AND principal is
                        public AND policy grants public access
    effective_allow   = (policy_allow AND NOT pab_blocks_policy)
                        OR (acl_allow AND NOT pab_blocks_acl)
                        OR iam_allow
    violation         = effective_allow AND principal == "*"
                        AND action in sensitive_actions

IPv4 conditions: source_ip is z3.Int in [0, 2^32-1] (NOT
BitVec — hard rule). CIDR ranges become Int range checks.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

import z3

from stave_solver import findings, sir


# Sensitive S3 actions for the public-exposure question. Iter
# L6 keeps the list narrow; future iterations promote control-
# specific action sets via SIR.ControlFact.predicate inspection.
SENSITIVE_S3_ACTIONS = {
    "s3:getobject",
    "s3:listbucket",
    "s3:putobject",
    "s3:deleteobject",
    "s3:putobjectacl",
    "s3:putbucketacl",
    "s3:*",
    "*",
}

# ACL permission → IAM action set. Mirrors the AWS ACL-to-action
# mapping the L4 grouper documents (READ → GetObject + ListBucket,
# etc.). The solver consumes this; the grouper does NOT.
ACL_PERMISSION_TO_ACTIONS: dict[str, set[str]] = {
    "READ": {"s3:getobject", "s3:listbucket"},
    "WRITE": {"s3:putobject", "s3:deleteobject"},
    "READ_ACP": {"s3:getbucketacl"},
    "WRITE_ACP": {"s3:putbucketacl"},
    "FULL_CONTROL": {
        "s3:getobject", "s3:listbucket",
        "s3:putobject", "s3:deleteobject",
        "s3:getbucketacl", "s3:putbucketacl",
    },
}


@dataclass
class _ContributingSource:
    """Internal pairing of a Z3 Bool variable with the SourceRef
    of the SIR fact it represents. The L7 fix suggester re-runs
    the solver with each contributing var negated to identify
    the minimal-fix set."""

    var: z3.BoolRef
    source: findings.SourceRef
    fact_kind: str  # "bucket_policy" | "acl_grant" | "iam_statement"


class S3SafetyModel:
    """Z3 composition model for one bucket's public-exposure
    question. Construct per (group, control); call evaluate()
    to get zero or one Finding.
    """

    def __init__(self, group: sir.ResourceFactGroup) -> None:
        self.group = group

    def evaluate(self, control: sir.ControlFact) -> list[findings.Finding]:
        """Return zero or one Finding for the (group, control) pair.

        Pipeline:
          1. Compose the violation formula (declares Bool vars
             per contributing fact). SAT → at least one allow
             path is open.
          2. Per-fact feasibility check (push/pop): each fact
             whose Bool var alone witnesses SAT is a real
             contributor.
          3. L7 fix builder: hypothesize one FixChange per
             contributor; re-check (push/pop) with each var
             forced False; proves_unsat=True iff that single
             change leaves the formula UNSAT.
        """
        builder = _FormulaBuilder(self.group)
        if not builder.has_any_allow_clause():
            return []

        s = z3.Solver()
        violation = builder.compose_public_violation_formula(s)
        s.add(violation)

        if s.check() != z3.sat:
            return []

        contributing_facts = builder.feasible_contributing_facts(s)
        if not contributing_facts:
            return []

        contributing_sources = [c.source for c in contributing_facts]
        suggested_fix = _build_suggested_fix(s, builder, contributing_facts, self.group)

        return [
            findings.Finding(
                control_id=control.id,
                asset_id=self.group.asset_id,
                verdict="violation",
                control_severity=control.severity,
                evidence={
                    "reason": "public principal can perform a sensitive action",
                    "actions": _sensitive_actions_in_group(self.group),
                },
                contributing_sources=contributing_sources,
                suggested_fix=suggested_fix,
                logical_proof=_explain(self.group),
            )
        ]


class _FormulaBuilder:
    """Encapsulates the Z3 formula construction. Exists so the
    L7 fix suggester can reuse the same formula structure when
    re-checking hypothesized fixes — the solver state is
    isolated from Finding emission.
    """

    def __init__(self, group: sir.ResourceFactGroup) -> None:
        self.group = group
        self.contributing: list[_ContributingSource] = []
        self._principal_str: Optional[z3.SeqRef] = None

    def principal(self) -> z3.SeqRef:
        if self._principal_str is None:
            self._principal_str = z3.String("principal")
        return self._principal_str

    def has_any_allow_clause(self) -> bool:
        """True iff the group has at least one fact that could
        contribute to an Allow path. Pre-flight check so the
        solver isn't asked to prove SAT on a trivially-empty
        formula."""
        for stmt in self.group.bucket_policy:
            if stmt.effect == "Allow":
                return True
        if self.group.acl_grants:
            return True
        for stmt in self.group.attached_iam:
            if stmt.effect == "Allow":
                return True
        return False

    def compose_public_violation_formula(self, s: z3.Solver) -> z3.BoolRef:
        """Compose the public-violation formula and return it
        as a single Z3 BoolRef. Caller adds it to the solver."""
        principal = self.principal()
        s.add(principal == z3.StringVal("*"))

        policy_allow = self._policy_allow_disjunction()
        acl_allow = self._acl_allow_disjunction()
        iam_allow = self._iam_allow_disjunction()

        pab_blocks_acl = self._pab_blocks_acl()
        pab_blocks_policy = self._pab_blocks_policy()

        effective_allow = z3.Or(
            z3.And(policy_allow, z3.Not(pab_blocks_policy)),
            z3.And(acl_allow, z3.Not(pab_blocks_acl)),
            iam_allow,
        )
        return effective_allow

    def contributing_sources_from_model(self, model: z3.ModelRef) -> list[findings.SourceRef]:
        """SourceRef list — see contributing_facts_from_model."""
        return [c.source for c in self.contributing_facts_from_model(model)]

    def contributing_facts_from_model(self, _model: z3.ModelRef) -> list[_ContributingSource]:
        """Deprecated, kept for callers that haven't switched.
        Use feasible_contributing_facts(s) which inspects the
        live solver via push/pop."""
        return list(self.contributing)

    def feasible_contributing_facts(self, s: z3.Solver) -> list[_ContributingSource]:
        """Return EVERY registered contributor that is by
        itself a feasible witness for the violation.

        Z3 produces minimal witnesses, so when ACL alone is
        sufficient the model assigns Policy=False and ACL=True
        — only ACL appears in the model. The user-facing
        finding wants BOTH ACL and Policy as contributors so
        the L7 fix suggester can reason about the joint set.

        Per-fact check: push, force this var True and all peers
        False, check, pop. SAT → this fact alone witnesses the
        violation, so it contributes. Uses the same Solver
        instance so var identities are preserved (a fresh
        solver with a recomposed formula yields different
        Bool vars).
        """
        out: list[_ContributingSource] = []
        for c in self.contributing:
            if self._is_feasible_contributor(s, c.var):
                out.append(c)
        return out

    def _is_feasible_contributor(self, s: z3.Solver, var: z3.BoolRef) -> bool:
        s.push()
        try:
            for c in self.contributing:
                if c.var is var:
                    s.add(c.var == z3.BoolVal(True))
                else:
                    s.add(c.var == z3.BoolVal(False))
            return s.check() == z3.sat
        finally:
            s.pop()

    def recheck_with_overrides(self, s: z3.Solver, overrides: dict) -> bool:
        """Re-run the existing formula with each Bool var in
        `overrides` forced to its mapped value. Returns True
        iff the formula is UNSAT under the overrides — the
        applied "fix" eliminates the violation. push/pop so
        the original solver state is preserved.
        """
        s.push()
        try:
            for var, val in overrides.items():
                s.add(var == z3.BoolVal(val))
            return s.check() == z3.unsat
        finally:
            s.pop()

    def _policy_allow_disjunction(self) -> z3.BoolRef:
        public_principal = self.principal() == z3.StringVal("*")
        # Explicit-deny precedence: any Deny on the public
        # principal short-circuits the entire policy_allow.
        deny_active = z3.BoolVal(False)
        for stmt in self.group.bucket_policy:
            if stmt.effect != "Deny":
                continue
            if not _statement_targets_public(stmt):
                continue
            deny_active = z3.Or(deny_active, z3.BoolVal(True))

        terms: list[z3.BoolRef] = []
        for stmt in self.group.bucket_policy:
            if stmt.effect != "Allow":
                continue
            if not _statement_has_sensitive_public_action(stmt):
                continue
            ip_check = _ip_condition_satisfied(stmt)
            var = z3.Bool(f"policy_stmt_{stmt.statement_index}")
            self.contributing.append(_ContributingSource(
                var=var,
                source=_source_ref_to_finding(stmt.source),
                fact_kind="bucket_policy",
            ))
            terms.append(z3.And(var, public_principal, ip_check))
        if not terms:
            return z3.BoolVal(False)
        return z3.And(z3.Or(*terms), z3.Not(deny_active))

    def _acl_allow_disjunction(self) -> z3.BoolRef:
        public_principal = self.principal() == z3.StringVal("*")
        terms: list[z3.BoolRef] = []
        for grant in self.group.acl_grants:
            if not grant.is_public:
                continue
            actions = ACL_PERMISSION_TO_ACTIONS.get(grant.permission.upper(), set())
            if not actions & SENSITIVE_S3_ACTIONS:
                continue
            var = z3.Bool(f"acl_grant_{grant.source.path[1] if grant.source and len(grant.source.path) > 1 else 'unknown'}")
            self.contributing.append(_ContributingSource(
                var=var,
                source=_source_ref_to_finding(grant.source),
                fact_kind="acl_grant",
            ))
            terms.append(z3.And(var, public_principal))
        if not terms:
            return z3.BoolVal(False)
        return z3.Or(*terms)

    def _iam_allow_disjunction(self) -> z3.BoolRef:
        terms: list[z3.BoolRef] = []
        for stmt in self.group.attached_iam:
            if stmt.effect != "Allow":
                continue
            if not _iam_statement_targets_sensitive(stmt):
                continue
            var = z3.Bool(f"iam_stmt_{stmt.statement_index}")
            self.contributing.append(_ContributingSource(
                var=var,
                source=_source_ref_to_finding(stmt.source),
                fact_kind="iam_statement",
            ))
            terms.append(var)
        if not terms:
            return z3.BoolVal(False)
        return z3.Or(*terms)

    def _pab_blocks_acl(self) -> z3.BoolRef:
        public_principal = self.principal() == z3.StringVal("*")
        for layer in self.group.pab:
            if layer.block_public_acls or layer.ignore_public_acls:
                return public_principal
        return z3.BoolVal(False)

    def _pab_blocks_policy(self) -> z3.BoolRef:
        # Composing PAB.BlockPublicPolicy + the policy granting
        # public access. We approximate "policy grants public
        # access" with public_principal here — the solver state
        # already constrains principal == "*", so this keeps
        # the formula tractable.
        public_principal = self.principal() == z3.StringVal("*")
        for layer in self.group.pab:
            if layer.block_public_policy or layer.restrict_public_buckets:
                return public_principal
        return z3.BoolVal(False)


def _statement_targets_public(stmt: sir.BucketPolicyStatementFact) -> bool:
    for p in stmt.principals:
        if p.is_public:
            return True
    return False


def _statement_has_sensitive_public_action(stmt: sir.BucketPolicyStatementFact) -> bool:
    if not _statement_targets_public(stmt):
        return False
    for action in stmt.actions:
        if action.lower() in SENSITIVE_S3_ACTIONS:
            return True
    return False


def _iam_statement_targets_sensitive(stmt: sir.IAMPolicyStatementFact) -> bool:
    for action in stmt.actions:
        if action.lower() in SENSITIVE_S3_ACTIONS:
            return True
    return False


def _ip_condition_satisfied(stmt: sir.BucketPolicyStatementFact) -> z3.BoolRef:
    """Convert IpAddress aws:SourceIp conditions into a Z3
    constraint expressing "this statement permits a PUBLIC
    requester".

    AWS IpAddress semantics: the statement matches when the
    source IP is inside ANY of the listed CIDRs (logical OR
    across the values list). For the public-violation
    question we additionally require the source IP to be a
    public-internet address (not RFC1918 / loopback / shared
    address space).

    Returns:
      - BoolVal(True) when no aws:SourceIp condition is present
        (the statement places no IP restriction; any public IP
        reaches it).
      - z3.And(in_listed_cidrs, is_public_ip) when at least one
        listed CIDR is parseable. If every listed CIDR is
        private, in_listed_cidrs ∧ is_public_ip is unsatisfiable
        — i.e., the statement only permits private IPs, no
        public violation possible.

    IPv4 modeled as z3.Int — never BitVec, per the prompt's
    hard rule.
    """
    has_ip_constraint = False
    listed_cidrs: list[z3.BoolRef] = []
    source_ip = z3.Int("source_ip")

    for cond in stmt.conditions:
        if cond.operator != "IpAddress":
            continue
        if cond.key.lower() != "aws:sourceip":
            continue
        for cidr_str in cond.values:
            has_ip_constraint = True
            net = _parse_ipv4_network(cidr_str)
            if net is None:
                continue
            start = int(net.network_address)
            end = start + (net.num_addresses - 1)
            listed_cidrs.append(z3.And(source_ip >= start, source_ip <= end))

    if not has_ip_constraint:
        return z3.BoolVal(True)
    if not listed_cidrs:
        # Every condition value failed to parse — conservative
        # fallback: treat as no constraint.
        return z3.BoolVal(True)

    in_listed_cidrs = z3.Or(*listed_cidrs)
    is_public_ip = _is_public_ip_constraint(source_ip)
    return z3.And(in_listed_cidrs, is_public_ip)


def _is_public_ip_constraint(source_ip: z3.ArithRef) -> z3.BoolRef:
    """Return a Z3 constraint asserting source_ip is in the
    public-internet IPv4 space — i.e., NOT in any RFC1918 /
    shared / loopback range."""
    private_ranges = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
        ipaddress.IPv4Network("100.64.0.0/10"),
        ipaddress.IPv4Network("127.0.0.0/8"),
    )
    not_in_private: list[z3.BoolRef] = []
    for net in private_ranges:
        start = int(net.network_address)
        end = start + (net.num_addresses - 1)
        not_in_private.append(z3.Or(source_ip < start, source_ip > end))
    return z3.And(*not_in_private)


def _parse_ipv4_network(cidr: str) -> Optional[ipaddress.IPv4Network]:
    try:
        return ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return None


def _is_private_cidr(net: ipaddress.IPv4Network) -> bool:
    private_ranges = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
        ipaddress.IPv4Network("100.64.0.0/10"),
        ipaddress.IPv4Network("127.0.0.0/8"),
    )
    return any(net.subnet_of(pr) for pr in private_ranges)


def _source_ref_to_finding(src: Optional[sir.SourceRef]) -> findings.SourceRef:
    if src is None:
        return findings.SourceRef()
    return findings.SourceRef(kind=src.kind, id=src.id, path=list(src.path))


def _build_suggested_fix(
    s: z3.Solver,
    builder: _FormulaBuilder,
    contributing_facts: list[_ContributingSource],
    group: sir.ResourceFactGroup,
) -> findings.SuggestedFix:
    """Hypothesize a fix per contributing fact, re-run Z3 with
    each fix applied, and emit the minimal-fix set.

    Strategy:
      1. For each contributing fact, build a FixChange describing
         the operation that would eliminate that fact's
         contribution (per the L7 operation taxonomy).
      2. For each fix, re-run the formula with the fact's Bool
         var forced False (= "the fact is no longer in effect").
         UNSAT → that single change proves the violation gone;
         emit it alone.
      3. If no single change proves UNSAT, force ALL contributing
         facts' vars False jointly. UNSAT under the joint set
         → emit all changes with proves_unsat=True (the joint
         claim, not the individual). SAT under the joint set →
         emit the changes with proves_unsat=False (we can't
         formally prove sufficiency — don't lie).
    """
    changes_with_var: list[tuple[findings.FixChange, z3.BoolRef]] = []
    for c in contributing_facts:
        change = _hypothesize_fix(c, group)
        changes_with_var.append((change, c.var))

    minimal_single: list[findings.FixChange] = []
    for change, var in changes_with_var:
        if builder.recheck_with_overrides(s, {var: False}):
            change.proves_unsat = True
            minimal_single.append(change)

    if minimal_single:
        return findings.SuggestedFix(
            description=(
                "Apply the single change below to eliminate this "
                "violation; Z3 proved this fix sufficient "
                "(proves_unsat=True)."
            ),
            changes=minimal_single,
        )

    joint_overrides = {var: False for _, var in changes_with_var}
    joint_proves_unsat = builder.recheck_with_overrides(s, joint_overrides)
    full_changes: list[findings.FixChange] = []
    for change, _var in changes_with_var:
        change.proves_unsat = joint_proves_unsat
        full_changes.append(change)
    return findings.SuggestedFix(
        description=(
            "No single change eliminates the violation; apply ALL "
            "changes below. proves_unsat reflects the joint effect "
            "of the listed set."
        ),
        changes=full_changes,
    )


def _hypothesize_fix(c: _ContributingSource, group: sir.ResourceFactGroup) -> findings.FixChange:
    """Translate one contributing fact into a concrete fix
    hypothesis. The operation/parameter pair follows the L7
    taxonomy (remove / constrain / add_deny / set_pab_flag);
    the target is the contributing fact's SourceRef so the
    user / Stave UI can navigate to the exact line.
    """
    target = c.source
    match c.fact_kind:
        case "bucket_policy":
            return findings.FixChange(
                target=target,
                operation="add_deny",
                parameter=(
                    "add a Deny statement above this one for the same "
                    "Principal/Action, or restrict via a Condition "
                    "(aws:PrincipalAccount, aws:SourceVpce)"
                ),
            )
        case "acl_grant":
            return findings.FixChange(
                target=target,
                operation="remove",
                parameter="delete this ACL grant",
            )
        case "iam_statement":
            return findings.FixChange(
                target=target,
                operation="constrain",
                parameter=(
                    "tighten the Resource clause or add a Condition "
                    "(aws:PrincipalArn, aws:SourceVpce)"
                ),
            )
        case _:
            return findings.FixChange(
                target=target,
                operation="remove",
                parameter="remove this contributing source",
            )


def _sensitive_actions_in_group(group: sir.ResourceFactGroup) -> list[str]:
    seen: dict[str, None] = {}
    for stmt in group.bucket_policy:
        if stmt.effect != "Allow":
            continue
        for action in stmt.actions:
            if action.lower() in SENSITIVE_S3_ACTIONS:
                seen[action] = None
    for grant in group.acl_grants:
        if not grant.is_public:
            continue
        for action in ACL_PERMISSION_TO_ACTIONS.get(grant.permission.upper(), set()):
            seen[action] = None
    for stmt in group.attached_iam:
        if stmt.effect != "Allow":
            continue
        for action in stmt.actions:
            if action.lower() in SENSITIVE_S3_ACTIONS:
                seen[action] = None
    return list(seen.keys())


def _explain(group: sir.ResourceFactGroup) -> str:
    return f"public principal can perform a sensitive action on {group.asset_id}"

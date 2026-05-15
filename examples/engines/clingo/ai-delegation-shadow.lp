% ai-delegation-shadow.lp — Clingo rules for AI agent, S3
% delegation, Shadow Admin, VPC peering, and Shadow EC2 patterns.
%
% Loaded alongside constraints.lp (the helper script concatenates
% them). Uses the predicate names that cmd/exportsir/facts.go
% actually emits, not the ones the original spec proposed:
%   has_agent_lambda_scope_broad  (not has_broad_lambda_invoke)
%   has_agent_invocation_logging  (not has_model_invocation_logging)
%   has_peering_peer_in_org       (TRUE = in-org → false is violation)
%   has_peering_route_broad       (not has_peering_route)
%   has_instance_stopped_aged     (not has_aged_stopped)
%   has_instance_profile_overprivileged (not has_profile_overbroad)
%   has_instance_dual_homed       (not has_environment_mix)
%   has_vendor_can_make_public    (not has_vendor_public_escalation)
%   has_customer_can_revoke       (TRUE = revocable → false is violation)
%
% Rules the spec proposed but no fixture exercises today
% (predicate not shipped) are NOT authored here. Author them
% when the underlying scalar lands in the projector.

% =============================
% AI Agent (Bedrock) violations
% =============================

% V-AGENT-BROAD-NO-GUARDRAIL — broad Lambda invoke without guardrail
violation(A, "agent_broad_lambda_no_guardrail") :-
    has_agent_lambda_scope_broad(A, "true"),
    has_agent_guardrail(A, "false").

% V-AGENT-BROAD-NO-LOGGING — broad Lambda invoke without logging
violation(A, "agent_broad_lambda_no_logging") :-
    has_agent_lambda_scope_broad(A, "true"),
    has_agent_invocation_logging(A, "false").

% V-AGENT-SHADOW — agent not managed by IaC
violation(A, "shadow_agent_no_iac") :-
    has_agent_iac_managed(A, "false").

% V-AGENT-BROAD-S3 — agent role has broad S3 access (data-boundary risk)
violation(A, "agent_broad_s3_access") :-
    has_agent_s3_scope_broad(A, "true").

% V-AGENT-KB-UNENCRYPTED — knowledge-base data source not encrypted
violation(A, "kb_unencrypted_data_source") :-
    has_kb_source_encrypted(A, "false").

% =============================
% S3 Delegation violations
% =============================

% V-DELEGATION-UNKNOWN-PRINCIPAL — name each unregistered principal
violation(B, "unknown_delegated_principal", P) :-
    has_unknown_delegated_principal(B, P).

% V-DELEGATION-SCOPE-EXCEEDED — name each scope-violating principal
violation(B, "delegation_scope_exceeded_for", P) :-
    has_delegation_scope_exceeded_for(B, P).

% V-DELEGATION-ESCALATION — vendor can make the bucket public
violation(B, "vendor_can_make_public") :-
    has_vendor_can_make_public(B, "true").

% V-DELEGATION-IRREVOCABLE — customer cannot revoke vendor access
violation(B, "irrevocable_delegation") :-
    has_customer_can_revoke(B, "false").

% V-DELEGATION-REVIEW-EXPIRED — vendor review_date in the past
violation(B, "delegation_review_expired") :-
    has_delegation_review_expired(B, "true").

% =============================
% Shadow Admin / IAM Role drift
% =============================

% V-SHADOW-ADMIN-COMPOUND — incompatible pair AND unused services
violation(A, "shadow_admin_signal") :-
    has_incompatible_pair(A, _),
    has_unused_service(A, _).

% V-INTENT-MISMATCH — declared role-type contradicted by permissions
violation(A, "intent_mismatch") :-
    has_intent_mismatch(A, "true").

% V-FORBIDDEN-CATEGORY — name each forbidden category present
violation(A, "forbidden_category", Cat) :-
    has_forbidden_category(A, Cat).

% V-INCOMPATIBLE-PAIR — name each incompatible category pair
violation(A, "incompatible_pair", Pair) :-
    has_incompatible_pair(A, Pair).

% Latent risk — name each unused service (informational; the
% scalar has_permission_drift_threshold_exceeded already covers
% the "drift exists" violation).
latent_risk(A, "unused_service", Svc) :-
    has_unused_service(A, Svc).

% =============================
% VPC Peering violations
% =============================

% V-PEERING-CROSS-ACCOUNT-BROAD — peer outside org AND broad route
violation(V, "cross_account_peering_broad_route") :-
    has_peering_peer_in_org(V, "false"),
    has_peering_route_broad(_, "true").

% V-PEERING-DNS-FROM-OUTSIDE — DNS resolution from a non-org peer
violation(V, "peering_dns_from_external_account") :-
    has_peering_peer_in_org(V, "false"),
    has_peering_dns_resolution(V, "true").

% =============================
% Shadow EC2 lateral-movement violations
% =============================

% V-SHADOW-EC2 — stopped-aged + overprivileged + dual-homed
violation(I, "shadow_ec2_pivot") :-
    has_instance_stopped_aged(I, "true"),
    has_instance_profile_overprivileged(I, "true"),
    has_instance_dual_homed(I, "true").

% =============================
% Show directives — expand the set the runner exposes.
% constraints.lp declares #show violation/3 and
% #show latent_risk/2. Many rules above emit violation/2
% (subject + kind, no per-element third arg) and latent_risk/3
% (subject + kind + per-element value), so add those arities
% to the show set. #show is additive across files.
% =============================
#show violation/2.
#show latent_risk/3.

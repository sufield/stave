% constraints.lp — security constraint definitions over Stave facts.
%
% Loaded after the per-fixture facts.lp produced from
% `stave export-sir --format jsonl`. Each rule defines a
% violation pattern that fires when a combination of facts
% matches the conjunction in the rule body.
%
% Why ASP not SMT here: ASP enumerates ALL grounded
% violations under stable-model semantics. Z3 finds one
% witness or returns unsat; Clingo returns every grounded
% atom that satisfies the constraint, which is the right
% shape for "list every (asset, principal, resource) triple
% that violates the policy." A CISO triages the list.

% =============================
% V1: Exploitable overperm — overpermissioned IAM role
% that is also assumable by a compute service. The compound
% the iter-13/iter-15 articles describe: each half is a
% known-finding control output (contributed_by binds the
% finding); the conjunction is the privesc primitive.
% =============================
violation(R, "exploitable_overperm", S) :-
    contributed_by(R, _),
    trusts_service(R, S).

% =============================
% V2: Multi-hop privesc chain — two consecutive can_assume
% edges. Reuses the can_assume edges the assumeEdgeFacts
% extractor emits. ASP grounding produces every (start,mid)
% witness; Z3's bounded transitive query produces just one.
% =============================
violation(Start, "privesc_chain_2hop", Mid) :-
    can_assume(Start, Mid),
    can_assume(Mid, _).

% =============================
% V3: Unauthenticated Cognito pool reaching S3 read.
% Maps the writeup-config Cognito chain.
% =============================
violation(P, "unauth_cognito_s3_read", R) :-
    allows_unauthenticated(P, "true"),
    maps_unauth_to(P, R),
    has_action(R, "s3:GetObject").

violation(P, "unauth_cognito_s3_read", R) :-
    allows_unauthenticated(P, "true"),
    maps_unauth_to(P, R),
    has_action(R, "s3:*").

% =============================
% V4: Self-registration enabled with broad S3 grant on the
% authenticated role. The Cognito-chain second-half: bypass
% UI guards by self-registering, then ride the broad
% authenticated role.
% =============================
violation(P, "self_register_broad_s3", R) :-
    self_registration_unrestricted(P, "true"),
    maps_auth_to(P, R),
    has_action(R, "s3:*").

% =============================
% V5: Wildcard action on wildcard resource — the iter-7a
% over-broad pattern. CEL flags this directly; included to
% show ASP shadowing the existing control as a cross-check.
% =============================
violation(R, "wildcard_action_resource", "s3:*") :-
    has_action(R, "s3:*"),
    has_resource(R, "*").

% =============================
% V6: Production resource + role with wildcard action —
% bybit-shape. ASP can't do prefix-matching like SMT
% string theory does, so this is the coarser version: any
% role with s3:* and any production-tagged bucket.
% Z3+SMT's bybit query refines this with str.prefixof.
% =============================
violation(R, "production_wildcard_pair", B) :-
    has_action(R, "s3:*"),
    has_type(B, "aws_s3_bucket"),
    has_tag(B, "environment=production").

% =============================
% Latent risks — distinct from violations. A role that
% trusts a compute service but has NO finding attached is
% latent: not currently flagged, but will turn into V1 the
% moment a single finding fires on it.
% =============================
latent_risk(R, "compute_trust_no_finding") :-
    has_type(R, "aws_iam_role"),
    trusts_service(R, _),
    not contributed_by(R, _).

#show violation/3.
#show latent_risk/2.

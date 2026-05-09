% reasoning.pl — security reasoning with proof trees over the
% Stave fact base. Each query rule carries a Proof accumulator
% that records the derivation chain step-by-step, so a
% successful proof comes back with the *evidence* alongside
% the verdict.
%
% Z3 says "sat"; Soufflé says "6 paths"; Prolog says
% "anonymous_reaches(pool, bucket, s3:GetObject) BECAUSE
% allows_unauthenticated(pool) AND maps_unauth_to(pool, role)
% AND has_action(role, s3:GetObject) AND has_resource(role,
% bucket)" — the structured explanation an AI agent or human
% auditor uses to determine which fact to break to collapse
% the chain.
%
% Cycle bound: anonymous/self-register/exploitable rules are
% non-recursive. The privesc_path/3 rule walks can_assume
% transitively under a depth bound (max_depth/1) — sufficient
% for the shipped fixtures and bounded against cycles. If a
% fixture with deep cycles arrives, switch to SWI-Prolog
% tabling (`:- table privesc_path/3.`).

:- use_module(library(lists)).

max_depth(8).

% ===========================================================
% Anonymous access — unauthenticated identity-pool path
% ===========================================================
anonymous_access(Pool, Resource, Action, [
    step(Pool, allows_unauthenticated, "true"),
    step(Pool, maps_unauth_to, Role),
    step(Role, grants, Action),
    step(Role, on_resource, Resource)
]) :-
    allows_unauthenticated(Pool, "true"),
    maps_unauth_to(Pool, Role),
    has_action(Role, Action),
    has_resource(Role, Resource).

% ===========================================================
% Self-registration access — any user pool with self-register
% open + any identity pool's auth role grants. The user pool
% (cognito-idp:...) and identity pool (cognito-identity:...)
% are distinct ARNs in the SIR; the rule joins on existence
% (matches the iter-16 reveal that any open user pool taints
% linked identity pools).
% ===========================================================
self_register_access(IdentityPool, Resource, Action, [
    step(UserPool, self_registration_unrestricted, "true"),
    step(IdentityPool, maps_auth_to, Role),
    step(Role, grants, Action),
    step(Role, on_resource, Resource)
]) :-
    self_registration_unrestricted(UserPool, "true"),
    maps_auth_to(IdentityPool, Role),
    has_action(Role, Action),
    has_resource(Role, Resource).

% ===========================================================
% Exploitable overpermission — role has both a finding
% (contributed_by) and is assumable by a compute service.
% ===========================================================
exploitable_role(Role, Control, Service, [
    step(Role, has_finding, Control),
    step(Role, trusts_compute, Service),
    conclusion(Role, exploitable_via_passrole)
]) :-
    contributed_by(Role, Control),
    trusts_service(Role, Service).

% ===========================================================
% Privilege escalation paths — multi-hop can_assume chains.
% Every successful proof is a path from Start to End through
% intermediate principals (no repeated nodes). Depth-bounded
% to max_depth/1 to keep search finite.
% ===========================================================
privesc_path(Start, End, Proof) :-
    max_depth(Max),
    privesc_path_(Start, End, [Start], Max, Steps),
    Steps \= [],
    Proof = Steps.

privesc_path_(Current, End, _Visited, _D, [step(Current, assumes, End)]) :-
    can_assume(Current, End).

privesc_path_(Current, End, Visited, Depth, [step(Current, assumes, Mid) | Rest]) :-
    Depth > 1,
    can_assume(Current, Mid),
    \+ member(Mid, Visited),
    NextDepth is Depth - 1,
    privesc_path_(Mid, End, [Mid | Visited], NextDepth, Rest).

% ===========================================================
% Expansion: per-asset boolean derivations.
%
% Each rule turns a per-asset boolean (the propertyFacts
% projector / PR-1-etc emit `has_X(asset, "true"|"false")`)
% into a one-step proof tree the renderer prints alongside
% the multi-step Cognito and IAM chains. Predicates referenced
% here match what real fixtures emit; transform-to-pl.sh
% declares them discontiguous so SWI-Prolog stays quiet on
% fixtures that don't mention all of them.
% ===========================================================

% Public S3 bucket — read or list.
public_bucket(B, [
    step(B, has_public_read, "true"),
    conclusion(B, public_read_enabled)
]) :-
    has_public_read(B, "true").

public_bucket(B, [
    step(B, has_public_list, "true"),
    conclusion(B, public_list_enabled)
]) :-
    has_public_list(B, "true").

% Cognito MFA / advanced-security gap.
mfa_gap(P, [
    step(P, has_mfa_enforced, "false"),
    conclusion(P, mfa_disabled)
]) :-
    has_mfa_enforced(P, "false").

mfa_gap(P, [
    step(P, has_advanced_security_enabled, "false"),
    conclusion(P, advanced_security_off)
]) :-
    has_advanced_security_enabled(P, "false").

% CloudTrail logging gap (mgmt or data events).
logging_gap(T, [
    step(T, has_logging_enabled, "false"),
    conclusion(T, logging_disabled)
]) :-
    has_logging_enabled(T, "false").

logging_gap(B, [
    step(B, has_data_event_logging, "false"),
    conclusion(B, data_event_logging_missing)
]) :-
    has_data_event_logging(B, "false").

% Dangling bucket reference — a reference to a bucket the
% account doesn't own / doesn't exist. Either signal alone is
% enough for takeover risk.
dangling_bucket(R, [
    step(R, has_bucket_owned, "false"),
    conclusion(R, bucket_takeover_risk)
]) :-
    has_bucket_owned(R, "false").

dangling_bucket(R, [
    step(R, has_bucket_exists, "false"),
    conclusion(R, bucket_takeover_risk)
]) :-
    has_bucket_exists(R, "false").

% Exposed repository artefacts (.git, .svn, .DS_Store).
exposed_repo(B, [
    step(B, has_exposed_repo_artifacts, "true"),
    conclusion(B, repo_metadata_publicly_accessible)
]) :-
    has_exposed_repo_artifacts(B, "true").

% EKS RBAC webhook-config write access.
webhook_admin(C, [
    step(C, has_webhook_config_access, "true"),
    conclusion(C, cluster_admin_via_webhook_config)
]) :-
    has_webhook_config_access(C, "true").

% EKS aws-auth ConfigMap template-injection vector.
aws_auth_injection(M, [
    step(M, has_uses_access_key_id, "true"),
    conclusion(M, identity_mapped_by_access_key)
]) :-
    has_uses_access_key_id(M, "true").

% Resource-policy broad-trust shape.
broad_resource_policy(R, [
    step(R, resource_policy_principal, "*"),
    conclusion(R, broad_trust_via_resource_policy)
]) :-
    resource_policy_principal(R, "*").

% ===========================================================
% Proof tree formatting.
% ===========================================================
print_proof(Proof) :- print_proof(Proof, 0).

print_proof([], _).
print_proof([step(From, Relation, To) | Rest], Indent) :-
    tab(Indent),
    format("~w --[~w]--> ~w~n", [From, Relation, To]),
    Next is Indent + 2,
    print_proof(Rest, Next).
print_proof([conclusion(Subject, Verdict) | Rest], Indent) :-
    tab(Indent),
    format("therefore ~w :: ~w~n", [Subject, Verdict]),
    print_proof(Rest, Indent).

% ===========================================================
% Query runner. Emits one section per query type. Sections
% with no proofs print "(none)" so the absence is explicit
% rather than a silent gap.
% ===========================================================
run_section(Header, Goal, Render) :-
    format("~n=== ~w ===~n", [Header]),
    findall(t, Goal, Results),
    ( Results = [] -> format("(none)~n") ; call(Render) ).

run_anonymous :-
    forall(
        anonymous_access(_Pool, Resource, Action, Proof),
        ( format("~nanonymous reaches ~w via ~w:~n", [Resource, Action]),
          print_proof(Proof) )
    ).

run_self_register :-
    forall(
        self_register_access(_Pool, Resource, Action, Proof),
        ( format("~nself-register reaches ~w via ~w:~n", [Resource, Action]),
          print_proof(Proof) )
    ).

run_exploitable :-
    forall(
        exploitable_role(Role, Control, Service, Proof),
        ( format("~nexploitable role ~w (control: ~w, service: ~w):~n",
                 [Role, Control, Service]),
          print_proof(Proof) )
    ).

run_privesc :-
    forall(
        privesc_path(Start, End, Proof),
        ( format("~nprivesc ~w -> ~w:~n", [Start, End]),
          print_proof(Proof) )
    ).

run_public_bucket :-
    forall(public_bucket(B, Proof),
        ( format("~npublic bucket ~w:~n", [B]),
          print_proof(Proof) )).

run_mfa :-
    forall(mfa_gap(P, Proof),
        ( format("~nMFA / advanced-security gap on ~w:~n", [P]),
          print_proof(Proof) )).

run_logging :-
    forall(logging_gap(T, Proof),
        ( format("~nlogging gap on ~w:~n", [T]),
          print_proof(Proof) )).

run_dangling :-
    forall(dangling_bucket(R, Proof),
        ( format("~ndangling bucket reference ~w:~n", [R]),
          print_proof(Proof) )).

run_exposed_repo :-
    forall(exposed_repo(B, Proof),
        ( format("~nexposed repo artefacts on ~w:~n", [B]),
          print_proof(Proof) )).

run_webhook :-
    forall(webhook_admin(C, Proof),
        ( format("~nwebhook admin access on ~w:~n", [C]),
          print_proof(Proof) )).

run_aws_auth :-
    forall(aws_auth_injection(M, Proof),
        ( format("~naws-auth template injection on ~w:~n", [M]),
          print_proof(Proof) )).

run_broad_policy :-
    forall(broad_resource_policy(R, Proof),
        ( format("~nbroad resource policy on ~w:~n", [R]),
          print_proof(Proof) )).

run_queries :-
    run_section("Anonymous Access Chains",
                anonymous_access(_, _, _, _), run_anonymous),
    run_section("Self-Registration Chains",
                self_register_access(_, _, _, _), run_self_register),
    run_section("Exploitable Overpermissioned Roles",
                exploitable_role(_, _, _, _), run_exploitable),
    run_section("Privilege Escalation Paths",
                privesc_path(_, _, _), run_privesc),
    run_section("Public S3 Buckets",
                public_bucket(_, _), run_public_bucket),
    run_section("Cognito MFA / Advanced-Security Gaps",
                mfa_gap(_, _), run_mfa),
    run_section("CloudTrail Logging Gaps",
                logging_gap(_, _), run_logging),
    run_section("Dangling Bucket References",
                dangling_bucket(_, _), run_dangling),
    run_section("Exposed Repository Artefacts",
                exposed_repo(_, _), run_exposed_repo),
    run_section("EKS Webhook Admin Access",
                webhook_admin(_, _), run_webhook),
    run_section("EKS aws-auth Template Injection",
                aws_auth_injection(_, _), run_aws_auth),
    run_section("Broad Resource Policy",
                broad_resource_policy(_, _), run_broad_policy).

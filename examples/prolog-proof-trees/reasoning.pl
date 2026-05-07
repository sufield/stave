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

run_queries :-
    run_section("Anonymous Access Chains",
                anonymous_access(_, _, _, _), run_anonymous),
    run_section("Self-Registration Chains",
                self_register_access(_, _, _, _), run_self_register),
    run_section("Exploitable Overpermissioned Roles",
                exploitable_role(_, _, _, _), run_exploitable),
    run_section("Privilege Escalation Paths",
                privesc_path(_, _, _), run_privesc).

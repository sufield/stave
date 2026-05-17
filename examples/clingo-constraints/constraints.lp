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
% the overperm-plus-trust articles describe: each half is a
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
% V5: Wildcard action on wildcard resource — the iam-overpermission-wildcard
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

% =============================================================
% Expansion — per-asset boolean violations.
%
% Each rule is anchored to a predicate that real fixtures emit;
% the matching predicate is also added to LIFTED_PREDICATES in
% run.py (without that list entry the lifter drops the JSONL
% triple and the rule body never matches). Target fixtures are
% named in each rule's comment.
% =============================================================

% V7: S3 bucket has public read enabled.
% Targets: s3-public-read-policy, s3-broad-write-scope,
%          s3-dotgit-readable, s3-public-list-policy,
%          s3-tenant-prefix-isolation,
%          s3-cross-account-replication-overperm.
violation(B, "public_read", "true") :-
    has_public_read(B, "true").

% V8: S3 bucket has public list enabled.
% Targets: same set as V7.
violation(B, "public_list", "true") :-
    has_public_list(B, "true").

% V9: Cognito user pool has MFA disabled. Anchored to the
% propertyFacts projector's `has_mfa_enforced(pool, "false")`
% emission. Targets: cognito-no-mfa-advanced-security,
% cognito-self-register-to-aws-creds.
violation(P, "mfa_disabled", "false") :-
    has_mfa_enforced(P, "false").

% V10: Cognito user pool has advanced-security disabled.
% Targets: cognito-no-mfa-advanced-security.
violation(P, "advanced_security_off", "false") :-
    has_advanced_security_enabled(P, "false").

% V11: CloudTrail trail has logging disabled.
% Targets: cloudtrail-stop-logging.
violation(T, "logging_disabled", "false") :-
    has_logging_enabled(T, "false").

% V12: S3 bucket reference points at a non-owned / non-existent
% bucket — either signal alone is enough to flag the
% dangling-takeover risk. Targets: s3-bucket-name-dangling.
violation(R, "bucket_not_owned", "false") :-
    has_bucket_owned(R, "false").

violation(R, "bucket_not_exists", "false") :-
    has_bucket_exists(R, "false").

% V13: Repository artefacts (.git, .svn, .DS_Store) accessible
% from the bucket. Targets: s3-dotgit-readable.
violation(B, "exposed_repo_artifacts", "true") :-
    has_exposed_repo_artifacts(B, "true").

% V14: EKS cluster role exposes webhook-config write access.
% Targets: eks-rbac-webhook-config-access.
violation(C, "webhook_config_access", "true") :-
    has_webhook_config_access(C, "true").

% V15: EKS aws-auth ConfigMap admits identity by access-key id
% — the template-injection vector. Targets:
% eks-aws-auth-template-injection.
violation(M, "access_key_template_injection", "true") :-
    has_uses_access_key_id(M, "true").

% V16: Resource policy grants access to a wildcard principal —
% the apigw / public-read / cross-account family's broad-trust
% shape. Targets: apigw-private-api-scoped-deny,
% s3-cross-account-replication-overperm,
% s3-public-list-policy, s3-public-read-policy.
violation(A, "broad_resource_policy_principal", "*") :-
    resource_policy_principal(A, "*").

% V17: CloudTrail data-event coverage missing for an S3 bucket.
% Targets: cloudtrail-stop-logging (data-events fixture pair).
violation(B, "data_event_logging_missing", "false") :-
    has_data_event_logging(B, "false").

#show violation/3.
#show latent_risk/2.

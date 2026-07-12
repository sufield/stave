# Datalog Relations Reference

Auto-generated from `.dl` source files. Do not edit manually.
Run: `go run ./internal/tools/gendatalogdocs`

## Input Relations (schema.dl)

| Relation | Parameters | Kind | Description |
|----------|-----------|------|-------------|
| [`has_type`](#has_type) | `asset: symbol, asset_type: symbol` | input | verbatim SIR-facts vocabulary |
| [`has_vendor`](#has_vendor) | `asset: symbol, vendor: symbol` | input |  |
| [`has_severity`](#has_severity) | `asset: symbol, severity: symbol` | input |  |
| [`has_action`](#has_action) | `principal: symbol, action: symbol` | input |  |
| [`has_resource`](#has_resource) | `principal: symbol, resource: symbol` | input |  |
| [`has_deny_action`](#has_deny_action) | `principal: symbol, action: symbol` | input |  |
| [`has_deny_resource`](#has_deny_resource) | `principal: symbol, resource: symbol` | input |  |
| [`has_permission_action`](#has_permission_action) | `principal: symbol, action: symbol` | input |  |
| [`has_permission_resource`](#has_permission_resource) | `principal: symbol, resource: symbol` | input |  |
| [`has_condition`](#has_condition) | `principal: symbol, condition_key: symbol` | input |  |
| [`has_condition_value`](#has_condition_value) | `principal: symbol, value: symbol` | input |  |
| [`has_tag`](#has_tag) | `asset: symbol, kv: symbol` | input |  |
| [`can_assume`](#can_assume) | `from_principal: symbol, to_role: symbol` | input |  |
| [`cross_account_assumes`](#cross_account_assumes) | `role: symbol, target: symbol` | input |  |
| [`trusts_service`](#trusts_service) | `role: symbol, service: symbol` | input |  |
| [`has_delegated_principal`](#has_delegated_principal) | `role: symbol, principal: symbol` | input |  |
| [`has_unknown_delegated_principal`](#has_unknown_delegated_principal) | `role: symbol, marker: symbol` | input |  |
| [`has_delegation_scope_exceeded_for`](#has_delegation_scope_exceeded_for) | `role: symbol, scope: symbol` | input |  |
| [`resource_policy_principal`](#resource_policy_principal) | `resource: symbol, principal: symbol` | input |  |
| [`resource_policy_action`](#resource_policy_action) | `resource: symbol, action: symbol` | input |  |
| [`grants_cross_account_access`](#grants_cross_account_access) | `resource: symbol, external_principal: symbol, action: symbol, grant_type: symbol` | input |  |
| [`maps_unauth_to`](#maps_unauth_to) | `pool: symbol, role: symbol` | input |  |
| [`maps_auth_to`](#maps_auth_to) | `pool: symbol, role: symbol` | input |  |
| [`allows_unauthenticated`](#allows_unauthenticated) | `pool: symbol, flag: symbol` | input |  |
| [`self_registration_unrestricted`](#self_registration_unrestricted) | `pool: symbol, flag: symbol` | input |  |
| [`contributed_by`](#contributed_by) | `asset: symbol, control: symbol` | input |  |
| [`is_decommissioned`](#is_decommissioned) | `asset: symbol, flag: symbol` | input |  |
| [`is_provisioned`](#is_provisioned) | `asset: symbol, flag: symbol` | input |  |
| [`first_seen_at`](#first_seen_at) | `asset: symbol, timestamp: symbol` | input |  |
| [`last_seen_at`](#last_seen_at) | `asset: symbol, timestamp: symbol` | input |  |
| [`has_exposure_window`](#has_exposure_window) | `asset: symbol, flag: symbol` | input |  |
| [`has_forbidden_state`](#has_forbidden_state) | `asset: symbol, state: symbol` | input |  |
| [`has_forbidden_category`](#has_forbidden_category) | `asset: symbol, category: symbol` | input |  |
| [`has_incompatible_pair`](#has_incompatible_pair) | `asset: symbol, pair: symbol` | input |  |
| [`has_intent_rationale`](#has_intent_rationale) | `asset: symbol, rationale: symbol` | input |  |
| [`has_privilege_level`](#has_privilege_level) | `principal: symbol, level: symbol` | input |  |
| [`has_unused_service`](#has_unused_service) | `principal: symbol, service: symbol` | input |  |
| [`has_data_event_logging`](#has_data_event_logging) | `asset: symbol, flag: symbol` | input |  |
| [`has_mfa_enforced`](#has_mfa_enforced) | `asset: symbol, flag: symbol` | input |  |
| [`has_advanced_security_enabled`](#has_advanced_security_enabled) | `asset: symbol, flag: symbol` | input |  |
| [`authorized`](#authorized) | `principal_id: symbol, resource_id: symbol` | input | Authorization + sensitivity model |
| [`sensitivity`](#sensitivity) | `resource_id: symbol, level: symbol` | input |  |
| [`is_principal_type`](#is_principal_type) | `t: symbol` | derived | Option B Datalog-readability renames |
| [`principal_type`](#principal_type) | `id: symbol, type: symbol` | output | has_type restricted to principal asset types |
| [`resource`](#resource) | `id: symbol, type: symbol` | output | has_type restricted to non-principal AWS asset types |
| [`trust_principal`](#trust_principal) | `role_id: symbol, principal_id: symbol` | output | union of cross_account_assumes and |
| [`trust_service`](#trust_service) | `role_id: symbol, service_principal: symbol` | output | alias of trusts_service for Option B naming |

## Derived Relations (rules.dl)

| Relation | Parameters | Kind | Description |
|----------|-----------|------|-------------|
| [`transitive_assume`](#transitive_assume) | `principal_id: symbol, role_id: symbol` | output | closure of can_assume over role |
| [`reachable_action`](#reachable_action) | `principal_id: symbol, action: symbol` | output | the principal's |
| [`reachable_resource`](#reachable_resource) | `principal_id: symbol, resource_pattern: symbol` | output |  |
| [`reachable_deny_action`](#reachable_deny_action) | `principal_id: symbol, action: symbol` | output | Same shape for the Deny side. Sirfacts emits has_deny_* |
| [`reachable_deny_resource`](#reachable_deny_resource) | `principal_id: symbol, resource_pattern: symbol` | output |  |
| [`effective_allow`](#effective_allow) | `principal_id: symbol, action: symbol, resource_pattern: symbol` | output | the cartesian |
| [`effective_deny`](#effective_deny) | `principal_id: symbol, action: symbol, resource_pattern: symbol` | output |  |
| [`effective_permission`](#effective_permission) | `principal_id: symbol, action: symbol, resource_pattern: symbol` | output | allow minus deny. Per Caveat 2, |
| [`arn_matches`](#arn_matches) | `pattern: symbol, arn: symbol` | derived | pattern matching for AWS resource ARNs |
| [`effective_access`](#effective_access) | `principal_id: symbol, resource_id: symbol, action: symbol` | output | the final reachability relation |
| [`resource_effective_access`](#resource_effective_access) | `resource_id: symbol, principal_id: symbol, action: symbol` | output | Resource-first index. Same relation, transposed. Useful |
| [`unauthorized_access`](#unauthorized_access) | `principal_id: symbol, resource_id: symbol, action: symbol` | output | unauthorized_access derivation |
| [`violation_c`](#violation_c) | `principal_id: symbol, resource_id: symbol, action: symbol` | output |  |
| [`violation_i`](#violation_i) | `principal_id: symbol, resource_id: symbol, action: symbol` | output | Integrity query |

## Discovery Relations (discovery.dl)

| Relation | Parameters | Kind | Description |
|----------|-----------|------|-------------|
| [`privesc_path`](#privesc_path) | `start: symbol, end: symbol, hops: number, hop1: symbol, hop2: symbol, hop3: symbol, hop4: symbol, hop5: symbol` | output | Path-tracking transitive assumption |
| [`access_path`](#access_path) | `principal: symbol, resource: symbol, action: symbol, via_role: symbol, hops: number` | output | principal reaches resource via assume chain |
| [`escalation_path`](#escalation_path) | `principal: symbol, admin_role: symbol, hops: number, hop1: symbol, hop2: symbol, hop3: symbol` | output | Security classification of discovered paths |
| [`exfil_path`](#exfil_path) | `principal: symbol, resource: symbol, via_role: symbol, hops: number` | output | exfil_path: principal can write to a resource via cross-account or wildcard S3 |
| [`external_reach`](#external_reach) | `principal: symbol, resource: symbol, action: symbol, via_role: symbol, hops: number` | output | external_reach: access from a cross-account principal |
| [`confused_deputy_path`](#confused_deputy_path) | `role: symbol, service: symbol, resource: symbol, action: symbol` | output | confused_deputy: service-trusted role reaches sensitive resource |
| [`path_condition`](#path_condition) | `principal: symbol, target: symbol, cond_key: symbol, cond_value: symbol` | output | surface per-hop conditions for Z3 |

---

## Relation Details

### has_type

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_type(asset: symbol, asset_type: symbol)
```

Input relations — verbatim SIR-facts vocabulary.

### has_vendor

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_vendor(asset: symbol, vendor: symbol)
```

### has_severity

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_severity(asset: symbol, severity: symbol)
```

### has_action

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_action(principal: symbol, action: symbol)
```

### has_resource

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_resource(principal: symbol, resource: symbol)
```

### has_deny_action

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_deny_action(principal: symbol, action: symbol)
```

### has_deny_resource

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_deny_resource(principal: symbol, resource: symbol)
```

### has_permission_action

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_permission_action(principal: symbol, action: symbol)
```

### has_permission_resource

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_permission_resource(principal: symbol, resource: symbol)
```

### has_condition

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_condition(principal: symbol, condition_key: symbol)
```

### has_condition_value

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_condition_value(principal: symbol, value: symbol)
```

### has_tag

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_tag(asset: symbol, kv: symbol)
```

### can_assume

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl can_assume(from_principal: symbol, to_role: symbol)
```

### cross_account_assumes

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl cross_account_assumes(role: symbol, target: symbol)
```

### trusts_service

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl trusts_service(role: symbol, service: symbol)
```

### has_delegated_principal

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_delegated_principal(role: symbol, principal: symbol)
```

### has_unknown_delegated_principal

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_unknown_delegated_principal(role: symbol, marker: symbol)
```

### has_delegation_scope_exceeded_for

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_delegation_scope_exceeded_for(role: symbol, scope: symbol)
```

### resource_policy_principal

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl resource_policy_principal(resource: symbol, principal: symbol)
```

### resource_policy_action

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl resource_policy_action(resource: symbol, action: symbol)
```

### grants_cross_account_access

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl grants_cross_account_access(resource: symbol, external_principal: symbol, action: symbol, grant_type: symbol)
```

### maps_unauth_to

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl maps_unauth_to(pool: symbol, role: symbol)
```

### maps_auth_to

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl maps_auth_to(pool: symbol, role: symbol)
```

### allows_unauthenticated

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl allows_unauthenticated(pool: symbol, flag: symbol)
```

### self_registration_unrestricted

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl self_registration_unrestricted(pool: symbol, flag: symbol)
```

### contributed_by

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl contributed_by(asset: symbol, control: symbol)
```

### is_decommissioned

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl is_decommissioned(asset: symbol, flag: symbol)
```

### is_provisioned

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl is_provisioned(asset: symbol, flag: symbol)
```

### first_seen_at

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl first_seen_at(asset: symbol, timestamp: symbol)
```

### last_seen_at

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl last_seen_at(asset: symbol, timestamp: symbol)
```

### has_exposure_window

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_exposure_window(asset: symbol, flag: symbol)
```

### has_forbidden_state

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_forbidden_state(asset: symbol, state: symbol)
```

### has_forbidden_category

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_forbidden_category(asset: symbol, category: symbol)
```

### has_incompatible_pair

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_incompatible_pair(asset: symbol, pair: symbol)
```

### has_intent_rationale

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_intent_rationale(asset: symbol, rationale: symbol)
```

### has_privilege_level

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_privilege_level(principal: symbol, level: symbol)
```

### has_unused_service

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_unused_service(principal: symbol, service: symbol)
```

### has_data_event_logging

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_data_event_logging(asset: symbol, flag: symbol)
```

### has_mfa_enforced

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_mfa_enforced(asset: symbol, flag: symbol)
```

### has_advanced_security_enabled

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl has_advanced_security_enabled(asset: symbol, flag: symbol)
```

### authorized

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl authorized(principal_id: symbol, resource_id: symbol)
```

G3 — Authorization + sensitivity model.

These three relations are emitted by the G0 extractor
after consulting stave-authorization.yaml (or its
hardcoded default). They are .input — base facts the
extractor materialises — because the tag-equality
computation is one-pass over has_tag and fits naturally
in Go rather than recursive Datalog.

See docs/authorization-model.md for the product-decision
shape, fail-open/fail-closed semantics, and limitations.

### sensitivity

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** input

```datalog
.decl sensitivity(resource_id: symbol, level: symbol)
```

### is_principal_type

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** derived

```datalog
.decl is_principal_type(t: symbol)
```

Derived views — Option B Datalog-readability renames.

These are .decl + rule, NOT .input — they project from the
raw SIR-facts vocabulary into the Option-B-flavored names
CIA queries downstream consume.
is_principal_type — which asset_type strings count as an
IAM principal for the access graph.

**Rules:**

```datalog
is_principal_type("aws_iam_user").
is_principal_type("aws_iam_role").
is_principal_type("aws_iam_federated_role").
is_principal_type("aws_iam_saml_provider").
is_principal_type("aws_iam_sso_config").
```

### principal_type

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** output

```datalog
.decl principal_type(id: symbol, type: symbol)
```

principal_type — has_type restricted to principal asset types.
Phase 7 G1 rules and CIA queries reason over principals; this
view filters out non-principal assets (S3 buckets, KMS keys,
etc.) which appear in has_type as resources.

### resource

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** output

```datalog
.decl resource(id: symbol, type: symbol)
```

resource — has_type restricted to non-principal AWS asset types.
Inverse of principal_type, with a substr filter requiring the
type string to start with "aws_". Sirfacts emits has_type for
both assets ("aws_s3_bucket", "aws_kms_key") AND control records
("unsafe_state", "ghost_reference"); without the prefix filter
the resource view would include control records as "resources",
which is a category error for CIA reachability queries.
The prefix is the standard discriminator: every asset type in
the observation contract starts with "aws_", "gcp_", or
(when those land) "azure_" / "k8s_". Extend the substr check
when non-AWS providers join the contract.

### trust_principal

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** output

```datalog
.decl trust_principal(role_id: symbol, principal_id: symbol)
```

trust_principal — union of cross_account_assumes and
has_delegated_principal. Both predicates describe "this role
trusts this non-service principal to assume it"; the SIR
emits them separately because they come from different
observation projections (cross-account chains vs delegated
principal lists).

### trust_service

**Source:** `reasoning/souffle/iam/schema.dl`

**Kind:** output

```datalog
.decl trust_service(role_id: symbol, service_principal: symbol)
```

trust_service — alias of trusts_service for Option B naming
consistency with trust_principal. Same semantics; just a
view for downstream readability.

### transitive_assume

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl transitive_assume(principal_id: symbol, role_id: symbol)
```

transitive_assume — closure of can_assume over role
chains. Base case: direct can_assume edge. Recursive:
extend an existing chain by one hop. Soufflé's
stratification guarantees termination; the depth cap
is implicit in Soufflé's bottom-up fixpoint (the
closure terminates when no new tuples are derived),
but we still bound the explicit privesc_chain depth
in reachability.dl per AWS's documented role-chain
limits.

### reachable_action

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl reachable_action(principal_id: symbol, action: symbol)
```

reachable_action / reachable_resource — the principal's
own emitted facts plus all facts on transitively-
assumable roles. The CIA queries reason over these
instead of has_action / has_resource directly because
a user who can assume an admin role inherits that
role's actions for the purposes of effective access.

### reachable_resource

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl reachable_resource(principal_id: symbol, resource_pattern: symbol)
```

### reachable_deny_action

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl reachable_deny_action(principal_id: symbol, action: symbol)
```

Same shape for the Deny side. Sirfacts emits has_deny_*
only when the principal's effective Deny set is non-
empty, so under Option B these are typically sparse.

### reachable_deny_resource

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl reachable_deny_resource(principal_id: symbol, resource_pattern: symbol)
```

### effective_allow

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl effective_allow(principal_id: symbol, action: symbol, resource_pattern: symbol)
```

effective_allow / effective_deny — the cartesian
product of reachable_action × reachable_resource per
principal. See Caveat 1 in the file header for why
this is necessarily an over-approximation under
Option B.

### effective_deny

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl effective_deny(principal_id: symbol, action: symbol, resource_pattern: symbol)
```

### effective_permission

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl effective_permission(principal_id: symbol, action: symbol, resource_pattern: symbol)
```

effective_permission — allow minus deny. Per Caveat 2,
the deny override fidelity depends on sirfacts emitting
both Allow and Deny halves for the same (principal,
action) pair. G2 cross-validation tells us whether
this approximation produces the same verdicts the I2-I7
compound CEL predicates produce.

### arn_matches

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** derived

```datalog
.decl arn_matches(pattern: symbol, arn: symbol)
```

arn_matches — pattern matching for AWS resource ARNs.
Per Caveat 3, handles exact match, universal "*", and
trailing "*" wildcard segments. Mid-pattern wildcards
are not implemented (rare in real AWS policy usage).

The relation is materialized over the cross product of
(patterns the principals have, resource ARNs in the
snapshot). Souffle computes this lazily during
effective_access derivation; no separate .output is
needed unless an operator wants to spot-check the
matcher.

### effective_access

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl effective_access(principal_id: symbol, resource_id: symbol, action: symbol)
```

effective_access — the final reachability relation.
"Principal P can perform action A against resource R"
where R is a concrete resource in the snapshot whose
ARN matches one of P's effective resource patterns.

### resource_effective_access

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl resource_effective_access(resource_id: symbol, principal_id: symbol, action: symbol)
```

Resource-first index. Same relation, transposed. Useful
for resource-centric queries: "who can touch this PHI
bucket?"

### unauthorized_access

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl unauthorized_access(principal_id: symbol, resource_id: symbol, action: symbol)
```

G3 — unauthorized_access derivation.

The raw violation set BEFORE CIA tier filtering. CIA
queries (G4 Confidentiality, G5 Integrity) layer the
read/write action class + the sensitivity filter on
top of this relation.

The authorized/sensitivity input relations are emitted
by the G3-extended extractor; see schema.dl §G3 +
docs/authorization-model.md for the product-decision
shape (tag equality on Owner/Team; fail-open for
untagged resources, fail-closed for tagged-resource +
untagged-principal).

### violation_c

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl violation_c(principal_id: symbol, resource_id: symbol, action: symbol)
```

### violation_i

**Source:** `reasoning/souffle/iam/rules.dl`

**Kind:** output

```datalog
.decl violation_i(principal_id: symbol, resource_id: symbol, action: symbol)
```

G5 — Integrity query.

"Does there exist an unauthorized principal with effective
access to a sensitive resource via write/modify/delete
actions?"

Mirrors violation_c with is_write_action substituted.

A principal action like `s3:*` fires BOTH violation_c AND
violation_i because it grants both read AND write. This is
correct: the principal can both read and modify; the dual
finding accurately describes both risk dimensions. See the
honest caveat at the top of action_classes.dl.

### privesc_path

**Source:** `reasoning/souffle/discovery/discovery.dl`

**Kind:** output

```datalog
.decl privesc_path(start: symbol, end: symbol, hops: number, hop1: symbol, hop2: symbol, hop3: symbol, hop4: symbol, hop5: symbol)
```

Path-tracking transitive assumption.

privesc_path emits the full chain as a fixed-width tuple.
Soufflé doesn't have lists; we use positional columns
(hop1..hop5) and pad unused hops with "—". Bounded to
depth 5 to match AWS's practical role-chain limit.

### access_path

**Source:** `reasoning/souffle/discovery/discovery.dl`

**Kind:** output

```datalog
.decl access_path(principal: symbol, resource: symbol, action: symbol, via_role: symbol, hops: number)
```

Access paths — principal reaches resource via assume chain.

access_path tracks: who, what resource, what action, how
many hops, and the final role that holds the permission.

### escalation_path

**Source:** `reasoning/souffle/discovery/discovery.dl`

**Kind:** output

```datalog
.decl escalation_path(principal: symbol, admin_role: symbol, hops: number, hop1: symbol, hop2: symbol, hop3: symbol)
```

Security classification of discovered paths.
escalation_path: assume chain leads to a role with admin-equivalent actions.

### exfil_path

**Source:** `reasoning/souffle/discovery/discovery.dl`

**Kind:** output

```datalog
.decl exfil_path(principal: symbol, resource: symbol, via_role: symbol, hops: number)
```

exfil_path: principal can write to a resource via cross-account or wildcard S3.

### external_reach

**Source:** `reasoning/souffle/discovery/discovery.dl`

**Kind:** output

```datalog
.decl external_reach(principal: symbol, resource: symbol, action: symbol, via_role: symbol, hops: number)
```

external_reach: access from a cross-account principal.

### confused_deputy_path

**Source:** `reasoning/souffle/discovery/discovery.dl`

**Kind:** output

```datalog
.decl confused_deputy_path(role: symbol, service: symbol, resource: symbol, action: symbol)
```

confused_deputy: service-trusted role reaches sensitive resource.

### path_condition

**Source:** `reasoning/souffle/discovery/discovery.dl`

**Kind:** output

```datalog
.decl path_condition(principal: symbol, target: symbol, cond_key: symbol, cond_value: symbol)
```

Condition edges — surface per-hop conditions for Z3.

For each assume edge in a discovered path, emit the
condition keys and values attached to the principal.
The Go harness reads these to build Z3 constraints.


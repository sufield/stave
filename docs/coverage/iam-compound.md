# IAM compound coverage map

Maps the 36 patterns in `docs/taxonomies/iam-compound.md` against
existing Stave controls. Status per pattern is one of:

- **covered** — an existing control directly detects this pattern
  with cross-resource reasoning sufficient to fire on the exact
  shape the taxonomy describes.
- **partial** — one or more existing controls detect *legs* of
  the pattern (e.g., "role reaches sensitive data" without the
  IMDSv1 + public-subnet conjunction) but no single control
  composes the full chain. Authoring work is the composition,
  not the legs.
- **gap** — nothing existing detects the pattern. Authoring
  is from scratch.

## Important framing for this coverage map

The classifier (`internal/tools/scope-classifier`) marks only
**99 controls catalog-wide as `scope: compound`** today — all
ghost-reference family. The classifier uses purely structural
heuristics (archetype tag + multi-asset-type) and can't see
controls whose cross-asset reasoning lives in the *observation
extractor* rather than in the predicate AST.

The IAM catalog has roughly 25–30 *semantically compound*
controls today — NEP (Net Effective Permissions), BLASTRADIUS,
TRUST family, CROSS.ENV, CHAIN, SSO. These reason across
principals, policies, group memberships, SCPs, and reachable
resources, but they do so via pre-computed observation fields
(`identity.escalation.*.present`, `identity.blastradius.*`,
`identity.nep.*`) that flatten the composition into a single-
asset predicate.

**This coverage map treats those semantically-compound controls
as covered/partial citations even though the classifier marks
them atomic.** Updating the classifier to recognize semantic
compounds is a separate exercise (would need predicate-content
analysis or annotation of observation extractors). The map's
job is honest content classification, not classifier-output
mirroring.

The strategic implication: Stave's *true* compound surface is
larger than the 99 / 2,658 = 3.72% the classifier reports. A
post-I1 follow-up could backfill `scope: compound` on the
semantically-compound IAM controls listed below to bring the
classifier-output in line with the reality the coverage map
documents.

---

## Sub-family 1: Principal-policy-resource chains (Capital One shape)

### 1.1 `principal_chain.ec2_imdsv1_to_sensitive_data` — **partial**

**Existing legs:**
- `CTL.EC2.IMDSV2.001` + `CTL.EC2.IMDSV2.002` — IMDSv1 prohibition (compute leg, atomic)
- `CTL.EC2.IMDS.UNNECESSARY.001` + `CTL.EC2.IMDS.HOPLIMIT.001` — IMDS hygiene siblings
- `CTL.IAM.IDENTITY.BLASTRADIUS.004` — role reaches excessive sensitive resources (semantic compound, role-leg)
- `CTL.IAM.IDENTITY.BLASTRADIUS.001` — role blast radius threshold (semantic compound, role-leg)

**Gap:** the full Capital One conjunction (IMDSv1 + sensitive-data-tag + subnet-with-IGW-route + role-reaches-bucket). The legs exist; no single control composes the four-way AND.

### 1.2 `principal_chain.lambda_public_url_to_sensitive_data` — **partial**

**Existing legs:**
- `CTL.IAM.ROLE.LAMBDA.SCOPING.001` — Lambda execution role assumable by any function (function-role-misconfiguration leg)
- `CTL.IAM.IDENTITY.BLASTRADIUS.001` / `.004` — role blast radius / sensitive-resource reach (data-leg)

**Gap:** function URL public + role reaches sensitive data composition.

### 1.3 `principal_chain.ecs_task_public_lb_to_sensitive_data` — **gap**

**Existing legs:** ECS controls + ELB controls likely cover individual surfaces (need to verify in I2 against `controls/ecs/` and `controls/elb/`). No IAM-side composition control exists today.

### 1.4 `principal_chain.eks_irsa_pod_public_ingress_to_sensitive_data` — **gap**

**Existing legs:** EKS controls (`controls/eks/`) cover IRSA hygiene; `iam/identity/BLASTRADIUS.*` covers role reach. No EKS-pod + role-reach composition.

### 1.5 `principal_chain.cross_account_role_no_source_restriction` — **covered**

**Existing controls:**
- `CTL.IAM.IDENTITY.BLASTRADIUS.002` — cross-account role must require ExternalId (exact match for the pattern)
- `CTL.IAM.TRUST.CONFUSEDDEPUTY.001` — third-party role trust must have confused-deputy protection (variant)

### 1.6 `principal_chain.imdsv1_dataplane_drift` — **gap**

**Existing legs:** IMDSv1 prohibition controls exist; dataplane/proxy-tag heuristic doesn't.

**Sub-family 1 summary:** 1 covered, 2 partial, 3 gap. Authoring focus: compose the 3 gap patterns; promote partial→covered by writing the conjunction predicates the legs make possible.

---

## Sub-family 2: Role assumption & trust policy weaknesses

### 2.1 `trust.cross_account_no_external_id_external_account` — **covered**

**Existing controls:**
- `CTL.IAM.IDENTITY.BLASTRADIUS.002` — cross-account role must require ExternalId
- `CTL.IAM.TRUST.CONFUSEDDEPUTY.001`

### 2.2 `trust.service_principal_no_source_restriction` — **partial**

**Existing:** `CTL.IAM.TRUST.CONFUSEDDEPUTY.001` (third-party flavor). Service-principal flavor (`aws:SourceAccount` / `aws:SourceArn` for service-principal trusts) needs explicit authoring.

**Gap:** the AWS-service-principal variant (Lambda, CloudFormation, S3-event triggered roles).

### 2.3 `trust.wildcard_principal` — **likely covered**

**Need to verify in I2:** `controls/iam/trust/CTL.IAM.TRUST.*` — almost certainly an existing control on `"Principal": "*"` in trust policy. Defer citation to I2 review pass.

### 2.4 `trust.broken_string_equals_userid` — **gap**

No existing control on the `aws:userid` reusability subtlety.

### 2.5 `trust.cross_service_to_attacker_owned_resource` — **partial**

**Existing:** `CTL.IAM.TRUST.DUAL.001` (combine compute + identity-federation trust without scoping). The "service invoked by external customers" variant needs authoring.

### 2.6 `trust.allow_assumerole_back_into_high_privilege` — **covered**

**Existing controls:**
- `CTL.IAM.IDENTITY.BLASTRADIUS.003` — role assume chain must not exceed depth threshold
- `CTL.IAM.CHAIN.GHOST.DELETION.001` (chain-targeting variant, ghost-flavored)
- `CTL.IAM.ESCALATE.CHAIN.001` — chain-escalation

**Sub-family 2 summary:** 2 covered, 2 partial, 1 gap, 1 needs-verification. Already strong coverage via TRUST + BLASTRADIUS families.

---

## Sub-family 3: Privilege escalation paths (Rhino-catalog-derived)

### 3.1 `privesc.passrole_to_higher_privilege` — **covered**

**Existing:** `CTL.IAM.ESCALATE.PASSROLE.*` (likely; check the 44 ESCALATE controls). The `controls/iam/escalation/` directory has the full Rhino-derived set as atomic checks. Authoring work: backfill `scope: compound` after a review pass confirms these reason cross-resource via observation extractors.

### 3.2–3.6 — **covered (semantic-compound)**

All five Rhino-catalog patterns map to existing `controls/iam/escalation/CTL.IAM.ESCALATE.*` controls:
- `ATTACHUSERPOLICY.001` / `ATTACHROLEPOLICY.001` / `ATTACHGROUPPOLICY.001` → 3.5
- `PUTUSERPOLICY.001` / `PUTROLEPOLICY.001` → 3.2 (find the exact IDs in `iam/escalation/`)
- `UPDATEASSUMEROLEPOLICY.001` → 3.3
- `CREATEACCESSKEY.001` → 3.4
- `CREATEPOLICYVERSION.001` + `SETDEFAULTPOLICYVERSION.001` → 3.6

**Sub-family 3 summary:** All 6 patterns covered. Authoring work for I4 is **review-and-backfill** rather than fresh authoring: confirm each existing ESCALATE control reasons compound-shaped, backfill `scope: compound` + `corpus_reference: rhino:<technique>`. Target: 6 backfills, possibly 0 net-new authored controls.

---

## Sub-family 4: Policy composition pitfalls

### 4.1 `composition.inline_shadows_managed_deny` — **gap**

Composition-of-policies analysis isn't in existing controls.

### 4.2 `composition.cross_group_deny_allow_conflict` — **partial**

**Existing:** `CTL.IAM.NEP.*` family computes net effective permissions including group membership composition. The NEP framework can express this pattern; needs an authored control that specifically flags cross-group deny/allow with non-overlapping conditions.

### 4.3 `composition.notaction_unintended_widening` — **partial**

**Existing:** `CTL.IAM.POLICY.CONDITION.NOTRESOURCE.001` (NotResource variant). The NotAction variant needs authoring.

### 4.4 `composition.resource_wildcard_with_cumulative_breadth` — **partial**

**Existing:** Several `CTL.IAM.POLICY.*` controls (find specific IDs during I5) handle wildcard-action + narrow-action-set patterns individually. Cumulative breadth via NEP isn't yet a dedicated check.

### 4.5 `composition.deny_condition_doesnt_constrain_caller` — **gap**

Condition-key-presence analysis not in existing controls.

### 4.6 `composition.scp_gap_for_root_equivalent` — **covered**

**Existing controls:**
- `CTL.IAM.SCP.CLOUDTRAIL.001` — SCP must protect CloudTrail
- `CTL.IAM.SCP.CONFIG.001` — SCP must protect Config
- `CTL.IAM.SCP.GUARDDUTY.001` — SCP must protect GuardDuty
- `CTL.IAM.SCP.IAM.001` — SCP must restrict critical IAM actions
- `CTL.IAM.SCP.LEAVEORG.001` — SCP must deny LeaveOrganization
- `CTL.IAM.SCP.REGIONS.001` — SCP must restrict regions

**Sub-family 4 summary:** 1 covered, 3 partial, 2 gap. The NEP framework gives the substrate for the partial/gap patterns; I5 authoring is composition-of-NEP rather than from-scratch.

---

## Sub-family 5: Federation & Identity Center paths

### 5.1 `federation.oidc_broad_sub_to_elevated_role` — **partial**

**Existing:**
- `CTL.IAM.TRUST.OIDC.001` — OIDC federation trust must be scoped to specific repository (close match for the GH-Actions variant)
- `CTL.IAM.FEDERATION.ROLEMAPPING.001` — federated role must be scoped to specific IdP groups

### 5.2 `federation.github_oidc_no_repo_scope` — **covered**

**Existing:** `CTL.IAM.TRUST.OIDC.001` — explicit GH Actions repo-scope check.

### 5.3 `federation.saml_no_group_filter` — **partial**

**Existing:**
- `CTL.IAM.FEDERATION.ROLEMAPPING.001`
- `CTL.IAM.FEDERATION.SAML.AUDIENCE.001`
- `CTL.IAM.FEDERATION.SAML.CERT.001`

The role-mapping control may cover this; needs review during I6 authoring to confirm SAML Group-attribute scope is checked, not just generic mapping.

### 5.4 `federation.identity_center_broad_assignment` — **partial**

**Existing:** `CTL.IAM.SSO.PERMSET.ADMIN.001` — SSO permission set must not include AdministratorAccess. The "assignment to broad group" variant needs explicit authoring.

### 5.5 `federation.external_idp_with_role_chaining` — **covered**

**Existing:** `CTL.IAM.IDENTITY.BLASTRADIUS.003` (role assume chain depth) + `CTL.IAM.FEDERATION.*` compose.

### 5.6 `federation.session_no_duration_ceiling` — **covered**

**Existing:**
- `CTL.IAM.SESSION.DURATION.001` — role MaxSessionDuration exceeds 4 hours
- `CTL.IAM.FEDERATION.SESSION.DURATION.001` — federated role session duration ≤ 4h

**Sub-family 5 summary:** 3 covered, 3 partial. Strong existing coverage via FEDERATION + SSO + TRUST.OIDC + SESSION. I6 work is mostly partial→covered via the IdP-group / Identity-Center-group variants.

---

## Sub-family 6: Auth strength composition

### 6.1 `auth_strength.high_privilege_no_mfa_enforcement` — **covered**

**Existing:**
- `CTL.IAM.CONSOLE.MFA.001` — console users must have MFA enabled
- `CTL.IAM.MFA.HWKEY.001` — privileged accounts must use hardware MFA
- `CTL.IAM.CROSSCLOUD.MFA.001` — MFA across all cloud providers
- `CTL.IAM.SSO.MFA.001` — SSO must enforce MFA at Identity Center level

### 6.2 `auth_strength.old_access_key_high_privilege` — **partial**

**Existing:**
- `CTL.IAM.CRED.ROTATION.001` — access keys must be rotated within 90 days (rotation leg)
- `CTL.IAM.CRED.EXPIRY.001`, `CTL.IAM.CRED.TTL.EXCEEDED.001`
- `CTL.IAM.IDENTITY.BLASTRADIUS.005` — user blast radius (privilege-leg)

The pure-age check and the pure-blast-radius check exist; the **conjunction** (old key AND high privilege) does not.

### 6.3 `auth_strength.console_access_weak_password_policy` — **partial**

**Existing:**
- `CTL.IAM.PASSWORD.COMPLEXITY.001`, `.LENGTH.001`, `.REUSE.001`, `.ROTATION.001` (password-policy legs)
- `CTL.IAM.CONSOLE.MFA.001` (console-access leg)
- `CTL.IAM.IDENTITY.BLASTRADIUS.005` (privilege-leg)

Triple conjunction (console + weak-policy + high-privilege) needs authoring.

### 6.4 `auth_strength.scp_doesnt_block_root_equivalent` — **covered**

Already cited under 4.6: the SCP family covers this exhaustively.

### 6.5 `auth_strength.cross_account_assume_no_mfa` — **gap**

The MFA-in-trust-condition variant isn't in existing controls.

### 6.6 `auth_strength.federated_session_no_max_duration_for_elevated` — **partial**

**Existing:** `CTL.IAM.SESSION.DURATION.001`, `CTL.IAM.FEDERATION.SESSION.DURATION.001`. The **conjunction with "elevated permissions"** needs explicit authoring (today's controls fire on duration alone).

**Sub-family 6 summary:** 2 covered, 3 partial, 1 gap.

---

## Summary table

| Sub-family | Patterns | Covered | Partial | Gap |
|---|---:|---:|---:|---:|
| 1. Principal-policy-resource chains | 6 | 1 | 2 | 3 |
| 2. Role assumption & trust weaknesses | 6 | 2 | 2 | 1+1 verify |
| 3. Privilege escalation paths | 6 | 6 | 0 | 0 |
| 4. Policy composition pitfalls | 6 | 1 | 3 | 2 |
| 5. Federation & Identity Center | 6 | 3 | 3 | 0 |
| 6. Auth strength composition | 6 | 2 | 3 | 1 |
| **Total** | **36** | **15** | **13** | **7+1** |

**Calibration:** 41% covered, 36% partial, 22% gap. Stave's existing IAM compound surface is substantially stronger than the classifier-output suggested. The work distribution skews toward composition (partial→covered) rather than greenfield authoring (gap→covered).

---

## Authoring priority list — I2–I7 sequencing

The plan's targets (40 IAM compound controls across I2–I7) need re-derivation against this map. Two work shapes dominate:

1. **Backfill `scope: compound` on existing semantic compounds** (especially I4 — the entire ESCALATE family). Mechanical work; produces 20–30 "new compounds" without authoring new YAMLs. Pure data-quality reclassification.
2. **Compose the partial-leg conjunctions** (especially I1, I6). Authored predicates that AND together existing observation fields. ~15–20 net-new controls.

**Revised per-iteration targets:**

| Iter | Sub-family | Approach | Target |
|---|---|---|---:|
| I2 | Principal-policy-resource chains | Compose legs into 4-way ANDs; cover the 3 gaps (ECS, EKS, dataplane-drift) | 6 net-new |
| I3 | Role assumption & trust | 1 net-new (service-principal source restriction) + 1 (broken-userid) + 1 verify-then-cite (wildcard-principal); promote 2 partials to covered via composition | 4 net-new + 2 promotions |
| I4 | Privilege escalation | Mostly **review + backfill** existing ESCALATE controls with `scope: compound` + `corpus_reference: rhino:<technique>`. 0 net-new authored | ~20 backfills, 0 net-new |
| I5 | Policy composition pitfalls | Compose NEP-based variants; 2 gap-fills (inline-shadows-deny, deny-condition-no-constrain) | 4 net-new + 3 promotions |
| I6 | Federation & Identity Center | 0 net-new; 3 partial→covered via SAML-group-filter + Identity-Center-broad-assignment promotions | 0 net-new + 3 promotions |
| I7 | Auth strength composition | 1 net-new (MFA-in-cross-account-trust); 3 partial→covered via conjunction authoring (old-key + privileged, console + weak-policy + privileged, federated-session + elevated) | 4 net-new + 0 backfills |

**Total:** ~18 net-new + ~20 backfills + ~8 promotions = ~46 explicit-compound additions to the catalog.

**Compound-share trajectory:**
- Today: 99 / 2658 = 3.72%
- After IAM I2–I7 (backfills only): 99 + ~20 = 119 / 2658 = **4.48%**
- After IAM I2–I7 (all): 99 + ~46 = 145 / 2704 = **5.36%**
- Plus Phase 2–6 (VPC/KMS/S3/Lambda/ECS-EKS, estimated at the plan's original targets): another ~95 net-new ⇒ 240 / 2799 = **8.57%** — close to the 9% target.

If I4 produces only ~12 backfills instead of 20 (the review pass culls non-genuine compounds), the trajectory shifts down 0.3pp at each stage — still within striking distance of 9% after Phase 6.

---

## Notes for I2–I7 authors

- **The `corpus_reference` CI rule fires on every new `scope: compound`.** Each authored or backfilled compound control must carry a prefix-schema citation from `docs/taxonomies/iam-compound.md`. Plan accordingly — every authoring session reads the taxonomy for the right citation.
- **Backfills count toward the strategic compound-share number.** They aren't "free wins" — each one is the result of a review pass confirming the control genuinely reasons compound-shaped (predicate uses pre-computed observation fields that themselves cross assets). Skip-the-review backfills would degrade the metric per the Goodhart guard.
- **Authoring under existing concept dirs**, not under a new `iam/compound/` parallel tree. Decision locked in `aws-compound-control-authoring-plan.md` §1.
- **Observation-contract gaps surface here.** Patterns like 1.1's "subnet has IGW route" or 4.1's "managed-policy deny + inline allow composition" may require observation fields that aren't yet populated. Where I2–I7 encounter these, surface in the iteration's commit message + route to a separate observation-contract iteration; don't conflate observation work with authoring.
- **The `partial → covered` promotions are real authoring** — they require writing the conjunction predicate that ANDs the existing legs. Cheaper than greenfield because the observation fields exist, but not zero-effort.

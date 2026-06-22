# E2E Test: IAM credential manipulation escalation cluster

## Case summary

- **Pattern**: Privilege-escalation techniques where the principal manipulates
  **another IAM user's** credentials rather than self-modifying its own policies.
  The principal gains access *as* the victim user. Rhino Security Labs cluster
  covering the four credential-manipulation techniques Prowler's
  `iam_policy_allows_privilege_escalation` enumerates.
- **Semantic shift**: `target_user_arn` on each sub-namespace identifies the
  **victim** — the privileged user whose credentials the principal can forge or
  reset — not the principal itself. Same field name as Cluster 1 (where it
  meant self-target); the contract doc flags the difference explicitly.
- **Severity: Critical**. Matches the direct-impersonation tier (Clusters 1
  and 2 — ATTACHUSERPOLICY, ASSUMEROLE, UPDATETRUST are all Critical). A
  single `CreateAccessKey` or `UpdateLoginProfile` call yields usable
  credentials for the victim with no intermediate service to execute code.
  Distinct from the PASSROLE.* family at High, which requires a target
  service to run attacker code.

## Assets

| Principal | Technique populated | Victim | Fires |
|---|---|---|---|
| `alice-create-key` | `create_access_key.present = true` (target_has_max_keys=false) | `admin-victor` | ✅ `CREATEACCESSKEY.001` |
| `bob-update-login` | `update_login_profile.present = true` (target_has_mfa=false) | `admin-victor` | ✅ `UPDATELOGINPROFILE.001` |
| `carol-create-login` | `create_login_profile.present = true` (target_has_existing_profile=false) | `svc-terraform` | ✅ `CREATELOGINPROFILE.001` |
| `dave-resync-mfa` | `resync_mfa_device.present = true` (target_has_mfa=true) | `admin-victor` | ✅ `RESYNCMFADEVICE.001` |
| `eve-clean` | every technique `.present = false` | — | — |
| `some-service-role` | `kind = role` + all four techniques `.present = true` | — | ✅ all four credential-manipulation controls (role-side coverage — kind gate lifted) |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.IAM.ESCALATE.CREATEACCESSKEY.001`    | critical | `create_access_key.present=true` (any principal kind) | 2 |
| `CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001` | critical | `update_login_profile.present=true` (any principal kind) | 2 |
| `CTL.IAM.ESCALATE.CREATELOGINPROFILE.001` | critical | `create_login_profile.present=true` (any principal kind) | 2 |
| `CTL.IAM.ESCALATE.RESYNCMFADEVICE.001`    | critical | `resync_mfa_device.present=true` (any principal kind) | 2 |
| **Total** | | | **8** |

## Expected result

- Exit code: 3
- Findings: 8
- Assets evaluated: 6, unsafe: 5 (four failing users plus the role, which fires all four controls)

## Compound findings (RiskEngine emergent)

Techniques chain naturally: `UpdateLoginProfile` on a user with MFA enrolled
typically requires `ResyncMFADevice` or `DeactivateMFADevice` to yield a
usable console session; `CreateLoginProfile` on an MFA-less service account
is self-sufficient. When both techniques target the same victim (e.g., Bob
AND Dave both targeting `admin-victor`), the RiskEngine sees a compound
takeover pattern — one principal disarms MFA, another resets the password
— without any cross-control wiring. Same emergent-compound rule as the
ASSUMEROLE + UPDATETRUST pair from Cluster 2.

This fixture deliberately places Bob and Dave on the same victim
(`admin-victor`) to exercise that cross-asset relationship in the output,
even though neither control gates on the other.

## Notes

- Severity defaulted to Critical per the task's guidance — credential
  manipulation is direct impersonation with no intermediate service. Matches
  the Cluster 1 / Cluster 2 Critical tier rather than the PASSROLE.* High
  tier.
- The `target_has_*` diagnostic fields record preconditions that the
  extractor folded into `.present` upstream: `target_has_max_keys=true`
  would mean the attacker additionally needs `DeleteAccessKey`;
  `target_has_existing_profile=true` would mean `CreateLoginProfile` fails
  and `UpdateLoginProfile` is the vehicle instead. Retained on the finding
  for observability even though they don't affect predicate evaluation.
- The fixture snapshots have no `generated_by.source_type`, which Stave
  accepts by default — matching every other escalation fixture.

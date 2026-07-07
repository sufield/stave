# IAM Control Pack — First Non-S3 Domain

## Why This Matters

Stave spent 2 months on a hexagonal architecture refactoring (3,448 commits,
60+ domain renames, 44 Strangler Fig extractions). The engine was built to be
vendor-agnostic and asset-type-agnostic, but all 64 controls were S3-only.

The IAM control pack is the proof: a second resource domain that requires
**zero engine code changes**. The observation loader, CEL evaluator, assessment
engine, output marshaler, and CI commands all work unchanged. IAM observations
flow through the same pipeline as S3 observations.

## What Was Added

### 10 Controls (CIS AWS Benchmark aligned)

```
controls/iam/
  root/
    CTL.IAM.ROOT.MFA.001.yaml          CIS 1.5   Root must have MFA
    CTL.IAM.ROOT.ACCESSKEY.001.yaml    CIS 1.4   Root must not have access keys
  console/
    CTL.IAM.CONSOLE.MFA.001.yaml       CIS 1.10  Console users must have MFA
  credentials/
    CTL.IAM.CRED.UNUSED.001.yaml       CIS 1.12  Disable unused credentials
    CTL.IAM.CRED.ROTATION.001.yaml     CIS 1.14  Rotate keys within 90 days
  password/
    CTL.IAM.PASSWORD.LENGTH.001.yaml   CIS 1.8   Min length >= 14
    CTL.IAM.PASSWORD.REUSE.001.yaml    CIS 1.9   Reuse prevention >= 24
    CTL.IAM.PASSWORD.COMPLEXITY.001.yaml CIS 1.8  Require all character types
  policy/
    CTL.IAM.POLICY.INLINE.001.yaml     CIS 1.15  No inline policies on users
    CTL.IAM.POLICY.DIRECT.001.yaml     CIS 1.15  No direct policy attachment
```

All controls use `unsafe_state` type with existing operators (`eq`, `lt`).
Each includes HIPAA, PCI-DSS, and SOC2 compliance references where applicable.

### aws-iam Profile

`stave apply --profile aws-iam` loads the 10 IAM controls from the embedded
pack. The `profileControlDomain()` function now returns `"iam"` for the new
profile, fulfilling the `nolint:unparam` promise that was waiting since the
original S3 implementation.

### IAM Observation Properties

S3 uses `properties.storage.*`. IAM uses `properties.identity.*`.

Three asset types:

| Asset Type | `identity.kind` | Properties |
|---|---|---|
| `aws_iam_account` | `account` | `root.mfa_enabled`, `root.has_access_keys` |
| `aws_iam_user` | `user` | `console_access.*`, `credentials.*`, `access_keys.*`, `policies.*` |
| `aws_iam_password_policy` | `password_policy` | `password_policy.minimum_length`, `require_*`, `reuse_prevention_count` |

### Files Changed

**5 existing files modified** (configuration/registration only):

| File | Change |
|---|---|
| `internal/controldata/embed.go` | Added `embedded/iam/**/*.yaml` glob |
| `internal/builtin/pack/embedded/index.yaml` | Added `iam` pack + 10 control refs |
| `cmd/apply/profile.go` | Added `ProfileAWSIAM`, updated `ParseProfile()` + `profileControlDomain()` |
| `cmd/apply/apply_extra_test.go` | Added `{ProfileAWSIAM, "iam"}` test case |
| `AGENTS.md` | New file: AI agent codex for codebase rules |
| `MEMORY.md` | New file: refactoring context and technical debt |

**Zero engine changes**: no modifications to `internal/core/`, `internal/app/`,
or `internal/adapters/` (including `internal/adapters/cel/`).

## How To Use

```bash
# Standard mode with IAM controls directory
stave apply \
  --controls controls/iam \
  --observations observations \
  --max-unsafe 168h \
  --eval-time 2026-01-11T00:00:00Z

# Profile mode
stave apply --profile aws-iam --input observations/bundle.json
```

## Extractor Requirements

IAM observations require these AWS API calls:

| Property | AWS API | IAM Permission |
|---|---|---|
| `root.mfa_enabled` | `GetAccountSummary` | `iam:GetAccountSummary` |
| `root.has_access_keys` | `GetAccountSummary` | `iam:GetAccountSummary` |
| `console_access.enabled` | `GetLoginProfile` | `iam:GetLoginProfile` |
| `console_access.mfa_enabled` | `ListMFADevices` | `iam:ListMFADevices` |
| `credentials.unused` | `GenerateCredentialReport` | `iam:GenerateCredentialReport` |
| `access_keys.*` | `ListAccessKeys`, `GetAccessKeyLastUsed` | `iam:ListAccessKeys` |
| `policies.*` | `ListUserPolicies`, `ListAttachedUserPolicies` | `iam:ListUserPolicies` |
| `password_policy.*` | `GetAccountPasswordPolicy` | `iam:GetAccountPasswordPolicy` |

## Remaining Work

- Semantic aliases (`iam.*` predicates in `internal/builtin/predicate/`)
- Additional E2E test fixtures (password policy, user credentials, multi-control)
- Control reference regeneration (`make docs-controls`)
- Extractor prompt for IAM (`docs/extractor-prompt-iam.md`)

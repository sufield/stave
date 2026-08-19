# Appendix B — Sensitive Action Classification

Stave classifies 520 IAM actions into five risk categories. This powers
privilege escalation and permission analysis controls.

## Categories

| Category | Meaning |
|----------|---------|
| CredentialExposure | Actions that reveal or create credentials |
| DataAccess | Actions that read sensitive data |
| PrivEsc | Actions that escalate privileges |
| ResourceExposure | Actions that expose resources publicly |
| Discovery | Actions that enumerate infrastructure |

## The Registry

```bash
wc -l internal/core/iam/sensitive_actions_data.go
```

```
635 internal/core/iam/sensitive_actions_data.go
```

520 actions, each tagged with a category. The registry is a Go lookup
table — not something the reader writes, but something controls reference
via observation fields like `identity.actions.sensitive_count` and
`identity.policy.has_data_access_actions`.

## How It Connects

Privilege escalation controls in `internal/controls/iam/escalation/` use
the classification to detect dangerous permission combinations. For example,
`CTL.IAM.ESCALATE.CREATEACCESSKEY.001` fires when a user can call
`iam:CreateAccessKey` on other users — a CredentialExposure action.

## CLI

```bash
stave permissions --help
```

The `stave permissions` command queries net effective permissions from a
snapshot, using the sensitive action registry to highlight dangerous grants.

# Universal Security Statements

28 universal statements encoded as SMT-LIB 2.6 formulas. Each expresses
a security property that holds across all services — the intensional
complement to the extensional control catalog.

## How universals work

Each universal is a first-order logic formula of the form:

    ∀x ∈ Domain: Precondition(x) → Property(x)

Encoded as its negation for Z3: "find me a violation."

    ∃x: Precondition(x) ∧ ¬Property(x)

- `sat` → violation exists (the model IS the finding)
- `unsat` → universal holds for this snapshot
- `unknown` → solver timeout

## Catalog

### Monolithic file (U1–U25)

The original 20 universals live in `docs-internal/security/universals.smt2`
as a single file with shared prelude and per-universal push/pop blocks.

| ID | Statement | Domain | SMT-LIB |
|---|---|---|---|
| U1 | Unrestricted PM on wildcard resource | Identity | universals.smt2 |
| U2 | Cross-account without org boundary | Resource policy | universals.smt2 |
| U3 | Federation without subject restriction | Federation | universals.smt2 |
| U4 | Credential exceeds max lifetime (access keys) | Credential | universals.smt2 |
| U5 | Session without attribution | Session | universals.smt2 |
| U6 | Policy removal without compensating control | Identity | universals.smt2 |
| U7 | Stateful resource not encrypted at rest | Data protection | universals.smt2 |
| U9 | Endpoint without TLS 1.2+ | Data protection | universals.smt2 |
| U10 | Classified data publicly accessible | Data protection | universals.smt2 |
| U11 | Isolation intent violation | Network | universals.smt2 |
| U12 | Management port open to 0.0.0.0/0 | Network | universals.smt2 |
| U13 | Default VPC with active resources | Network | universals.smt2 |
| U14 | Active region without CloudTrail | Detection | universals.smt2 |
| U15 | Detection configured but not delivering | Detection | universals.smt2 |
| U16 | Detection scope < deployment scope | Detection | universals.smt2 |
| U17 | CloudTrail logs not tamper-proof | Detection | universals.smt2 |
| U18 | Credential exceeds max lifetime (general) | Credential | universals.smt2 |
| U19 | Key rotation enabled but stalled | Credential | universals.smt2 |
| U20 | Root account used for operations | Identity | universals.smt2 |
| U21 | Declared intent ≠ observed state | Meta | universals.smt2 |
| U22 | Ghost reference — target doesn't exist | Structural | universals.smt2 |
| U25 | Compute role has admin permissions | Identity | universals.smt2 |

Gaps: U8, U23, U24 reserved (not yet formalized).

### Per-file universals (U26–U33)

Discovered 2026-08-07 by catalog→formulas analysis: properties appearing
across ≥3 services with no existing universal.

| ID | Statement | Domain | Services | Coverage | File |
|---|---|---|---|---|---|
| U26 | Service-level logging must be enabled | Logging | 48 | 69% | u26-service-logging.smt2 |
| U27 | Non-public endpoints must require auth | Auth | 28 | 71% | u27-endpoint-authentication.smt2 |
| U28 | Stateful resources must have deletion protection | Integrity | 12 | 75% | u28-deletion-protection.smt2 |
| U29 | Stateful resources must have backup | Integrity | 18 | 61% | u29-backup-configured.smt2 |
| U30 | Config must not contain plaintext secrets | Secrets | 21 | 57% | u30-no-plaintext-secrets.smt2 |
| U31 | Software must not run deprecated versions | Currency | 13 | 92% | u31-version-currency.smt2 |
| U32 | Compute must enforce IMDSv2 | Compute | 10 | 50% | u32-imdsv2-enforced.smt2 |
| U33 | Required security services must be enabled | Detection | 13 | 77% | u33-security-service-enabled.smt2 |

## Relationships

```
Stateful resource family (stores_data qualifier):
  U7  encryption → U28 deletion protection → U29 backup

Credential lifecycle:
  U30 storage → U4/U18 lifetime → U19 rotation

Detection lifecycle:
  U33 enabled → U15 delivering → U16 regional scope

Logging stack:
  U14 region CloudTrail → U26 service logging → U15 detection delivery

Authentication hierarchy:
  U27 endpoint auth → U3 federation subject → U9 TLS transport
```

## Usage

```bash
# Run a single universal against a snapshot
z3 data/universals/u26-service-logging.smt2 snapshot.smt2

# Run the original 20 universals
z3 docs-internal/security/universals.smt2 snapshot.smt2
```

## Gap sweep

Coverage percentages are from the forward gap sweep
(`docs-internal/gap-reports/universal-forward-sweep-2026-08-07.md`).
Re-sweep monthly after control authoring sprints.

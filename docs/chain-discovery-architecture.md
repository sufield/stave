# Chain Discovery Architecture

## Overview

Chain discovery answers: "given this account's configuration,
what can an attacker reach from any starting point?" It
computes this exhaustively using formal reasoning, not by
simulating attacks or sampling paths.

## Three-Engine Pipeline

```
Snapshot (obs.v0.1)
  │
  ▼
stave export-sir --format jsonl
  │
  ▼
┌─────────────────────────────────────────────┐
│         SIR Facts (JSONL triples)            │
│  (subject, predicate, object)               │
│  can_assume, has_action, has_resource,      │
│  trusts_service, conditions, ...            │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│         Soufflé / Datalog                    │
│                                             │
│  Input:  SIR facts as TSV relations         │
│  Rules:  reasoning/souffle/iam/rules.dl     │
│          reasoning/souffle/discovery/       │
│            discovery.dl                     │
│  Output: All reachable paths with           │
│          classification + condition edges   │
│                                             │
│  Computes: transitive closure (fixpoint)    │
│  Guarantee: finds ALL paths, not a sample   │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│         Z3 SMT Solver (deferred)             │
│                                             │
│  Input:  Each path + its condition edges    │
│  Query:  Are all conditions on all edges    │
│          simultaneously satisfiable?        │
│  Output: SAT (path is viable + witness)     │
│          UNSAT (path is semantically dead)  │
│                                             │
│  Filters: structural paths → viable paths   │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│         Deduplication                        │
│                                             │
│  Compare viable paths against 622 known     │
│  chain YAML definitions.                    │
│  Novel = not covered by any known chain     │
│  Confirmed = matches a known chain pattern  │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│         Report                               │
│                                             │
│  Novel chains: paths nobody designed a      │
│  control for. These are the discoveries.    │
│                                             │
│  Confirmed chains: known patterns that      │
│  exist in this specific account. Validates  │
│  both the chain definitions and the engine. │
└─────────────────────────────────────────────┘
```

## Why Three Engines

Each engine contributes something the others cannot:

| Engine | What It Does | Why It's Needed |
|--------|-------------|----------------|
| Soufflé/Datalog | Transitive closure over relationships | Finds ALL paths exhaustively. A search-based approach finds A path. Datalog finds EVERY path. |
| Z3 | Condition satisfiability per path | Filters structurally-present but semantically-dead paths. Without Z3, every structural edge is assumed traversable. |
| cvc5 | Confirmation | Multi-engine agreement eliminates solver bugs. A path verified by Z3 must also be confirmed by cvc5. |

## Relationship Types

The SIR facts exporter (`internal/core/sirfacts/facts.go`, 21
projectors) projects these relationship types from the snapshot:

| Fact Type | Edge Meaning | Source Projector |
|-----------|-------------|-----------------|
| can_assume | Principal can assume a role | assumeEdgeFacts, trustPolicyFacts |
| has_action | Role has an IAM action grant | iamPolicyFacts |
| has_resource | Role has a resource ARN pattern | iamPolicyFacts |
| trusts_service | Role trusts a service principal | trustPolicyFacts |
| has_deny_action | Explicit deny on an action | denyPolicyFacts |
| has_condition | Statement has condition constraints | conditionFacts |
| has_type | Asset type classification | assetFacts |
| has_identity | Principal identity metadata | identityFacts |
| has_exposure | Resource exposure status | exposureFacts |
| has_tag | Asset tagging | tagFacts |
| has_control | Control evaluation result | controlFacts |

## Security Query Classifications

The discovery engine classifies each path into query types:

| Query | What It Finds | Datalog Relation |
|-------|--------------|-----------------|
| escalation | Path to a higher-privilege role (admin, wildcard actions) | `escalation_path` |
| exfil | Role can write to resources via assume chain | `exfil_path` |
| external | External principal reaches internal resources | `external_reach` |
| confused-deputy | Service trust without source condition | `confused_deputy_path` |
| privesc | Any multi-hop privilege increase | `privesc_path` |

## File Structure

```
reasoning/souffle/
  iam/
    schema.dl          ← 35+ input relations (SIR fact types)
    rules.dl           ← effective-access derivation, ARN matching,
                         deny override, unauthorized_access
    extract.go         ← JSONL → per-predicate TSV splitter
    validate.go        ← G2 cross-validator (template for discovery)
  discovery/
    discovery.dl       ← path-tracking, security classification,
                         condition edge output (extends iam/rules.dl)
    main.go            ← orchestrator (export-sir → extract → souffle → parse → dedup → report)
    dedup.go           ← compare paths against chains/*.yaml by risk category
    report.go          ← text + JSON output formatting
    LIVE-VALIDATION.md ← runbook for testing against a live AWS account
```

## Deduplication Strategy

Dedup is coarse — by risk category, not exact path. A discovered
path is "confirmed" if any existing chain YAML covers the same
risk class:

| Discovery Category | Matching Chain Field | Matching Values |
|-------------------|---------------------|-----------------|
| escalation | postconditions | privilege_escalation, admin_access, shadow_admin_access, full_account_admin |
| exfiltration | postconditions | data_access, data_exfiltration, training_data_leak |
| external-reach | preconditions | cross_account_access, external_access |
| confused-deputy | preconditions | confused_deputy |

A path is "novel" if no known chain covers its risk class at all.

## Comparison to Offensive Agents

| Dimension | Chain Discovery (Stave) | Offensive Agent |
|-----------|------------------------|----------------|
| Finds | Every path in the graph | A path from a foothold |
| Operates on | Snapshot (offline) | Live environment (runtime) |
| Credentials | None | Required |
| Completeness | Exhaustive (Datalog fixpoint) | Sampled (agent exploration) |
| Proves absence | Yes (no path = no path exists) | No (no path found ≠ no path exists) |
| Deterministic | Yes (same facts = same paths) | No |

Chain discovery and offensive testing are complementary.
Chain discovery is the screening tool (fast, complete, offline).
Offensive testing is the confirmation tool (slow, targeted, live).

## Running

```bash
# From observations directory
make chain-discover ARGS="-snapshot observations/"

# From pre-exported JSONL
make chain-discover ARGS="-jsonl /tmp/facts.jsonl"

# Filter by query type
make chain-discover ARGS="-snapshot observations/ -query escalation"

# Novel chains only, JSON output
make chain-discover ARGS="-snapshot observations/ -novel-only -json"

# Limit path depth
make chain-discover ARGS="-snapshot observations/ -max-hops 3"
```

All flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-snapshot` | — | Snapshot observations directory |
| `-jsonl` | — | Pre-existing JSONL fact stream (mutually exclusive with -snapshot) |
| `-controls` | `controls` | Controls directory |
| `-chains` | `chains` | Chain YAML directory for dedup |
| `-stave` | `./stave` | Path to stave binary |
| `-souffle` | `souffle` | Path to souffle binary |
| `-out` | temp | Output directory |
| `-now` | `2026-01-15T00:00:00Z` | Eval-time for deterministic output |
| `-query` | `all` | Query filter: all, escalation, exfil, external, confused-deputy |
| `-novel-only` | false | Only show novel paths |
| `-json` | false | JSON output |
| `-max-hops` | 5 | Maximum path depth (1-5) |

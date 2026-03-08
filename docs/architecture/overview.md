---
title: "Architecture Overview"
sidebar_label: "Architecture"
sidebar_position: 1
description: "Stave's internal architecture: pipeline stages, package map, trust boundaries, and command routing."
---

# Architecture Overview

Stave is a single static binary with no plugins, no network, and no persistent state. All evaluation runs as a pure function: files in, findings out.

## Pipeline

```mermaid
flowchart TD
    obs["Observations (JSON)"] --> sv["Schema Validation<br/><i>Reject malformed input early</i>"]
    ctl["Controls (YAML)"] --> sv
    sv --> tb["Timeline Builder<br/><i>Sort snapshots, build per-asset<br/>timelines of safe/unsafe states</i>"]
    tb --> ev["Evaluator<br/><i>Match predicates, compute durations,<br/>apply thresholds, emit findings</i>"]
    ev --> ow["Output Writer<br/><i>JSON or text to stdout / --out file</i>"]
```

## Package Map

```
stave/
├── cmd/stave/              Entry point (main.go)
│   └── cmd/                Cobra command definitions
│       ├── root.go         Global flags, --require-offline, --sanitize, --force
│       ├── apply/          apply command tree (handler, options, deps, validate, verify)
│       ├── diagnose/       diagnose command tree (artifacts, docs, report)
│       ├── enforce/        CI commands (baseline, cidiff, diff, fix, gate, graph)
│       ├── ingest/         ingest command + profile dispatch
│       ├── initcmd/        init command (alias, config, context, env)
│       ├── prune/          snapshot lifecycle (archive, cleanup, hygiene, upcoming)
│       ├── bugreport/      bug-report command + doctor checks
│       ├── fixtures/       demo command + fixture data
│       ├── templates/      Go template helpers
│       └── cmdutil/        Shared CLI utilities
│
├── internal/
│   ├── domain/             Core business logic (no I/O)
│   │   ├── evaluation/     Evaluation engine (engine, exposure, diagnosis, risk, remediation)
│   │   ├── diag/           Diagnose engine
│   │   ├── predicate/      Predicate operators (15 ops)
│   │   ├── asset/          Asset model
│   │   ├── kernel/         Core domain types
│   │   ├── policy/         Policy types
│   │   ├── ports/          Port interfaces
│   │   ├── securityaudit/  Security audit report types
│   │   └── validation/     Domain validation rules
│   │
│   ├── app/                Use-case orchestration
│   │   ├── eval/           Wire inputs → evaluator → output (pipeline)
│   │   ├── validation/     Wire inputs → schema checks
│   │   ├── diagnose/       Wire inputs → diagnostics
│   │   ├── capabilities/   Capabilities query
│   │   ├── contracts/      Port interfaces (FindingMarshaler, EnrichFunc)
│   │   ├── service/        Shared app services (evaluation, readiness)
│   │   ├── workflow/       Envelope assembly
│   │   ├── ingest/         Snapshot ingestion
│   │   ├── hygiene/        Snapshot lifecycle reporting
│   │   ├── project/        Project init and enforcement runners
│   │   ├── securityaudit/  Security audit builders
│   │   └── support/        Bug report and diagnose runners
│   │
│   ├── adapters/
│   │   ├── input/          File loaders (JSON observations, YAML controls, S3 extractors)
│   │   ├── output/         JSON/text/SARIF output marshalers
│   │   ├── gitinfo/        Git repository metadata
│   │   └── govulncheck/    Vulnerability checking
│   │
│   ├── contracts/          Schema validation (obs.v0.1, ctrl.v1 via JSON Schema)
│   ├── cli/                CLI error types, config, and UI utilities
│   ├── sanitize/           --sanitize implementation
│   ├── safetyenvelope/     Output envelope types and validation
│   ├── integrity/          Manifest integrity verification
│   ├── compliance/         Compliance mapping
│   ├── config/             Configuration loading
│   ├── builtin/            Embedded control packs and predicates
│   └── platform/           Platform utilities (crypto, fsutil, logging, state)
│
├── schemas/                Schema source of truth (JSON Schema files)
├── controls/s3/            S3 control packs (43 YAML files)
└── examples/               Example observations and controls
```

### Layer Rules

- **`domain/`** contains pure business logic with no file I/O, no CLI dependencies, and no external packages beyond the standard library.
- **`app/`** orchestrates use cases by wiring domain logic to adapters. It handles the flow: load inputs → validate → apply → format output.
- **`adapters/`** handle all I/O: reading files, parsing formats, writing output.
- **`cmd/`** handles only CLI concerns: flag parsing, exit codes, error formatting.

## Trust Boundaries

```mermaid
flowchart LR
    snap["Snapshot Files<br/>(untrusted input)"]
    ctl["Control Files<br/>(trusted input)"]

    subgraph machine ["User Machine"]
        subgraph stave ["Stave Binary"]
            sv["Schema Validation<br/>(reject bad input)"]
            ev["Evaluator<br/>(closed DSL only)"]
        end
    end

    snap --> sv
    ctl --> ev
    sv --> ev

    stave --> out1["stdout<br/>(findings JSON)"]
    stave --> out2["stderr<br/>(errors, logs)"]
    stave --> out3["--out file<br/>(0600)"]

    style stave fill:none,stroke:#333
    style machine fill:none,stroke:#999
```

> **No network | No exec | No creds | No plugins**

**Input trust levels:**

| Input | Trust Level | Validation |
|-------|-------------|------------|
| Observation files | Untrusted | Full JSON Schema validation, `additionalProperties: false` |
| Control files | Trusted (user-authored or shipped) | YAML Schema validation, operator allowlist |
| CLI flags | Trusted (user-supplied) | Path normalization, bucket name validation |

**Output trust:**

All output is written with restricted permissions (`0700` dirs, `0600` files). Stdout/stderr are the primary output channels; file output only happens when `--out` is passed.

## Command Map

| Command | Entry Point | App Layer | Domain Layer |
|---------|-------------|-----------|--------------|
| `apply` | `cmd/apply/` | `app/eval/` | `domain/evaluation/` |
| `validate` | `cmd/apply/validate/` | `app/validation/` | `contracts/` |
| `diagnose` | `cmd/diagnose/` | `app/diagnose/` | `domain/diag/` |
| `ingest` | `cmd/ingest/` | `app/ingest/` | Adapter-level extraction |
| `verify` | `cmd/apply/verify/` | — | Before/after comparison |
| `snapshot hygiene` | `cmd/prune/hygiene/` | `app/hygiene/` | Weekly lifecycle report |
| `ci fix-loop` | `cmd/enforce/fix/` | — | Apply before/after + verification |
| `capabilities` | `cmd/commands.go` | `app/capabilities/` | — |
| `graph coverage` | `cmd/enforce/graph/` | — | Predicate matching |

## Schema Lifecycle

1. Source-of-truth schemas live in `schemas/` (e.g., `obs.v0.1.schema.json`).
2. `make sync-schemas` copies them to `internal/contracts/schema/embedded/` for embedding.
3. The copied files are gitignored build artifacts.
4. `make build` runs `sync-schemas` automatically.

Schema IDs use `urn:stave:schema:` (not HTTP URLs) to avoid implying network fetching.

## Further Reading

- [Data Flow and I/O](../trust/data-flow-and-io.md) — per-command I/O model
- [Execution Safety](../trust/execution-safety.md) — no-exec guarantees
- [Security Guarantees](../trust/01-guarantees.md) — full guarantee inventory

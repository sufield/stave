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
    obs["Observations (JSON)"] --> sv["Schema Validation\n<i>Reject malformed input early</i>"]
    ctl["Controls (YAML)"] --> sv
    sv --> tb["Timeline Builder\n<i>Sort snapshots, build per-asset\ntimelines of safe/unsafe states</i>"]
    tb --> ev["Evaluator\n<i>Match predicates, compute durations,\napply thresholds, emit findings</i>"]
    ev --> ow["Output Writer\n<i>JSON or text to stdout / --out file</i>"]
```

## Package Map

```
stave/
├── cmd/stave/              Entry point (main.go)
│   └── cmd/                Cobra command definitions
│       ├── root.go         Global flags, --require-offline, --sanitize, --force
│       ├── apply/          apply command tree (handler, options, deps)
│       ├── diagnose/       diagnose command tree (artifacts, docs, report)
│       ├── enforce/        CI commands (baseline, cidiff, diff, fix, gate, graph)
│       ├── ingest/         ingest command + profile dispatch
│       ├── initcmd/        init command (alias, config, context, env)
│       ├── prune/          snapshot lifecycle (archive, cleanup, hygiene, manifest)
│       ├── bugreport/      bug-report command
│       ├── fixtures/       demo command + fixture data
│       └── cmdutil/        Shared CLI utilities
│
├── internal/
│   ├── domain/             Core business logic (no I/O)
│   │   ├── evaluation/     Evaluation engine (engine, exposure, risk, remediation)
│   │   ├── diag/           Diagnose engine
│   │   ├── predicate/      Predicate operators (15 ops)
│   │   ├── asset/          Asset model
│   │   ├── kernel/         Core domain types
│   │   ├── policy/         Policy types
│   │   ├── ports/          Port interfaces
│   │   └── validation/     Domain validation rules
│   │
│   ├── app/                Use-case orchestration
│   │   ├── eval/           Wire inputs → evaluator → output
│   │   ├── validation/     Wire inputs → schema checks
│   │   ├── diagnose/       Wire inputs → diagnostics
│   │   ├── capabilities/   Capabilities query
│   │   ├── service/        Shared app services
│   │   └── ...             (ingest, hygiene, workflow, etc.)
│   │
│   ├── adapters/
│   │   ├── input/          File loaders (JSON observations, YAML controls)
│   │   └── output/         JSON/text output writers
│   │
│   ├── contracts/          Schema validation (obs.v0.1, ctrl.v1 via JSON Schema)
│   ├── cli/                CLI error types and UI utilities
│   ├── sanitize/           --sanitize implementation
│   └── platform/           Platform-specific code (logging, fsutil)
│
├── schemas/                Schema source of truth (JSON Schema files)
├── controls/s3/            S3 control packs (43 YAML files)
└── examples/               Example observations
```

### Layer Rules

- **`domain/`** contains pure business logic with no file I/O, no CLI dependencies, and no external packages beyond the standard library.
- **`app/`** orchestrates use cases by wiring domain logic to adapters. It handles the flow: load inputs → validate → apply → format output.
- **`adapters/`** handle all I/O: reading files, parsing formats, writing output.
- **`cmd/`** handles only CLI concerns: flag parsing, exit codes, error formatting.

## Trust Boundaries

```mermaid
flowchart LR
    snap["Snapshot Files\n(untrusted input)"]
    ctl["Control Files\n(trusted input)"]

    subgraph machine ["User Machine"]
        subgraph stave ["Stave Binary"]
            sv["Schema Validation\n(reject bad input)"]
            ev["Evaluator\n(closed DSL only)"]
        end
    end

    snap --> sv
    ctl --> ev
    sv --> ev

    stave --> out1["stdout\n(findings JSON)"]
    stave --> out2["stderr\n(errors, logs)"]
    stave --> out3["--out file\n(0600)"]

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

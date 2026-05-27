---
title: "Enable the Z3 Solver"
sidebar_label: "Enable Z3"
description: "Install libz3 and use Z3 with Stave. The Stave binary itself is built CGO_ENABLED=0 and has no Z3 dependency; Z3 is opt-in per-machine for the example provers and the SMT-LIB file pipeline."
---

# Enable the Z3 Solver

The Stave binary is built with `CGO_ENABLED=0` and ships no
native libraries. Z3 is opt-in: install it once on the machines
that need it, then point your reasoning workflow at it. There is
no Stave config flag to "enable Z3" — the engine is selected by
which tool reads the exported facts.

If you only need to understand what Z3 adds, read [Stave and Z3](../../../docs-content/explanation/z3-solver.md)
first. This page is the install and verification recipe.

## When You Need Z3

| Scenario | Need libz3? |
|---|---|
| Run `stave apply` against YAML controls | No — uses in-process CEL |
| Export facts with `stave export-sir --format smt2` | No — Stave writes the SMT-LIB file; the solver runs separately |
| Run the exported SMT-LIB file through Z3 CLI | Yes — install `z3` |
| Run the exported file through cvc5 / Yices | No — install that solver instead |
| Build / run the `examples/z3-*` Go programs | Yes — install `libz3-dev` (development headers for cgo) |
| Embed Z3 in your own prover linked against `pkg/stave` | Yes — same as above |

The split keeps the main release artefact small and
signature-attested without forcing every operator to compile
against libz3.

## Install

| OS | Command |
|---|---|
| Ubuntu 22.04 / 24.04 / Debian | `sudo apt-get install -y z3 libz3-dev pkg-config` |
| Fedora / RHEL | `sudo dnf install -y z3 z3-devel pkgconf` |
| Arch | `sudo pacman -S z3 pkgconf` |
| macOS (Homebrew) | `brew install z3 pkg-config` |
| Nix | `nix-shell -p z3 pkg-config` |

The `z3` package gives you the CLI; `libz3-dev` (or `z3-devel`)
gives you the headers needed for cgo builds. Install both if you
plan to use both paths.

## Verify

```bash
z3 --version
# Z3 version 4.13.0 - 64 bit
```

Smoke-test against an SMT-LIB file Stave can produce:

```bash
cd /tmp
cat > smoke.smt2 <<'SMT'
(declare-const bucket_public Bool)
(declare-const policy_principal_wildcard Bool)
(assert (= bucket_public policy_principal_wildcard))
(assert bucket_public)
(check-sat)
(get-model)
SMT
z3 smoke.smt2
# sat
# (
#   (define-fun bucket_public () Bool true)
#   (define-fun policy_principal_wildcard () Bool true)
# )
```

If you see `sat` plus a model, the solver is working.

## Use Z3 with Stave

There are two integration paths, picked at the workflow boundary
— not by a Stave flag.

### Path 1: File boundary (no cgo)

```bash
# 1. Export facts in SMT-LIB v2 from a snapshot bundle
stave export-sir --input observations/bundle.json \
                 --format smt2 \
                 --out facts.smt2

# 2. Add a question (assertion + check-sat) on top of the facts
cat question.smt2 facts.smt2 > query.smt2

# 3. Run any SMT solver
z3 query.smt2
# or: cvc5 query.smt2
# or: yices-smt2 query.smt2
```

This is the default. The Stave binary stays free of native
dependencies; the solver of your choice runs the query. Swap Z3
for cvc5 or Yices by changing one command.

Worked example: [`examples/z3-multi-hop-can-assume/`](https://github.com/sufield/stave/tree/main/examples/z3-multi-hop-can-assume) —
loads facts, asserts a multi-hop `iam:AssumeRole` reachability
question, prints SAT / UNSAT.

### Path 2: Library API + cgo

For embedded use — tight feedback loops, custom provers built on
Stave's structured types — link directly against libz3 from a Go
program that imports `pkg/stave`:

```bash
cd stave/examples/z3-public-exposure/z3prove
CGO_ENABLED=1 go run .
```

Worked example: [`examples/z3-public-exposure/`](https://github.com/sufield/stave/tree/main/examples/z3-public-exposure) —
loads an observation snapshot via the Stave library API, builds
a per-bucket Z3 model in process, returns SAT / UNSAT.

The cgo path was historically the only option. The file-boundary
path is now preferred for most uses because it composes with any
SMT-conformant solver and keeps the Stave binary native-dep-free.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `z3: command not found` | Z3 CLI not installed | Install the `z3` package per the table above |
| `pkg-config: z3 was not found` during cgo build | Missing dev headers | Install `libz3-dev` / `z3-devel` |
| `dyld: Library not loaded: libz3.dylib` (macOS) | Brew-linked libz3 not on the loader path | `brew link --force z3`, or set `DYLD_LIBRARY_PATH=$(brew --prefix z3)/lib` |
| `unsat` on a query you expected `sat` | Question encoding bug, not Stave | Reproduce with `z3 -smt2 query.smt2 -v:10`; check assertions in isolation |
| Long-running `check-sat` | Quantifier instantiation blow-up | Add `(set-option :timeout 30000)` to bound the query; consider reformulating |

For deeper integration questions, the [Z3 Question Catalogue](../../../docs-content/explanation/z3-question-catalogue.md)
documents which question shapes Stave's exported facts are
designed to answer.

## Release Posture

Z3 is excluded from the Stave release bundles on purpose:

- The signed `stave` binary has no native dependency surface.
- Operators audit one supply chain (Stave's), not two (Stave + libz3).
- Replacing Z3 with cvc5 / Yices for a given workflow is a
  one-command change, not a rebuild.

See [Release Security](../trust/02-release-security.md) for the
full rationale.

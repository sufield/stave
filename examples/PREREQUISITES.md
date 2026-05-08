# Examples — Prerequisites

This file collects the host-side dependencies the engine
examples need. Stave itself has no native dependencies; these
prerequisites apply only to the example provers and engine
runners that consume Stave's exported facts.

## libz3 development headers (for `z3prove/` examples)

The Go-bound Z3 provers under `<example>/z3prove/` use the
`github.com/aclements/go-z3` package, which links against
`libz3` via CGO. The compiler needs `z3.h` at build time;
without it you'll see:

```
fatal error: z3.h: No such file or directory
```

Install before running `CGO_ENABLED=1 go run .` from inside
`z3prove/`:

| OS | Command |
|---|---|
| Ubuntu 22.04 / 24.04 | `sudo apt-get install -y libz3-dev pkg-config` |
| Debian 12+ | `sudo apt-get install -y libz3-dev pkg-config` |
| Fedora / RHEL 9+ | `sudo dnf install -y z3-devel pkgconf-pkg-config` |
| Arch / Manjaro | `sudo pacman -S z3 pkgconf` |
| macOS (Homebrew) | `brew install z3 pkg-config` |
| nix | `nix-shell -p z3 pkg-config` |

The Stave binary itself does NOT depend on libz3. The
`z3prove/` directories are separate Go modules so their CGO
link stays out of Stave's main build. Running `make build` in
the repo root works on a host with no libz3 installed; only
the per-example `go run .` requires the headers.

## SMT-LIB CLI solvers (for `z3-*` examples)

The SMT-LIB-only examples (`examples/z3-*`) shell out to the
solver CLIs — no Go binding, no CGO, no library import.

| OS | Command |
|---|---|
| Ubuntu 22.04 / 24.04 | `sudo apt-get install -y z3 cvc5` |
| Debian 12+ | `sudo apt-get install -y z3 cvc5` |
| Fedora / RHEL | `sudo dnf install -y z3 cvc5` |
| macOS (Homebrew) | `brew install z3 cvc5` |

Yices (optional cross-check) is at https://yices.csl.sri.com/.

## Soufflé (for `souffle-reachability/`)

Soufflé doesn't ship a Python wheel, so it's a system binary.

| OS | Command |
|---|---|
| Ubuntu 22.04 / 24.04 with sudo | `sudo apt-get install -y souffle` |
| Ubuntu 24.04 without sudo | extract the upstream `.deb` into `~/.local`: `curl -fsSL https://github.com/souffle-lang/souffle/releases/download/2.5/x86_64-ubuntu-2404-souffle-2.5-Linux.deb -o /tmp/s.deb && dpkg-deb -x /tmp/s.deb /tmp/sx && cp /tmp/sx/usr/bin/souffle* ~/.local/bin/ && export PATH=$HOME/.local/bin:$PATH` |
| macOS (Homebrew) | `brew install souffle` |

## SWI-Prolog (for `prolog-proof-trees/`)

| OS | Command |
|---|---|
| Ubuntu 22.04 / 24.04 | `sudo apt-get install -y swi-prolog` |
| Fedora / RHEL | `sudo dnf install -y pl` |
| macOS (Homebrew) | `brew install swi-prolog` |

## Python venv (for `clingo-constraints/`, `sat-control-regression/`)

These engines ship as Python libraries (no system binary).

```bash
python3 -m venv .tools-venv
.tools-venv/bin/pip install clingo python-sat pyyaml
```

The compare-engines harness expects the venv at
`<repo-root>/.tools-venv` by default. Override with
`CLINGO_VENV` / `PYSAT_VENV` env vars.

## Java (optional, for TLA+/TLC)

The TLA+ engine example (`examples/tlaplus-temporal-safety/`)
ships with a Python BFS that runs without Java. The
`CognitoSafety.tla` + `CognitoSafety.cfg` files are for
TLC users:

```bash
curl -fsSL -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
java -cp tla2tools.jar tlc2.TLC CognitoSafety.tla -config CognitoSafety.cfg
```

Java 17+ recommended. The Python runner is the load-bearing
path for the example; TLC is the upgrade route when temporal
properties become required.

## Why the prereqs aren't bundled

Stave is air-gapped by design: it ships as a single Go binary
with no runtime dependencies. The example provers and engine
runners are *demonstrations* of what external tools can do
with Stave's fact export — each one is opt-in, and each
needs its own runtime installed by the operator. The
boundary between Stave and the engines is the on-disk file
format (JSONL or SMT-LIB v2); no engine is invoked as a
subprocess by Stave itself.

---
name: stave-setup
description: Build Stave from source and verify the binary and control catalog work, adapting to what is already installed
triggers:
  - first time touching Stave
  - install Stave
  - build Stave
  - set up Stave
  - get started with Stave
requires:
  - go (>= 1.27 — see https://go.dev/dl/)
  - git
  - jq (apt: sudo apt install jq)
---

# stave-setup

## What this skill does
Installs prerequisites, builds Stave from source, and verifies the binary +
control catalog. Adapts to what is already installed — skip steps whose check
already passes.

**Time:** ~5 minutes. **No AWS account needed.**

## Steps

### 1. Check Go (>= 1.27 required)
```
go version
```
- Go >= 1.27 → proceed.
- Missing or older → install Go 1.27.x:
  ```
  wget https://go.dev/dl/go1.27.0.linux-amd64.tar.gz
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.27.0.linux-amd64.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  go version   # → go1.27.0
  ```

### 2. Check jq
```
jq --version || sudo apt install -y jq
```

### 3. Clone and build
```
git clone https://github.com/sufield/stave
cd stave
make build
```
Use `make build`, NOT bare `go build` — `make build` runs `sync-schemas` /
`sync-controls` first, which a fresh clone needs. If the build fails, report the
`make` output verbatim (usually a Go-version mismatch).

### 4. Verify the binary
```
./stave version
```
Expect a version line (e.g. `edge (production)`). Both `./stave version` and
`./stave --version` work.

### 5. Verify the control catalog
```
./stave controls list -i controls | wc -l
```
Expect **2,600+** controls. If 0, the `controls/` directory didn't clone — re-check step 3.

### 6. Verify search
```
./stave search "privilege escalation"
```
Expect multiple results with control IDs and descriptions.

## Success
A working `stave` binary with 2,600+ controls, search functioning.
**Next:** `first-evaluation`.

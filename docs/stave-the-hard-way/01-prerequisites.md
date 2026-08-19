# Lab 01 — Prerequisites

## Install Stave

Download the latest release from the [Stave releases page](https://github.com/sufield/stave/releases)
or build from source:

```bash
git clone https://github.com/sufield/stave.git
cd stave
make build
```

## Verify Your Environment

```bash
stave --version
```

Expected output:

```
stave version edge (production)
```

Run the environment check:

```bash
stave doctor
```

Expected output (all PASS):

```
[PASS] version-info: stave_version= go_version=go1.26.5 ...
[PASS] os-version: ...
[PASS] shell: ...
[PASS] workspace-writable: directory is writable: ...
```

You need: `stave`, `git`, `jq`. AWS CLI is optional — all exercises use
pre-built fixtures. No AWS credentials required.

## Clone the Repository

If you built from source, you already have it. Otherwise:

```bash
git clone https://github.com/sufield/stave.git
cd stave
```

The fixtures live under `internal/fixtures/labs/`. You will reference them
throughout the tutorial.

## Verify

Run both commands. Both succeed:

```bash
stave --version && stave doctor
```

Next: [Lab 02 — Observations](02-observations.md)

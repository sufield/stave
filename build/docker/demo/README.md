# Stave Tutorials Docker Image

> **Note — the unified entry point is `stave/examples/`.** This
> Docker image (`stave-tutorials`) bundles 44 numbered scenarios
> + a HIPAA scenario behind an `entrypoint.sh` flag interface
> (`docker run stave-tutorials --scenario N`). Most of these
> scenarios are duplicated by the canonical examples under
> `stave/examples/` (`public-bucket`, `s3-public-read-policy`,
> `s3-broad-write-scope`, `s3-bucket-name-dangling`, …) which
> ship with multi-engine analysis on top of stave-apply output.
>
> For early adopters: open the repo in Codespaces (`Open in
> GitHub Codespaces` badge on the README) and run any example
> via `bash examples/<name>/run.sh`. Entry-level demos live
> under `examples/demo-s3-*/`.
>
> This image is kept for users who prefer `docker compose up`
> over Codespaces. Treat it as a legacy surface — new scenarios
> should be authored as `examples/<name>/` directories.

## Build

```bash
docker compose -f stave/docker-compose.yaml up
```

## Use

```bash
docker run stave-tutorials --list
docker run stave-tutorials --scenario 1
docker run stave-tutorials --scenario 1 --fixed
docker run stave-tutorials --hipaa
docker run stave-tutorials --risk-chains
```

The image bundles `stave` (CGO_ENABLED=0) plus a Z3 Go example
(`/usr/local/bin/z3-example`). Full flag list is in
[`entrypoint.sh`](entrypoint.sh).

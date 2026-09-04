# Stave adopter workspace image.
#
# Multi-stage:
#   builder  — golang:1.27.0, compiles `stave` and `stave-mcp`
#   runtime  — ubuntu:24.04, Go toolchain, Steampipe, the binaries,
#              and the repo content an adopter needs at runtime
#
# Build from the stave module root (NOT from this directory — the
# Dockerfile COPYs source files from the module root):
#
#   cd stave
#   docker build -f stave-workspace/Dockerfile -t stave-workspace:edge .
#
# Run a quick sanity check inside the image:
#
#   docker run --rm -it stave-workspace:edge bash -lc '
#       stave version &&
#       stave-mcp --help 2>&1 | head -1 &&
#       bash /opt/stave/examples/demo-ai-security/run.sh'

# ─── Stage 1: build the binaries ─────────────────────────────────────
# Pinned to the toolchain go.mod declares. Bumping go.mod's `toolchain`
# directive is the single source of truth; bump this in lockstep.
FROM golang:1.27.0-bookworm AS builder

ENV CGO_ENABLED=0

WORKDIR /src
# Cache module downloads in a separate layer so `go build` is fast on
# source-only changes.
COPY go.mod go.sum ./
RUN go mod download

# The repo vendors deps (vendor/ is part of build correctness — see
# bump-x/sys/0.45.0 commit). COPY everything so vendor/ comes along
# too; .dockerignore excludes build artifacts.
COPY . .

# Both binaries embed schemas/controls/alternatives via go:embed under
# internal/. `make build` runs sync-schemas + sync-controls +
# sync-alternatives before `go build` so the embedded mirrors match
# the canonical sources — replicate that here.
RUN make sync-schemas sync-controls sync-alternatives \
 && go build -trimpath -ldflags="-s -w" -o /out/stave     ./cmd/stave \
 && go build -trimpath -ldflags="-s -w" -o /out/stave-mcp ./cmd/stave-mcp

# ─── Stage 2: runtime ────────────────────────────────────────────────
FROM ubuntu:24.04

# Pin every external tool. No floating :latest.
ARG GO_VERSION=1.27.0
ARG STEAMPIPE_VERSION=1.0.0

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PATH="/usr/local/go/bin:/home/coder/go/bin:/usr/local/bin:${PATH}" \
    GOPATH=/home/coder/go \
    STAVE_CONTROLS=/opt/stave/controls \
    STAVE_CHAINS=/opt/stave/chains

# System packages adopters reach for: curl/wget for ad-hoc downloads,
# jq for JSON wrangling (the Steampipe→obs.v0.1 mapping needs it),
# git for cloning their own work, ca-certificates for TLS,
# bash-completion for tab-complete on `stave`. unzip is needed by the
# Steampipe installer's archive handling.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git jq unzip bash-completion sudo less \
 && rm -rf /var/lib/apt/lists/*

# Install Go (pinned). Adopters use this for custom tooling and to
# rebuild Stave from source inside the workspace.
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz \
 && tar -C /usr/local -xzf /tmp/go.tar.gz \
 && rm /tmp/go.tar.gz \
 && /usr/local/go/bin/go version

# Install Steampipe (pinned) + AWS plugin. The plugin install runs as
# a non-root user, so create `coder` first and run the install as it
# so the plugin lands under that user's $HOME (~/.steampipe/).
# GCP / other plugins are NOT installed by default — adopters can add
# them later (`steampipe plugin install gcp`) to keep the image lean.
RUN useradd -m -s /bin/bash -u 1000 coder \
 && echo 'coder ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/coder

RUN curl -fsSL "https://github.com/turbot/steampipe/releases/download/v${STEAMPIPE_VERSION}/steampipe_linux_amd64.tar.gz" \
        -o /tmp/steampipe.tar.gz \
 && tar -xzf /tmp/steampipe.tar.gz -C /usr/local/bin steampipe \
 && rm /tmp/steampipe.tar.gz \
 && steampipe --version

USER coder
RUN steampipe plugin install aws
USER root

# Stave binaries from stage 1.
COPY --from=builder /out/stave     /usr/local/bin/stave
COPY --from=builder /out/stave-mcp /usr/local/bin/stave-mcp

# Repo content the adopter consumes at runtime. /opt/stave is the
# single canonical root; the home-dir symlinks below are convenience.
COPY --chown=root:root controls/        /opt/stave/controls/
COPY --chown=root:root chains/          /opt/stave/chains/
COPY --chown=root:root schemas/         /opt/stave/schemas/
COPY --chown=root:root examples/        /opt/stave/examples/
COPY --chown=root:root docs/workflows/  /opt/stave/guides/
COPY --chown=root:root TERMINOLOGY.md   /opt/stave/TERMINOLOGY.md

# Convenience symlinks: adopters' shortest paths reach for ~/examples,
# ~/guides, ~/chains. Each demo dir also gets an `obs` symlink that
# points at fixtures/writeup-config/observations so the START-HERE
# commands stay short ("--observations ~/examples/demo-ai-security/obs").
RUN ln -s /opt/stave/examples /home/coder/examples \
 && ln -s /opt/stave/guides   /home/coder/guides \
 && ln -s /opt/stave/chains   /home/coder/chains \
 && for d in /opt/stave/examples/demo-*; do \
        [ -d "$d/fixtures/writeup-config/observations" ] && \
        ln -s fixtures/writeup-config/observations "$d/obs"; \
    done

# Terminal MOTD shown on every interactive shell — quick-start
# commands always one screen away.
COPY --chown=root:root stave-workspace/motd.sh /etc/profile.d/stave-motd.sh
RUN chmod 0644 /etc/profile.d/stave-motd.sh

# Coder runs commands as the `coder` user; the workspace home is
# where the agent and the IDE root land.
USER coder
WORKDIR /home/coder

# Healthcheck: a fast, pure-catalog command (no observations) that
# proves stave is on the PATH and the embedded catalog is intact.
HEALTHCHECK --interval=60s --timeout=5s --start-period=15s --retries=3 \
    CMD stave features >/dev/null 2>&1 || exit 1

CMD ["bash", "-l"]

FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl wget gnupg2 \
        build-essential pkg-config jq make \
        python3 python3-venv python3-dev python3-pip \
        swi-prolog z3 cvc5 libz3-dev \
        default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Souffle 2.5 was packaged against libffi7; Ubuntu 24.04 ships libffi8.
# Pull libffi7 from focal to satisfy the dependency.
RUN ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in \
         amd64) MIRROR="http://archive.ubuntu.com/ubuntu" ;; \
         arm64|*) MIRROR="http://ports.ubuntu.com/ubuntu-ports" ;; \
       esac \
    && wget -q -O /tmp/libffi7.deb "${MIRROR}/pool/main/libf/libffi/libffi7_3.3-4_${ARCH}.deb" \
    && apt-get update \
    && apt-get install -y --no-install-recommends /tmp/libffi7.deb \
    && rm /tmp/libffi7.deb \
    && rm -rf /var/lib/apt/lists/*

# Souffle 2.5 — Datalog reasoning engine (amd64 only; release artifact is x86_64).
RUN ARCH="$(dpkg --print-architecture)" \
    && if [ "$ARCH" = "amd64" ]; then \
         wget -q -O /tmp/souffle.deb https://github.com/souffle-lang/souffle/releases/download/2.5/x86_64-ubuntu-2404-souffle-2.5-Linux.deb \
         && apt-get update \
         && apt-get install -y --no-install-recommends /tmp/souffle.deb \
         && rm /tmp/souffle.deb \
         && rm -rf /var/lib/apt/lists/*; \
       else \
         echo "Skipping Souffle .deb install on $ARCH (no upstream package); the souffle-reachability example will be unavailable." ; \
       fi

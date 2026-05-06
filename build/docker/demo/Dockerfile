# Build stage: compile stave from source
FROM golang:1.26-bookworm@sha256:8e8aa801e8417ef0b5c42b504dd34db3db911bb73dba933bd8bde75ed815fdbb AS builder
ARG VERSION=edge
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make sync-schemas sync-controls && \
    CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/sufield/stave/internal/version.String=${VERSION}" -o /stave ./cmd/stave

# Runtime stage: stave Go binary + Python solver under one image.
# python:3.11-slim is the base because stave-solver is a Python
# package and this avoids a second apt-install layer for Python.
FROM python:3.11-slim-bookworm
RUN groupadd -g 10001 stave && \
    useradd -u 10001 -g stave -m -d /work stave && \
    apt-get update && \
    apt-get install -y --no-install-recommends jq && \
    rm -rf /var/lib/apt/lists/*

# Install the Z3 solver package. Non-editable since the image is
# read-only at runtime; this also keeps libz3 resolution simple
# (the z3-solver wheel ships its own libz3.so).
COPY python/solver/ /opt/stave-solver/
RUN pip install --no-cache-dir /opt/stave-solver

COPY --from=builder /stave /usr/local/bin/stave
COPY build/docker/demo/scenarios/ /scenarios/
COPY build/docker/demo/all_controls.txt /scenarios/all_controls.txt
COPY build/docker/demo/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER stave
WORKDIR /work
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--scenario", "1"]

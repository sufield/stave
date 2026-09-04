# Build stage: compile stave (cgo-free) and the z3 example
# (cgo, links libz3) from source.
FROM golang:1.27-bookworm AS builder
ARG VERSION=edge
RUN apt-get update && \
    apt-get install -y --no-install-recommends libz3-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make sync-schemas sync-controls && \
    CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/sufield/stave/internal/version.String=${VERSION}" -o /stave ./cmd/stave && \
    CGO_ENABLED=1 go build -tags z3example -ldflags "-s -w" -o /z3-example ./examples/z3-public-exposure

# Runtime stage: stave Go binary + Z3 Go example. The stave
# binary is statically linked (CGO_ENABLED=0); only the Z3
# example links libz3 dynamically, so the runtime stage installs
# libz3-4 and jq.
FROM debian:bookworm-slim@sha256:f06537653ac770703bc45b4b113475bd402f451e85223f0f2837acbf89ab020a
RUN groupadd -g 10001 stave && \
    useradd -u 10001 -g stave -m -d /work stave && \
    apt-get update && \
    apt-get install -y --no-install-recommends libz3-4 jq && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /stave /usr/local/bin/stave
COPY --from=builder /z3-example /usr/local/bin/z3-example
COPY build/docker/demo/scenarios/ /scenarios/
COPY build/docker/demo/all_controls.txt /scenarios/all_controls.txt
COPY build/docker/demo/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER stave
WORKDIR /work
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--scenario", "1"]

# Build stage: compile stave from source
FROM golang:1.26-bookworm AS builder
WORKDIR /src
COPY stave/go.mod stave/go.sum ./
RUN go mod download
COPY stave/ .
RUN make sync-schemas sync-controls && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /stave ./cmd/stave

# Runtime stage: minimal image with stave + scenarios
FROM debian:bookworm-slim
RUN groupadd -g 10001 stave && \
    useradd -u 10001 -g stave -m -d /work stave
COPY --from=builder /stave /usr/local/bin/stave
COPY stave/build/docker/demo/scenarios/ /scenarios/
COPY stave/build/docker/demo/all_controls.txt /scenarios/all_controls.txt
COPY stave/build/docker/demo/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER stave
WORKDIR /work
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]

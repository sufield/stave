# Build stage: compile stave from source
FROM golang:1.26-bookworm@sha256:8e8aa801e8417ef0b5c42b504dd34db3db911bb73dba933bd8bde75ed815fdbb AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make sync-schemas sync-controls && \
    CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/sufield/stave/internal/version.String=$(cat VERSION)" -o /stave ./cmd/stave

# Runtime stage: minimal image with stave + scenarios
FROM debian:bookworm-slim@sha256:f06537653ac770703bc45b4b113475bd402f451e85223f0f2837acbf89ab020a
RUN groupadd -g 10001 stave && \
    useradd -u 10001 -g stave -m -d /work stave
COPY --from=builder /stave /usr/local/bin/stave
COPY build/docker/demo/scenarios/ /scenarios/
COPY build/docker/demo/all_controls.txt /scenarios/all_controls.txt
COPY build/docker/demo/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER stave
WORKDIR /work
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--scenario", "1"]

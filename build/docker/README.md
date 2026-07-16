# build/docker/

Docker images for Stave distribution and demos.

## Dockerfile.release

Minimal `FROM scratch` image containing only the statically-linked `stave` binary. Used by the release pipeline to publish multi-platform images.

```dockerfile
FROM scratch
COPY ${TARGETPLATFORM}/stave /usr/local/bin/stave
ENTRYPOINT ["stave"]
```

## demo/

Interactive demo image with 44 curated S3 misconfiguration scenarios plus a HIPAA compliance scenario. Each scenario includes `bad/` observations (violations present) and `fixed/` observations (violations remediated).

Build and run:

```bash
docker compose -f stave/docker-compose.yaml up

docker run stave-tutorials --list           # list scenarios
docker run stave-tutorials --scenario 1     # run a scenario
```

The demo image builds Stave from source (multi-stage Dockerfile) and also includes the Z3 example binary and `jq` for post-processing.

See `demo/README.md` for full usage. New scenarios should be authored as `examples/<name>/` directories rather than added here.

# Scope and support

## In scope
- AWS S3 public exposure only
- Offline analysis of local configuration snapshots
- Deterministic findings and reports

## Out of scope
- Non-S3 assets or platforms
- Application-specific logic (CMS, e-commerce, etc.)
- Other AWS services
- Continuous monitoring or agents

## Supported surfaces
- CLI: `stave apply`, `stave apply --profile mvp1-s3`, `stave ingest --profile mvp1-s3`, `stave validate`, `stave diagnose`, `stave verify`, `stave snapshot hygiene`, `stave ci fix-loop`, `stave graph coverage`
- Tests: `make e2e`, `go test ./...`

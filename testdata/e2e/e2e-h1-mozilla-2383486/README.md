# HackerOne 2383486: Insecure S3 Bucket Exposing Git Directory

**Program:** Mozilla
**Report:** 2383486
**Title:** Insecure S3 Bucket Exposing Git Directory
**Bucket:** mofo-infographics

## Pattern

Public S3 bucket exposes `.git/` directory, enabling repo reconstruction and potential secret leakage via tools like GitDump.

## Modeling

Uses `properties.storage.content.exposed_repo_artifacts` boolean: `true` = VCS artifacts accessible (unsafe), `false` = cleaned up (safe). Combined with public read visibility check.

## Test Case

**T1 (2024-02-21, Unsafe):** `exposed_repo_artifacts: true`, `public_read: true`
- CTL.S3.NO_REPO_ARTIFACTS fires

**T2 (2024-03-01, Fixed):** `exposed_repo_artifacts: false`
- CTL.S3.NO_REPO_ARTIFACTS clears

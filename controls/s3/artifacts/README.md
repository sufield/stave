# S3 Artifact Exposure Controls

Controls in this directory detect version control artifacts exposed via publicly accessible S3 buckets.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.REPO.ARTIFACT.001 | Public Buckets Must Not Expose VCS Artifacts | Public bucket serves `.git/`, `.svn/`, or other VCS directories that enable repo reconstruction |

## Why This Matters

VCS artifacts (`.git/`, `.svn/`) in public buckets allow attackers to reconstruct the entire repository history, including secrets, credentials, and internal code that were committed at any point. This is a common finding in bug bounty programs targeting static website buckets.

## Predicate Logic

REPO.ARTIFACT.001 uses a compound `all` predicate:

1. Bucket must be publicly accessible (public read **or** public list)
2. `exposed_repo_artifacts` must be true

The control only fires when both conditions hold -- a private bucket with VCS artifacts is not flagged because the artifacts are not reachable.

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.access.public_read` | bool | REPO.ARTIFACT.001 |
| `properties.storage.access.public_list` | bool | REPO.ARTIFACT.001 |
| `properties.storage.content.exposed_repo_artifacts` | bool | REPO.ARTIFACT.001 |

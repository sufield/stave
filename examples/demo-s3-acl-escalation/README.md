# S3 Demo: ACL Privilege Escalation


Buckets where ACL grants (WRITE_ACP, READ_ACP, FULL_CONTROL) enable attackers to modify permissions, enumerate access, or gain complete control -- even when the bucket policy looks clean.

## Background

S3 ACL permission types beyond READ and WRITE are frequently overlooked. WRITE_ACP allows modifying the ACL itself (privilege escalation), READ_ACP reveals who has access (reconnaissance), and FULL_CONTROL combines everything including ACL modification. Bug bounty researchers exploit these to convert limited access into full bucket takeover.

**Based on:** HackerOne ACL escalation patterns documented in Intigriti and YesWeHack S3 guides

## Buckets

**`dev-shared-workspace`** -- ACL grants WRITE_ACP and READ_ACP to AllUsers. An attacker can read the ACL to discover grants, then modify the ACL to give themselves FULL_CONTROL.

**`legacy-partner-data`** -- ACL grants FULL_CONTROL to AuthenticatedUsers. Any AWS account holder has complete control including read, write, delete, and ACL modification.

## Triggered Controls

| Control | Resource | Description |
|---------|----------|-------------|
| `CTL.S3.ACL.ESCALATION.001` | dev-shared-workspace | No Public ACL Modification (WRITE_ACP) |
| `CTL.S3.ACL.RECON.001` | dev-shared-workspace | No Public ACL Readability (READ_ACP) |
| `CTL.S3.ACL.FULLCONTROL.001` | legacy-partner-data | No FULL_CONTROL ACL Grants to Public |
| `CTL.S3.CONTROLS.001` | dev-shared-workspace | Public Access Block Must Be Enabled |
| `CTL.S3.CONTROLS.001` | legacy-partner-data | Public Access Block Must Be Enabled |

## Run

```bash
bash run.sh
```

Current expected output is in `expected/output.json`.

The runner uses the standard `stave apply` + encoding verification
pipeline. No Docker required — works in the Codespaces devcontainer
or any local checkout with stave built (`make build` in stave/).

## Try it yourself

Replace the JSON files in `fixtures/observations/` with your own
S3 observations and re-run. The bucket-name + property values
update; the schema and the controls do not.

## Provenance

Migrated from `docs-content/demo/scenarios/acl-escalation/`. The original
Docker entrypoint surface is deprecated — every scenario it
exposed is now a directory under `examples/demo-s3-*/` with a
runner that works in the unified Codespaces devcontainer.

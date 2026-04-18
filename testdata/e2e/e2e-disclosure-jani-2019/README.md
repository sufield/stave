# E2E Test: Jay Jani Jan 2019 — Public ACL read + write

## Case summary

- **Source**: Jay Jani, January 2019 disclosure (Medium article, "Unrestricted Remote File Upload and Deletion").
- **Pattern**: S3 bucket ACL grants READ and WRITE to AllUsers; `aws s3 ls`, `aws s3 cp`, and `aws s3 rm` all succeeded with `--no-sign-request`.
- **Modeled assets**: 2 synthetic buckets — `jani-public-rw` (disclosed config) and `jani-hardened` (PAB fully enabled, silent).
- **Regression guard**: confirms `CTL.S3.PUBLIC.003` fires at **critical** severity on plain public WRITE grants to AllUsers, alongside PUBLIC.001 (read) and PUBLIC.LIST.001 (list).

## Buckets

| ID | `public_read` | `public_list` | `public_write` | PAB |
|----|:---:|:---:|:---:|:---:|
| `jani-public-rw` | true | true | true | off |
| `jani-hardened` | false | false | false | fully enabled |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.PUBLIC.001` | critical | `public_read=true` | 1 |
| `CTL.S3.PUBLIC.003` | critical | `public_write=true` | 1 |
| `CTL.S3.PUBLIC.LIST.001` | high | `public_list=true` | 1 |
| **Total** | | | **3** |

## Expected result

- Exit code: 3
- Findings: 3
- Buckets evaluated: 2, unsafe: 1

## Notes

The post does not disclose whether the public access was ACL-based or policy-based. Setting `write_via_resource: false` captures the likely ACL path; if policy-based, `CTL.S3.POLICY.WRITE.001` would fire additionally. Not in the asserted control set for this regression guard.

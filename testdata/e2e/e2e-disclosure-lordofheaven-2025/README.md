# E2E Test: LordofHeaven Incident 2 Jul 2025 — Three writable government buckets

## Case summary

- **Source**: LordofHeaven, July 2025 disclosure. On a government domain, the researcher discovered three S3 buckets that accepted unauthenticated `aws s3 cp` (upload) and `aws s3 rm` (delete). Write was confirmed by uploading `hello.txt` to one bucket and deleting it cleanly via `--no-sign-request`. Full read, write, and delete capability on anonymous requests on all three.
- **Pattern**: three S3 buckets with ACL or policy granting public READ and WRITE to AllUsers.
- **Modeled assets**: 4 synthetic buckets — three disclosed configs (`gov-writable-bucket-1/2/3`) and one hardened control (`gov-hardened-bucket`, PAB fully enabled, silent).
- **Regression guard**: confirms `CTL.S3.PUBLIC.003` fires at **critical** severity on multiple buckets in the same snapshot, and that a hardened bucket in the same snapshot stays silent.

## Buckets

| ID | `public_read` | `public_list` | `public_write` | PAB |
|----|:---:|:---:|:---:|:---:|
| `gov-writable-bucket-1` | true | true | true | off |
| `gov-writable-bucket-2` | true | true | true | off |
| `gov-writable-bucket-3` | true | true | true | off |
| `gov-hardened-bucket` | false | false | false | fully enabled |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.PUBLIC.001` | critical | `public_read=true` | 3 |
| `CTL.S3.PUBLIC.003` | critical | `public_write=true` | 3 |
| `CTL.S3.PUBLIC.LIST.001` | high | `public_list=true` | 3 |
| **Total** | | | **9** |

## Expected result

- Exit code: 3
- Findings: 9
- Buckets evaluated: 4, unsafe: 3

## Notes

The post does not disclose the exact bucket names or whether the public access was ACL-based or policy-based. The modeled buckets use generic placeholder names. Setting `write_via_resource: false` captures the likely ACL path.

This is the third disclosed incident (following Jani 2019 and Sriram 2017) grounding `CTL.S3.PUBLIC.003` at critical severity as the correct detector for public WRITE grants to AllUsers. All three incidents share the same WRITE-at-critical detection shape.

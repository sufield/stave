# E2E Test: Sriram Oct 2017 — ACL public WRITE enabling logo overwrite / stored XSS

## Case summary

- **Source**: Sriram, October 2017 disclosure (blog post describing `aws s3 mv` upload to victim bucket and logo overwrite with malicious SVG for stored XSS).
- **Pattern**: S3 bucket ACL grants LIST and WRITE to AllUsers; `aws s3 ls` and `aws s3 mv` succeeded with `--no-sign-request`. Individual object GETs returned **Access Denied** — the post explicitly discloses that object-level ACLs were private despite bucket-level permissive ACLs.
- **Modeled assets**: 2 synthetic buckets — `sriram-logo-bucket` (disclosed config, list + write, read-at-bucket-level false) and `sriram-hardened` (PAB fully enabled, silent).
- **Regression guard**: confirms `CTL.S3.PUBLIC.003` fires at **critical** severity on plain public WRITE grants to AllUsers, even when bucket-level public_read is false.

## Buckets

| ID | `public_read` | `public_list` | `public_write` | PAB |
|----|:---:|:---:|:---:|:---:|
| `sriram-logo-bucket` | false | true | true | off |
| `sriram-hardened` | false | false | false | fully enabled |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.PUBLIC.003` | critical | `public_write=true` | 1 |
| `CTL.S3.PUBLIC.LIST.001` | high | `public_list=true` | 1 |
| **Total** | | | **2** |

`CTL.S3.PUBLIC.001` is not asserted because the disclosure explicitly reports that individual GETs failed. This is captured as `public_read: false`. If a future iteration distinguishes bucket-level from object-level read exposure, the `public_read` boolean's semantics may need refinement.

## Expected result

- Exit code: 3
- Findings: 2
- Buckets evaluated: 2, unsafe: 1

## Notes

The SVG stored-XSS exploitation is out of scope — Stave detects the configuration (public write), not the exploitation (content injection + browser execution). The critical-severity write finding is the detection target.

The post does not disclose whether the write grant was ACL-based or policy-based. Setting `write_via_resource: false` captures the likely ACL path.

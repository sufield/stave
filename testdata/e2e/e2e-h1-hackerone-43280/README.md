# HackerOne 43280: HTTPS Not Enforced on S3

**Program:** HackerOne
**Report:** 43280
**Title:** HTTPS is not enforced for objects stored by HackerOne on Amazon S3

## Pattern

HTTP allowed because bucket policy does not enforce `aws:SecureTransport`. Objects accessible over plaintext HTTP.

## Modeling

Uses `properties.storage.encryption.in_transit_enforced` boolean: `false` = HTTP allowed (unsafe), `true` = HTTPS enforced (safe).

## Test Case

**T1 (2015-01-11, Unsafe):** `in_transit_enforced: false`
- CTL.S3.ENCRYPT.002 fires

**T2 (2015-01-18, Fixed):** `in_transit_enforced: true`
- CTL.S3.ENCRYPT.002 clears

# HackerOne 404822: Slack S3 Bucket Exposure

**Program:** Slack
**Report:** 404822
**Title:** AWS S3 bucket exposed iOS test build code + configuration

## What We Model

- `public_read: true` + `public_list: true` (bucket contents browsable)
- `public_access_fully_blocked: false` (no PAB safety net)

## What We Prove

Evaluator fires CTL.S3.PUBLIC.001 and CTL.S3.CONTROLS.001 on T1 (unsafe) and none on T2 (fixed).

## Test Case

**T1 (2018-09-03, Unsafe):** Public read + list enabled, PAB disabled
**T2 (2019-02-23, Fixed):** Public read + list disabled, PAB fully enabled

**Note:** Content sensitivity (source code exposure) is out of scope. This test validates configuration exposure detection only.

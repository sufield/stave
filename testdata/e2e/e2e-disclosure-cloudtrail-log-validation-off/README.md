# Disclosure: CloudTrail log file validation disabled

Source: defense-evasion pattern aligned with MITRE ATT&CK
`T1562.008` and CIS AWS Foundations Benchmark control 3.2.
With log-file validation disabled, the SHA-256 digest files
that detect post-delivery tampering of CloudTrail S3 objects
are not produced. Forensic investigators cannot determine
whether logs in the trail bucket were altered or deleted.

This is a quieter form of detection bypass than `StopLogging`
— the trail keeps appearing healthy in the console, but its
forensic value is silently degraded. Both AWS Trusted Advisor
and Prowler flag this configuration; CIS labels it a
mandatory level-1 control.

## Pattern

Trail is actively logging and multi-region (so
`CTL.CLOUDTRAIL.STOP.DETECT.001` does not fire), but
`LogFileValidationEnabled == false` — digest files are not
written, so any S3 object mutation in the trail bucket is
undetectable after the fact.

## Fixture mechanics

- Asset: `aws_cloudtrail_trail` `org-audit-trail`.
- `trail.is_logging: true` and
  `trail.is_multi_region_trail: true` — the StopLogging
  control deliberately does not fire (this fixture isolates
  the validation-off case).
- `trail.log_file_validation_enabled: false` — the unsafe
  condition.

Control fired: `CTL.CLOUDTRAIL.LOG.VALIDATION.001`.

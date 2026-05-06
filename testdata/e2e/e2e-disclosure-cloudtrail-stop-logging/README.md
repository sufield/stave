# Disclosure: CloudTrail StopLogging — defense evasion

Source: well-documented attacker pattern mapped to MITRE
ATT&CK `T1562.008` (*Disable or Modify Cloud Logs*). Reported
in multiple incident responses (Mandiant cloud IR write-ups;
AWS Security Bulletin guidance on detecting unauthorized
`StopLogging` calls). The `StopLogging` API call is the first
and cheapest action an attacker takes after compromise to
blind subsequent stages.

## Pattern

A trail exists and is configured as multi-region, but
`IsLogging == false` — the trail is in stopped state. While
stopped, no management or data events are recorded; the
window remains audit-blind until `StartLogging` is called or
the gap is detected by a separate watcher (CloudWatch alarm
on `StopLogging` events from the management trail itself, or
the EventBridge default bus).

The fixture leaves the trail stopped across the entire
observation window — i.e., the gap is persistent, not a
brief misconfiguration that self-corrected.

## Fixture mechanics

- Asset: `aws_cloudtrail_trail` `org-audit-trail`.
- `trail.is_logging: false` (the unsafe condition).
- `trail.is_multi_region_trail: true` (control's other clause
  is satisfied — only the `is_logging` clause fires).
- Diagnostic fields `stopped_at` / `stopped_by` carry the
  forensic context.

Control fired: `CTL.CLOUDTRAIL.STOP.DETECT.001`.

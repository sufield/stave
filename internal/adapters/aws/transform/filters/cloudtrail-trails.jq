# aws cloudtrail describe-trails  ->  one aws_cloudtrail_trail asset per trail.
# Single-call source (the trail's get-trail-status is not needed for these
# signals). The id is the TrailARN AWS returns.
#
# Emitted (directly from describe-trails):
#   audit_trail.log_file_validation_enabled / .multi_region_enabled
#   audit.cloudtrail.include_global_events
#   trail.log_file_validation_enabled  (kept for controls that read it here)
#
# NOT emitted (documented in ctf/stave-transform/pending-items.md):
#   audit.cloudtrail.data_events_s3 / .has_s3_data_event_gap — whether S3 data
#   events are logged needs `aws cloudtrail get-event-selectors` (a separate
#   call). describe-trails only exposes HasCustomEventSelectors, which can't tell
#   whether S3 specifically is covered when selectors exist.
.trailList[] | {
  id: .TrailARN,
  type: "aws_cloudtrail_trail",
  vendor: "aws",
  properties: {
    audit_trail: {
      kind: "trail",
      log_file_validation_enabled: .LogFileValidationEnabled,
      multi_region_enabled: .IsMultiRegionTrail
    },
    audit: {
      kind: "trail",
      cloudtrail: {
        include_global_events: .IncludeGlobalServiceEvents
      }
    },
    trail: {
      log_file_validation_enabled: .LogFileValidationEnabled
    }
  }
}

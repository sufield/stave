# aws cloudwatch describe-alarms  ->  one aws_cloudwatch_alarm asset per metric
# alarm. Single-call source; id = the AlarmArn AWS returns.
#
#   monitoring.cloudwatch.has_any_action  true when the alarm has at least one
#     action across AlarmActions / OKActions / InsufficientDataActions (an alarm
#     with no actions notifies nobody).
.MetricAlarms[] | {
  id: .AlarmArn,
  type: "aws_cloudwatch_alarm",
  vendor: "aws",
  properties: { monitoring: {
    kind: "alarm",
    cloudwatch: {
      has_any_action: ((((.AlarmActions) // []) + ((.OKActions) // []) + ((.InsufficientDataActions) // [])) | length > 0)
    }
  } }
}

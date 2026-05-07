; Query — Rhino Pattern 4 (Indirect Compute Invocation) reachability
;
; Pattern 4 is the family of methods where a principal triggers
; compute execution WITHOUT direct invoke permission — by
; manipulating the event source that triggers the compute.
; Rhino's named example: write to a DynamoDB table whose stream
; triggers a Lambda with a privileged role. The iter-15 prover
; generalised: SQS/SNS/Kinesis publishers, S3 PutObject events,
; EventBridge rules, IoT topic rules, SES receipt rules,
; CloudWatch alarms — every event source that fans out to
; Lambda or another compute primitive.
;
; SAT  → principal has at least one event-source-write action
;        on a wildcard resource. Witness names principal + action.
; UNSAT → no Pattern 4 action present on a wildcard resource.

(declare-const principal String)
(declare-const action String)
(declare-const resource String)

(assert (or
  (has_type principal "aws_iam_user")
  (has_type principal "aws_iam_role")))

(assert (has_action principal action))
(assert (or
  ; Rhino's named method (#16): DynamoDB stream → Lambda
  (= action "dynamodb:PutItem")
  ; Beyond Rhino — same event-source-publishes-to-compute shape
  (= action "sqs:SendMessage")
  (= action "kinesis:PutRecord")
  (= action "sns:Publish")
  (= action "s3:PutObject")
  (= action "events:PutRule")
  (= action "events:PutTargets")
  (= action "iot:CreateTopicRule")
  (= action "ses:CreateReceiptRule")
  (= action "cognito-idp:UpdateUserPool")
  (= action "cloudwatch:PutMetricAlarm")
  (= action "lambda:CreateEventSourceMapping")))

(assert (has_resource principal resource))
(assert (= resource "*"))

(check-sat)
(get-value (principal action resource))

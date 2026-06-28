# aws opensearch describe-domain (or es describe-elasticsearch-domain)
#   ->  one aws_opensearch_domain asset.
# The detail response {"DomainStatus":{...}} is self-describing (carries the ARN).
#
#   logging.audit_logs_enabled  LogPublishingOptions.AUDIT_LOGS.Enabled (absent -> false)
#   access.policy_allows_wildcard  the resource AccessPolicies is empty (no policy
#     = open) OR a statement grants a "*" principal. AccessPolicies is a JSON
#     *string* and must be parsed; an empty string is the committed-data case.
.DomainStatus
| ((.AccessPolicies // "") | test("^\\s*$")) as $emptyPolicy
| {
  id: .ARN,
  type: "aws_opensearch_domain",
  vendor: "aws",
  properties: { search_service: {
    kind: "domain",
    logging: {
      audit_logs_enabled: ((.LogPublishingOptions.AUDIT_LOGS.Enabled) // false)
    },
    access: {
      policy_allows_wildcard: (
        if $emptyPolicy then true
        else (
          ((.AccessPolicies | fromjson | .Statement) // []) as $s
          | (if ($s | type) == "object" then [$s] else $s end)
          | any(
              (.Principal == "*")
              or ((.Principal.AWS?) == "*")
              or ((.Principal.AWS?) | (if type == "array" then any(. == "*") else false end))
            )
        ) end
      )
    }
  } }
}

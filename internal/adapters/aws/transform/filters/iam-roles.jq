# aws iam list-roles  ->  one aws_iam_role asset per role.
# AWSServiceRole* roles are AWS-managed and excluded (they inflate the asset
# count without producing actionable findings) — matching scripts/aws-snapshot.sh.
# trusted_services is extracted from AssumeRolePolicyDocument exactly as the
# proven aws-snapshot.sh jq does; Principal.Service is normalised whether AWS
# returns it as a string or an array.
#
# Note: attached_policy_arns / is_admin_equivalent / tags come from separate API
# calls (list-attached-role-policies, list-role-tags) and are added by the
# cross-call merge step, not this single-file filter.
.Roles[]
| select(.RoleName | startswith("AWSServiceRole") | not)
| {
  id: .Arn,
  type: "aws_iam_role",
  vendor: "aws",
  properties: { identity: {
    kind: "role",
    name: .RoleName,
    trusted_services: ([
      (.AssumeRolePolicyDocument.Statement // [])[]
      | .Principal.Service?
      | if type == "array" then .[] else . end
    ] | map(select(. != null)) | unique)
  } }
}

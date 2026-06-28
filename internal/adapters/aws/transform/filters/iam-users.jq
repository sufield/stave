# aws iam list-users  ->  one base aws_iam_user asset per user.
# The list call carries only identity (name/arn); computed signals
# (has_inline_policies, has_admin_access) come from per-user enrichment filters
# and merge in by id. Shape follows the committed nccgroup convention:
# identity.kind == "user".
.Users[] | {
  id: .Arn,
  type: "aws_iam_user",
  vendor: "aws",
  properties: { identity: {
    kind: "user",
    name: .UserName,
    arn: .Arn
  } }
}
